# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Steps the running graph and swaps in deployed ones (the C++ GraphHost and serving loop).

A deployed graph with a model-time step dt runs on a UTC grid: step n is due
at origin + n * dt, origin being its activation time. A node that falls behind
runs the missed steps at once. A graph without dt (and the startup graph) steps
at the node's step_rate_hz, or not at all when that is 0.
"""
import asyncio
from dataclasses import dataclass

from .clock import utc_now_ns
from .graph import Graph, rate_from_step_ns, schema_rate

BEHIND_REPORT_NS = 50_000_000
MAX_STEPS_PER_TURN = 1000  # then yield, so control requests are still served while catching up


@dataclass
class Staged:
    graph: Graph
    step_ns: int | None  # model-time step; None: untimed


class Executor:
    def __init__(self, step_rate_hz: float = 0.0, log=print):
        self.step_rate_hz = step_rate_hz
        self.log = log
        self.graph: Graph | None = None
        self.step_ns: int | None = None
        self.origin_ns = 0
        self.lag_ns = 0
        self.max_lag_ns = 0
        self.stopped = False  # a step failed
        self.pending: tuple[Staged, int] | None = None
        self._wake = asyncio.Event()
        self._watches: list[str] = []
        self._last_watch_ns = 0

    # ---- DeploymentHost ---------------------------------------------------------

    def stage(self, node_schema: dict, step_ns: int | None) -> Staged:
        """Compiles without running; raises SchemaError for a fragment that does not build or validate.

        The diagram's model-time step, exact in nanoseconds, seeds the rate of every element
        that pins none and must equal the rate of every element that pins one (GraphHost::stage);
        a deployed graph never carries the node's step rate."""
        rate = rate_from_step_ns(step_ns) if step_ns else schema_rate(node_schema)
        graph = Graph(node_schema, rate)
        if step_ns:
            graph.require_model_time_rate(rate)
        return Staged(graph, step_ns)

    def activate(self, staged: Staged, activate_at_ns: int | None) -> None:
        """Runs the staged graph from activate_at_ns (the previous one runs until then), or at once."""
        self.pending = None
        if activate_at_ns is not None and activate_at_ns > utc_now_ns():
            self.pending = (staged, activate_at_ns)
            self.log(f"runtime.deployment.scheduled activate_at_ns={activate_at_ns}")
        else:
            # A commit that arrives late catches up on the grid of activate_at_ns.
            self._swap(staged, activate_at_ns if activate_at_ns is not None else utc_now_ns())
        self._wake.set()

    def execution_state(self) -> str:
        return "stepping" if self._period_ns() and not self.stopped else "not_stepping"

    def timing(self) -> dict:
        steps = self.graph.steps if self.graph else 0
        if self.graph and self.step_ns:
            return {"pacing": "grid", "period_ns": self.step_ns, "origin_utc_ns": self.origin_ns, "steps": steps,
                    "lag_ns": self.lag_ns, "max_lag_ns": self.max_lag_ns, "rebases": 0}
        pacing = "rate" if self.graph and self.step_rate_hz > 0 else "none"
        return {"pacing": pacing, "step_rate_hz": self.step_rate_hz, "steps": steps}

    # ---- running ------------------------------------------------------------------

    def run_startup(self, graph: Graph) -> None:
        self._swap(Staged(graph, None), utc_now_ns())

    def watch(self, element_ids: list[str]) -> None:
        self._watches = element_ids

    def _swap(self, staged: Staged, origin_ns: int) -> None:
        self.graph, self.step_ns, self.origin_ns = staged.graph, staged.step_ns, origin_ns
        self.lag_ns = self.max_lag_ns = 0
        self.stopped = False
        self.log(f"runtime.graph.active name={staged.graph.name} elements={len(staged.graph.elements)} "
                 f"pacing={self.timing()['pacing']}")

    def _period_ns(self) -> int | None:
        if self.graph is None:
            return None
        if self.step_ns:
            return self.step_ns
        return round(1e9 / self.step_rate_hz) if self.step_rate_hz > 0 else None

    async def run(self) -> None:
        while True:
            now = utc_now_ns()
            if self.pending and now >= self.pending[1]:
                staged, at = self.pending
                self.pending = None
                self._swap(staged, at)
            period = self._period_ns()
            wait_ns = 500_000_000
            if period and not self.stopped:
                due = self.origin_ns + self.graph.steps * period
                ran = 0
                while due <= now and ran < MAX_STEPS_PER_TURN:
                    if not self._step(now - due):
                        break
                    ran += 1
                    due += period
                wait_ns = min(wait_ns, max(0, due - utc_now_ns()))
            if self.pending:
                wait_ns = min(wait_ns, max(0, self.pending[1] - utc_now_ns()))
            self._report_watches(now)
            self._wake.clear()
            try:
                await asyncio.wait_for(self._wake.wait(), wait_ns / 1e9)
            except asyncio.TimeoutError:
                pass

    def _step(self, lag_ns: int) -> bool:
        try:
            self.graph.step()
        except Exception as ex:
            self.stopped = True
            self.log(f"runtime.execution.stopped=error step={self.graph.steps} error={ex}")
            return False
        if self.step_ns:
            if lag_ns > self.step_ns and lag_ns > BEHIND_REPORT_NS and self.lag_ns <= BEHIND_REPORT_NS:
                self.log(f"runtime.execution.behind lag_ms={lag_ns / 1e6:.1f}")
            self.lag_ns = lag_ns
            self.max_lag_ns = max(self.max_lag_ns, lag_ns)
        return True

    def _report_watches(self, now: int) -> None:
        if not self._watches or self.graph is None or now - self._last_watch_ns < 1_000_000_000:
            return
        self._last_watch_ns = now
        values = " ".join(f"{e}={self.graph.sample(e):.6g}" for e in self._watches if e in self.graph.elements)
        if values:
            model_time = f" t={self.graph.steps * self.step_ns / 1e9:.6g}s" if self.step_ns else ""
            self.log(f"watch step={self.graph.steps}{model_time} {values}")

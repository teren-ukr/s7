# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests of s7py: canonical JSON, graph semantics, diagram parts and the control protocol.

Run from s7py: python3 -m unittest discover -s tests
"""
import asyncio
import json
import math
import subprocess
import sys
import tempfile
import unittest
from fractions import Fraction
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from s7node import diagram as diagrams  # noqa: E402
from s7node.graph import (ELEMENT_TYPES, Element, Graph, SchemaError, TrapezoidIntegrator,  # noqa: E402
                          rate_from_hz, rate_from_seconds, rate_from_step_ns, schema_rate)
from s7node.jcs import canonicalize, configuration_digest, loads  # noqa: E402

CERTS = ROOT.parent / "s7l2" / "s7runtime" / "examples" / "certs"
FIXTURE = ROOT.parent / "s7l2" / "s7runtime" / "tests" / "fixtures" / "control_v1.json"
NODE = "11111111-2222-3333-4444-555555555555"
OTHER = "33333333-4444-5555-6666-777777777777"


class CanonicalJsonTest(unittest.TestCase):
    def test_numbers_follow_ecmascript(self):
        # RFC 8785 appendix B and ECMAScript Number::toString corner cases.
        cases = {
            0.0: "0", -0.0: "0", 2.0: "2", 4.5: "4.5", 0.002: "0.002", 1e-7: "1e-7", 1e-6: "0.000001",
            1e20: "100000000000000000000", 1e21: "1e+21", 1e30: "1e+30", 333333333.3333333: "333333333.3333333",
            5e-324: "5e-324", 1.7976931348623157e308: "1.7976931348623157e+308", -1.5e-9: "-1.5e-9",
            123456789012345680000.0: "123456789012345680000",
        }
        for value, text in cases.items():
            self.assertEqual(canonicalize(value), text, value)

    def test_members_sorted_by_utf16(self):
        # U+1F600 (surrogates D83D DE00) sorts before U+FB33 in UTF-16, after it in code points.
        self.assertEqual(canonicalize({"דּ": 1, "\U0001f600": 2, "a": [True, None]}),
                         '{"a":[true,null],"\U0001f600":2,"דּ":1}')

    def test_large_integers_refused(self):
        with self.assertRaises(ValueError):
            canonicalize(2**53 + 1)

    def test_fixture_digests(self):
        """The digests in the conformance script were computed independently (tools/gen_control_fixtures.py)."""
        script = json.loads(FIXTURE.read_text())
        checked = 0
        for step in script["steps"]:
            configuration = step["request"].get("deployment", {}).get("configuration")
            if step["name"] != "prepare_tampered" and isinstance(configuration, dict):
                self.assertEqual(configuration_digest(configuration), configuration["configuration_digest"], step["name"])
                checked += 1
        self.assertGreater(checked, 0)

    def test_duplicate_members_refused(self):
        with self.assertRaises(ValueError):
            loads('{"a": 1, "a": 2}')


def schema(elements, connections=()):
    return {"name": "t", "elements": elements,
            "connections": [{"from_element": a, "from_port": 0, "to_element": b, "to_port": p} for a, b, p in connections]}


def graph(elements, connections=(), rate=Fraction(1)):
    """A graph seeded at 1 Hz unless an element pins its own rate, like the C++ test schemas."""
    return Graph(schema(elements, connections), rate)


def run(g, steps, *element_ids):
    seen = []
    for _ in range(steps):
        g.step()
        seen.append(tuple(g.sample(e) for e in element_ids))
    return seen


class FailOnce(Element):
    """Gain that raises on its second call: a fault in the middle of the causal phase."""

    params = ("type",)
    input_count = 1

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.calls = 0

    def step(self, inputs):
        self.calls += 1
        if self.calls == 2:
            raise ArithmeticError("injected fault")
        self.outputs[0] = inputs[0]


class GraphTest(unittest.TestCase):
    def test_feedthrough_runs_in_causal_order(self):
        # Listed sink-first: still computed source-first within one step.
        g = graph([{"id": "g", "type": "Gain", "params": {"factor": 3}},
                   {"id": "c", "type": "Constant", "params": {"value": 2}}], [("c", "g", 0)])
        g.step()
        self.assertEqual(g.sample("g"), 6.0)

    def test_causal_memory_publishes_at_the_next_step(self):
        # s7core/tests/core_smoke.cpp, "Delay and PreviousValue delay by exactly one step":
        # the same graph, in both declaration orders, and the same values after every step.
        elements = [{"id": "source", "type": "Accumulator", "params": {}},
                    {"id": "unit", "type": "Constant", "params": {"value": 1}},
                    {"id": "delay", "type": "Delay", "params": {"initial_value": -1}},
                    {"id": "previous", "type": "PreviousValue", "params": {"initial_value": -2}},
                    {"id": "after_delay", "type": "Gain", "params": {"factor": 1}}]
        connections = [("unit", "source", 0), ("source", "delay", 0), ("delay", "previous", 0), ("delay", "after_delay", 0)]
        for order in (elements, elements[::-1]):
            g = graph(order, connections)
            self.assertEqual(run(g, 4, "source", "delay", "after_delay", "previous"),
                             [(1.0, -1.0, -1.0, -2.0), (2.0, 1.0, 1.0, -1.0), (3.0, 2.0, 2.0, 1.0), (4.0, 3.0, 3.0, 2.0)])

    def test_counter_loop_through_delay(self):
        # y = 1 + z^-1 y: an Adder fed back through a Delay counts steps.
        g = graph([{"id": "one", "type": "Constant", "params": {"value": 1}},
                   {"id": "sum", "type": "Adder", "params": {}},
                   {"id": "z", "type": "Delay", "params": {}}],
                  [("one", "sum", 0), ("z", "sum", 1), ("sum", "z", 0)])
        self.assertEqual(run(g, 5, "sum", "z"), [(1.0, 0.0), (2.0, 1.0), (3.0, 2.0), (4.0, 3.0), (5.0, 4.0)])

    def test_euler_integrator_closes_a_loop(self):
        # x' = -x, x(0) = 1, forward Euler: x[n] = (1 - dt)^n, x[n] visible after step n + 1.
        dt = 0.01
        g = Graph(schema([{"id": "x", "type": "EulerIntegrator", "params": {"dt": dt, "initial_value": 1}},
                          {"id": "neg", "type": "Gain", "params": {"factor": -1}}],
                         [("x", "neg", 0), ("neg", "x", 0)]))
        self.assertEqual(run(g, 2, "x", "neg"), [(1.0, -1.0), (1 - dt, -(1 - dt))])
        for _ in range(98):
            g.step()
        self.assertAlmostEqual(g.sample("x"), (1 - dt) ** 99, places=12)

    def test_oscillator(self):
        g = Graph(schema([{"id": "o", "type": "AnalogOscillator",
                           "params": {"amplitude": 2, "frequency_hz": 1, "sample_rate_hz": 4, "phase": 0}}]))
        values = [v for v, in run(g, 3, "o")]
        self.assertTrue(all(math.isclose(a, b, abs_tol=1e-12) for a, b in zip(values, [0, 2, 0])))

    def test_invalid_schemas(self):
        cases = {
            "cycle without causal memory": schema(
                [{"id": "a", "type": "Gain"}, {"id": "b", "type": "Gain"}], [("a", "b", 0), ("b", "a", 0)]),
            "is not connected": schema([{"id": "g", "type": "Gain"}]),
            "more than one driver": schema(
                [{"id": "c", "type": "Constant"}, {"id": "g", "type": "Gain"}], [("c", "g", 0), ("c", "g", 0)]),
            "unknown element type": schema([{"id": "s", "type": "Scope"}]),
            "data streams": schema([{"id": "s", "type": "NetSink"}]),
            "F64 only": schema([{"id": "c", "type": "Constant", "params": {"type": "I32", "value": 1}}]),
            "input port 2": schema([{"id": "c", "type": "Constant"}, {"id": "a", "type": "Adder"}],
                                   [("c", "a", 0), ("c", "a", 1), ("c", "a", 2)]),
            "2 to 64 entries": schema([{"id": "a", "type": "Adder", "params": {"weights": [1]}}]),
            "non-empty array": schema([{"id": "a", "type": "Adder", "params": {"weights": []}}]),
        }
        for message, bad in cases.items():
            with self.subTest(message), self.assertRaisesRegex(SchemaError, message):
                Graph(bad, Fraction(1))

    def test_parameters_are_checked_against_the_declaration(self):
        # builtin_element_registry.cpp / checked_params: an unknown name or enum value is refused.
        cases = {
            "unknown parameter 'gain'": {"id": "g", "type": "Gain", "params": {"gain": 2}},
            "unknown parameter 'dt'": {"id": "d", "type": "Delay", "params": {"dt": 1}},
            "'mode' must be one of implicit, sampled": {"id": "i", "type": "TrapezoidIntegrator",
                                                        "params": {"mode": "explicit"}},
            "'overflow' must be one of saturate, wrap": {"id": "g", "type": "Gain", "params": {"overflow": "clip"}},
            "accumulator_type': type F32": {"id": "a", "type": "Accumulator", "params": {"accumulator_type": "F32"}},
            "'factor' must be a number": {"id": "g", "type": "Gain", "params": {"factor": True}},
        }
        for message, element in cases.items():
            with self.subTest(message), self.assertRaisesRegex(SchemaError, message):
                graph([{"id": "c", "type": "Constant"}, element], [("c", element["id"], 0)])
        # Declared parameters that change nothing for F64 are accepted.
        g = graph([{"id": "c", "type": "Constant", "params": {"type": "F64", "value": 2}},
                   {"id": "a", "type": "Accumulator",
                    "params": {"type": "F64", "accumulator_type": "F64", "overflow": "wrap"}}], [("c", "a", 0)])
        self.assertEqual(run(g, 2, "a"), [(2.0,), (4.0,)])

    def test_adder_sums_in_input_order(self):
        # AdderT adds term by term, so 0.1 + 0.2 + 0.3 is 0.6000000000000001, not the exact sum 0.6.
        g = graph([{"id": f"c{i}", "type": "Constant", "params": {"value": v}} for i, v in enumerate((0.1, 0.2, 0.3))]
                  + [{"id": "s", "type": "Adder", "params": {"weights": [1, 1, 1]}}],
                  [("c0", "s", 0), ("c1", "s", 1), ("c2", "s", 2)])
        g.step()
        self.assertEqual(g.sample("s"), (0.1 + 0.2) + 0.3)
        self.assertNotEqual(g.sample("s"), 0.6)

    def test_ports(self):
        with self.assertRaisesRegex(SchemaError, "output port 1 does not exist"):
            Graph({"elements": [{"id": "c", "type": "Constant"}, {"id": "g", "type": "Gain"}],
                   "connections": [{"from_element": "c", "from_port": 1, "to_element": "g", "to_port": 0}]}, Fraction(1))
        # An omitted port is port 0, as in s7runtime's schema loader.
        g = Graph({"elements": [{"id": "c", "type": "Constant", "params": {"value": 3}}, {"id": "g", "type": "Gain"}],
                   "connections": [{"from_element": "c", "to_element": "g"}]}, Fraction(1))
        g.step()
        self.assertEqual(g.sample("g"), 3.0)

    def test_a_failed_step_leaves_every_output_as_it_was(self):
        # NodeRuntime::step: published outputs are all or nothing, and the step is retried.
        with mock.patch.dict(ELEMENT_TYPES, {"FailOnce": FailOnce}):
            g = graph([{"id": "one", "type": "Constant", "params": {"value": 1}},
                       {"id": "count", "type": "Adder", "params": {}},
                       {"id": "z", "type": "Delay", "params": {}},
                       {"id": "fail", "type": "FailOnce"},
                       {"id": "after", "type": "Gain", "params": {"factor": 10}}],
                      [("one", "count", 0), ("z", "count", 1), ("count", "z", 0), ("count", "fail", 0), ("fail", "after", 0)])
        ids = ("count", "z", "fail", "after")
        self.assertEqual(run(g, 1, *ids), [(1.0, 0.0, 1.0, 10.0)])
        with self.assertRaisesRegex(ArithmeticError, "injected fault"):
            g.step()
        self.assertEqual((g.steps, tuple(g.sample(e) for e in ids)), (1, (1.0, 0.0, 1.0, 10.0)))
        self.assertEqual(run(g, 2, *ids), [(2.0, 1.0, 2.0, 20.0), (3.0, 2.0, 3.0, 30.0)])
        self.assertEqual(g.steps, 3)


class RateTest(unittest.TestCase):
    """RateResolver (s7core/src/rate_inference.cpp): mandatory, like a type check."""

    def integrators(self, dt_a, dt_b):
        return schema([{"id": "a", "type": "EulerIntegrator", "params": {"dt": dt_a}},
                       {"id": "b", "type": "EulerIntegrator", "params": {"dt": dt_b}}], [("a", "b", 0), ("b", "a", 0)])

    def test_connected_elements_share_one_rate(self):
        Graph(self.integrators(0.01, 0.01))
        # Rates are exact rationals, not rounded to a nanosecond: a sub-nanosecond period
        # mismatch is a conflict too (rate_inference_smoke.cpp, "fractional_rate_conflict").
        with self.assertRaisesRegex(SchemaError, "rate conflict"):
            Graph(self.integrators(0.0010000001, 0.0010000002))
        with self.assertRaisesRegex(SchemaError, r"rate conflict: 'b' declares 50 Hz but 'a', connected to it, declares 100 Hz"):
            Graph(self.integrators(0.01, 0.02))
        # An oscillator pins its sample rate the same way.
        with self.assertRaisesRegex(SchemaError, "rate conflict"):
            Graph(schema([{"id": "o", "type": "AnalogOscillator", "params": {"sample_rate_hz": 1000}},
                          {"id": "x", "type": "EulerIntegrator", "params": {"dt": 0.01}}], [("o", "x", 0)]))

    def test_seed_and_undetermined_rate(self):
        constant = schema([{"id": "c", "type": "Constant"}, {"id": "g", "type": "Gain"}], [("c", "g", 0)])
        with self.assertRaisesRegex(SchemaError, r"the rate of 'c' cannot be determined \(connected to: c, g\)"):
            Graph(constant)
        Graph(constant, rate_from_step_ns(10_000_000))
        # Every connected set needs a rate: an integrator pins only its own.
        with self.assertRaisesRegex(SchemaError, "the rate of 'k' cannot be determined"):
            Graph(schema([{"id": "x", "type": "EulerIntegrator", "params": {"dt": 0.1}}, {"id": "k", "type": "Constant"},
                          {"id": "neg", "type": "Gain"}], [("x", "neg", 0), ("neg", "x", 0)]))
        # The seed only fills sets that pin no rate: it is not compared with an element's own.
        Graph(self.integrators(0.01, 0.01), rate_from_step_ns(1_000_000))

    def test_invalid_steps(self):
        for dt in (0, -0.01, 1e-10):
            with self.subTest(dt), self.assertRaisesRegex(SchemaError, "element 'a': a model-time step"):
                Graph(self.integrators(dt, 0.01))

    def test_schema_rate(self):
        self.assertEqual(schema_rate({"dt": 0.001}), Fraction(1000))
        self.assertEqual(schema_rate({"dt": 0.5}, step_rate_hz=10), Fraction(2))  # dt first
        self.assertEqual(schema_rate({}, step_rate_hz=10), Fraction(10))
        self.assertIsNone(schema_rate({}))
        # The simplest rational within binary64 precision (Rate::from_seconds): 3 Hz stays 3 Hz,
        # 44.1 kHz stays 44.1 kHz, and a dt and its 1/dt in Hz agree.
        self.assertEqual(rate_from_hz(3), Fraction(3))
        self.assertEqual(rate_from_hz(44_100), Fraction(44_100))
        self.assertEqual(rate_from_seconds(1 / 3), Fraction(3))
        for dt in (0.01, 1 / 48_000, 2.5e-7, 0.1):
            self.assertEqual(rate_from_seconds(dt), rate_from_hz(1 / dt), dt)
        for dt in ("0.1", True, None):
            with self.subTest(dt), self.assertRaisesRegex(SchemaError, "'dt' must be"):
                schema_rate({"dt": dt})

    def test_deployment_is_seeded_by_the_diagram_dt(self):
        from s7node.runtime import Executor

        executor = Executor(log=lambda _: None)
        constant = schema([{"id": "c", "type": "Constant"}])
        self.assertEqual(executor.stage(constant, 10_000_000).step_ns, 10_000_000)
        with self.assertRaisesRegex(SchemaError, "cannot be determined"):
            executor.stage(constant, None)
        # Every element's own rate must be the diagram's (NodeRuntime::set_model_time_rate),
        # even one that nothing connects to another rate.
        diagram = {"dt": 0.01, "schema": schema([{"id": "x", "type": "EulerIntegrator", "params": {"dt": 0.01}, "node": NODE},
                                                  {"id": "k", "type": "Constant", "node": NODE}], [("k", "x", 0)])}
        executor.stage(diagrams.extract_node_schema(diagram, NODE), diagrams.model_time_step_ns(diagram))
        diagram["schema"]["elements"][0]["params"]["dt"] = 0.02
        with self.assertRaisesRegex(SchemaError, "model-time rate 100 Hz conflicts with element 'x' at 50 Hz"):
            executor.stage(diagrams.extract_node_schema(diagram, NODE), diagrams.model_time_step_ns(diagram))


class TrapezoidTest(unittest.TestCase):
    """The implicit TrapezoidIntegrator (s7l2/docs/TRAPEZOID_INTEGRATION.md)."""

    def decay(self, dt, k, initial=1.0, order=1):
        elements = [{"id": "x", "type": "TrapezoidIntegrator", "params": {"dt": dt, "initial_value": initial}},
                    {"id": "f", "type": "Gain", "params": {"factor": -k}}]
        return Graph(schema(elements[::order], [("x", "f", 0), ("f", "x", 0)]))

    def oscillator(self, dt, reverse=False):
        # x' = v, v' = -x: two implicit states coupled directly, without a Delay.
        elements = [{"id": "x", "type": "TrapezoidIntegrator", "params": {"dt": dt, "initial_value": 1}},
                    {"id": "v", "type": "TrapezoidIntegrator", "params": {"dt": dt}},
                    {"id": "minus_x", "type": "Gain", "params": {"factor": -1}}]
        return Graph(schema(elements[::-1] if reverse else elements,
                            [("v", "x", 0), ("x", "minus_x", 0), ("minus_x", "v", 0)]))

    def test_scalar_decay_follows_the_exact_discrete_solution(self):
        # x' = -k x: x[n+1] = x[n] (1 - k dt/2) / (1 + k dt/2); x[n] is visible after step n + 1.
        dt, k = 0.01, 2.0
        g = self.decay(dt, k)
        factor = (1 - k * dt / 2) / (1 + k * dt / 2)
        values = [x for x, in run(g, 200, "x")]
        self.assertEqual(values[0], 1.0)
        for n, x in enumerate(values):
            self.assertTrue(math.isclose(x, factor ** n, rel_tol=1e-12), (n, x, factor ** n))

    def test_coupled_states_keep_the_energy_of_a_conservative_oscillator(self):
        # The trapezoid map of a linear oscillator is a rotation: x^2 + v^2 stays 1.
        g = self.oscillator(0.01)
        for _ in range(20_000):  # 200 model seconds
            g.step()
            energy = g.sample("x") ** 2 + g.sample("v") ** 2
        self.assertTrue(math.isclose(energy, 1.0, rel_tol=1e-9), energy)
        # Its phase advances by 2 atan(dt/2) per step, close to dt.
        theta = 2 * math.atan(0.01 / 2) * (g.steps - 1)
        self.assertTrue(math.isclose(g.sample("x"), math.cos(theta), abs_tol=1e-8))

    def test_result_does_not_depend_on_declaration_order(self):
        a, b = self.oscillator(0.05), self.oscillator(0.05, reverse=True)
        self.assertEqual(run(a, 500, "x", "v"), run(b, 500, "x", "v"))

    def test_derivative_through_stateful_feedthrough_is_refused(self):
        with self.assertRaisesRegex(SchemaError, "stateful direct-feedthrough element 'acc'"):
            Graph(schema([{"id": "x", "type": "TrapezoidIntegrator", "params": {"dt": 0.1}},
                          {"id": "acc", "type": "Accumulator"}], [("x", "acc", 0), ("acc", "x", 0)]))
        # A stateful element the derivative does not reach through a trial state is fine:
        # the oscillator is held for the step, like any source.
        g = Graph(schema([{"id": "x", "type": "TrapezoidIntegrator", "params": {"dt": 0.25}},
                          {"id": "o", "type": "AnalogOscillator", "params": {"sample_rate_hz": 4, "frequency_hz": 1}},
                          {"id": "sum", "type": "Adder", "params": {"weights": [1, -1]}}],
                         [("o", "sum", 0), ("x", "sum", 1), ("sum", "x", 0)]))
        self.assertEqual([e.id for e in g.trapezoid_rhs], ["sum"])
        run(g, 8, "x")

    def test_nonconvergence_restores_the_published_state(self):
        # x' = -k x with k dt / 2 = 5: the fixed-point iteration is not contractive.
        g = self.decay(1.0, 10.0)
        with self.assertRaisesRegex(RuntimeError, "did not converge after 64 iterations"):
            g.step()
        self.assertEqual((g.steps, g.sample("x"), g.sample("f")), (0, 1.0, 0.0))
        with self.assertRaisesRegex(RuntimeError, "did not converge"):
            g.step()  # retried from the same state, failing the same way
        self.assertEqual((g.steps, g.sample("x")), (0, 1.0))

    def test_sampled_mode_integrates_supplied_samples(self):
        # A ramp 0, 1, 2, ... integrates exactly: y[n] = n^2 / 2 (dt = 1); direct feedthrough.
        g = Graph(schema([{"id": "one", "type": "Constant", "params": {"value": 1}},
                          {"id": "ramp", "type": "Accumulator", "params": {"initial_value": -1}},
                          {"id": "y", "type": "TrapezoidIntegrator", "params": {"mode": "sampled"}}],
                         [("one", "ramp", 0), ("ramp", "y", 0)]))
        self.assertEqual([y for y, in run(g, 5, "y")], [n * n / 2 for n in range(5)])
        with self.assertRaisesRegex(SchemaError, "cycle without causal memory"):
            Graph(schema([{"id": "y", "type": "TrapezoidIntegrator", "params": {"mode": "sampled"}},
                          {"id": "f", "type": "Gain", "params": {"factor": -1}}], [("y", "f", 0), ("f", "y", 0)]))

    def test_implicit_element_is_stepped_only_by_the_graph(self):
        with self.assertRaisesRegex(RuntimeError, "coupled numerical stage"):
            TrapezoidIntegrator("x", {}).step([0.0])


class DiagramTest(unittest.TestCase):
    def diagram(self, connections, streams=None):
        d = {"schema": schema([{"id": "a", "type": "Constant", "node": NODE},
                               {"id": "b", "type": "Gain", "node": NODE},
                               {"id": "c", "type": "Gain", "node": OTHER}], connections)}
        if streams is not None:
            d["streams"] = streams
        return d

    def test_node_part(self):
        part = diagrams.extract_node_schema(self.diagram([("a", "b", 0)]), NODE)
        self.assertEqual(part["name"], f"t@{NODE}")
        self.assertEqual([e["id"] for e in part["elements"]], ["a", "b"])
        self.assertNotIn("node", part["elements"][0])
        self.assertEqual(len(part["connections"]), 1)
        self.assertEqual(diagrams.placed_nodes(self.diagram([])), [NODE, OTHER])

    def test_connection_between_nodes_needs_a_stream(self):
        with self.assertRaisesRegex(SchemaError, "leaves this node without a stream"):
            diagrams.extract_node_schema(self.diagram([("a", "b", 0), ("b", "c", 0)]), NODE)

    def test_stream_ends_are_refused(self):
        stream = {"stream_id": "5d4c3b2a-1f0e-4d9c-8b7a-6f5e4d3c2b1a", "data_type": "F64",
                  "producer": {"node_uuid": NODE, "element": "b", "port": 0},
                  "consumers": [{"node_uuid": OTHER, "element": "c", "port": 0}]}
        with self.assertRaisesRegex(SchemaError, "no data plane"):
            diagrams.extract_node_schema(self.diagram([("a", "b", 0), ("b", "c", 0)], [stream]), NODE)

    def test_model_time_step(self):
        self.assertEqual(diagrams.model_time_step_ns({"dt": 0.001}), 1_000_000)
        self.assertIsNone(diagrams.model_time_step_ns({}))
        with self.assertRaises(SchemaError):
            diagrams.model_time_step_ns({"dt": 0})


def free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class NodeProcess:
    """An s7node process on a free port with its own state directory."""

    def __init__(self, config: dict, state_dir: Path, *args):
        self.port = free_port()
        config.setdefault("websocket", {}).setdefault("server", {})["port"] = self.port
        path = state_dir.parent / f"{state_dir.name}.json"
        path.write_text(json.dumps(config))
        self.process = subprocess.Popen(
            [sys.executable, "-m", "s7node", "--schema", str(path), "--state-dir", str(state_dir), *args],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.lines = []
        for line in self.process.stdout:  # ready once it prints its control URL
            self.lines.append(line)
            if line.startswith("runtime.listen_url="):
                break

    def stop(self) -> str:
        self.process.terminate()
        output, _ = self.process.communicate(timeout=10)
        return "".join(self.lines) + output


def have_cryptography() -> bool:
    try:
        import cryptography  # noqa: F401
    except ImportError:
        return False
    return True


@unittest.skipUnless(have_cryptography() and CERTS.exists(), "needs the cryptography package and s7l2 test certificates")
class ConformanceTest(unittest.TestCase):
    def test_control_fixtures(self):
        """The control protocol conformance script, over mTLS, except its data-stream steps."""
        from check_control_fixtures import run

        from s7node.tls import client_context, load_certificate_file

        studio = load_certificate_file(str(CERTS / "s7_studio.cert.pem"))
        config = {
            "websocket": {"server": {"bind_address": "127.0.0.1", "tls": {
                "cert_file": str(CERTS / "s7_runtime_node.cert.pem"), "key_file": str(CERTS / "s7_runtime_node.key.pem"),
                "ca_file": str(CERTS / "s7_root_ca.cert.pem")}}},
            "control": {"studio_key_purpose_oid": "2.25.4266950079767543379770189370854073200",
                        "studio_certificate_sha256": studio.fingerprint_sha256, "max_configuration_bytes": 2048},
            "clock": {"assume_synchronized": True},
        }
        ca = str(CERTS / "s7_root_ca.cert.pem")
        contexts = {"anonymous": client_context(ca),
                    "studio": client_context(ca, str(CERTS / "s7_studio.cert.pem"), str(CERTS / "s7_studio.key.pem"))}
        with tempfile.TemporaryDirectory() as tmp:
            node = NodeProcess(config, Path(tmp) / "node")
            try:
                failures = asyncio.run(run(f"wss://127.0.0.1:{node.port}", contexts, skip_streams=True))
            finally:
                output = node.stop()
            self.assertEqual(failures, 0, output)
            # The committed revision 1 was persisted and is restored by the next process.
            node = NodeProcess(config, Path(tmp) / "node")
            output = node.stop()
            self.assertIn("deployment.restored deployment_id=fixture-deployment revision=1", output)


class PlainWebSocketTest(unittest.TestCase):
    def test_read_only_requests_and_refused_mutation(self):
        from s7node.websocket import connect

        async def talk(port):
            ws = await connect("127.0.0.1", port, "/control")
            responses = []
            for request in ({"type": "HELLO", "request_id": "h", "protocol_version": 1},
                            {"type": "LIST_DEPLOYMENTS", "request_id": "l", "protocol_version": 1},
                            {"type": "PREPARE_DEPLOYMENT", "request_id": "p", "protocol_version": 1, "deployment": {}}):
                await ws.send(json.dumps(request))
                responses.append(json.loads(await ws.recv()))
            await ws.close()
            return responses

        startup = schema([{"id": "c", "type": "Constant", "params": {"value": 1}},
                          {"id": "acc", "type": "Accumulator", "params": {}}], [("c", "acc", 0)])
        with tempfile.TemporaryDirectory() as tmp:
            node = NodeProcess({**startup, "execution": {"step_rate_hz": 50}}, Path(tmp) / "node")
            try:
                hello, deployments, prepare = asyncio.run(talk(node.port))
            finally:
                node.stop()
        self.assertEqual(hello["type"], "HELLO_OK")
        self.assertEqual(hello["status"], "idle")
        self.assertEqual(deployments["execution"], "stepping")
        self.assertEqual(deployments["timing"]["pacing"], "rate")
        self.assertEqual((prepare["type"], prepare["code"]), ("ERROR", "UNAUTHORIZED"))


if __name__ == "__main__":
    unittest.main()

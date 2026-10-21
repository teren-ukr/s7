# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Schema -> validate -> compile -> step, for a subset of the built-in elements.

Mirrors s7core (elements.hpp, builtin_element_registry.cpp, validation.cpp,
rate_inference.cpp, runtime.cpp) for F64 signals only: every value is a Python
float. Elements with direct feedthrough run in causal order; causal-memory
elements (Delay, PreviousValue, EulerIntegrator, an implicit TrapezoidIntegrator)
stage what they compute and publish it at the start of the next step, so a cycle
must pass through one of them and every value read after a step belongs to that
step (doc/S7_Formal_Model.md, "Causal Memory").
"""
import math
from fractions import Fraction


class SchemaError(ValueError):
    pass


# ---- rates (s7core rate.hpp: samples per second, exact) ---------------------------

def rate_from_step_ns(step_ns: int) -> Fraction:
    return Fraction(1_000_000_000, step_ns)


_UINT64_MAX = 2**64 - 1
_PERIOD_TOLERANCE = 2 * Fraction(2) ** -52  # twice binary64 machine epsilon, relative


def _long_double(x: Fraction) -> Fraction:
    """x rounded to the nearest x86 long double (64-bit significand, ties to even), the type
    Rate::from_seconds computes in; near its tolerance the rounding decides the convergent."""
    if x == 0:
        return x
    magnitude = abs(x)
    exponent = magnitude.numerator.bit_length() - magnitude.denominator.bit_length()
    if Fraction(2) ** exponent > magnitude:
        exponent -= 1
    scaled = magnitude / Fraction(2) ** (exponent - 63)  # in [2^63, 2^64)
    significand = round(scaled)  # Fraction rounds half to even
    return (1 if x > 0 else -1) * significand * Fraction(2) ** (exponent - 63)


def rate_from_seconds(dt: float) -> Fraction:
    """The simplest rational period within binary64 precision of dt, as s7::Rate::from_seconds:
    the first continued-fraction convergent of 1/(1/dt) within twice machine epsilon, so that
    dt and an equivalent 1/dt in Hz give the same rate. Rounded like its long double arithmetic."""
    if not (dt > 0) or not math.isfinite(dt):
        raise SchemaError("a model-time step must be a positive, finite number of seconds")
    if dt < 1e-9 or dt > 9e9:
        raise SchemaError("a model-time step must be between 1 ns and 9e9 s")
    period = Fraction(1.0 / (1.0 / dt))
    remainder = period
    p0, p1, q0, q1 = 0, 1, 1, 0  # convergents p/q of the period
    while True:
        whole = math.floor(remainder)
        if whole >= _UINT64_MAX or (p1 and whole > (_UINT64_MAX - p0) // p1) or (q1 and whole > (_UINT64_MAX - q0) // q1):
            break
        p, q = whole * p1 + p0, whole * q1 + q0
        if p and q and abs(_long_double(_long_double(Fraction(p, q)) - period)) <= period * _PERIOD_TOLERANCE:
            return Fraction(q, p)
        p0, p1, q0, q1 = p1, p, q1, q
        fraction = remainder - whole  # exact in long double too
        if fraction == 0:
            break
        remainder = _long_double(1 / fraction)
    raise SchemaError("a model-time step that cannot be represented as a rational rate")


def rate_from_hz(hz: float) -> Fraction:
    if not (hz > 0) or not math.isfinite(hz):
        raise SchemaError("a sample rate must be a positive, finite number of Hz")
    return rate_from_seconds(1.0 / hz)


def rate_text(rate: Fraction) -> str:
    if rate.denominator == 1:
        return f"{rate.numerator} Hz"
    return f"{float(rate):g} Hz ({rate.numerator}/{rate.denominator})"


def schema_rate(schema: dict, step_rate_hz: float = 0.0) -> Fraction | None:
    """The rate seed of a schema (s7runtime build_schema_from_definition): its own dt, else the node's step rate."""
    if "dt" in schema:
        dt = schema["dt"]
        if isinstance(dt, bool) or not isinstance(dt, (int, float)):
            raise SchemaError("'dt' must be a positive number of seconds")
        return rate_from_seconds(dt)
    return rate_from_hz(step_rate_hz) if step_rate_hz > 0 else None


# ---- parameters -------------------------------------------------------------------

def _number(params: dict, name: str, default: float) -> float:
    value = params.get(name, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SchemaError(f"parameter '{name}' must be a number (s7py supports F64 signals only)")
    return float(value)


def _numbers(params: dict, name: str) -> list[float]:
    values = params.get(name, [1, 1])
    if not isinstance(values, list) or not values:
        raise SchemaError(f"parameter '{name}' must be a non-empty array of numbers")
    if len(values) == 1 or len(values) > 64:
        raise SchemaError(f"parameter '{name}' must have 2 to 64 entries")
    return [_number({name: value}, name, 0.0) for value in values]


def _choice(params: dict, name: str, allowed: tuple[str, ...]) -> str:
    value = params.get(name, allowed[0])
    if value not in allowed:
        raise SchemaError(f"parameter '{name}' must be one of {', '.join(allowed)}")
    return value


# Parameters every element of a kind declares besides its own (builtin_element_registry.cpp).
GENERIC = ("type",)
ARITHMETIC = GENERIC + ("overflow",)
ACCUMULATING = ARITHMETIC + ("accumulator_type",)


def _check_params(params: dict, known: tuple[str, ...]) -> None:
    for name in params:
        if name not in known:
            raise SchemaError(f"unknown parameter '{name}' (known: {', '.join(known)})")
    for name in ("type", "accumulator_type"):
        if params.get(name, "F64") != "F64":
            raise SchemaError(f"parameter '{name}': type {params[name]} is not supported (F64 only)")
    if "overflow" in params:
        _choice(params, "overflow", ("saturate", "wrap"))


# ---- elements -----------------------------------------------------------------------

class Element:
    """One instance in a graph. Subclasses set their ports and flags and implement step()."""

    params = GENERIC
    memory = False  # causal memory (no direct feedthrough): outputs depend only on earlier inputs
    stateful = False  # keeps state between steps; the trapezoid solver must not reevaluate it
    input_count = 0
    output_count = 1

    def __init__(self, element_id: str, params: dict):
        self.id = element_id
        self.outputs = [0.0] * self.output_count

    def rate(self) -> Fraction | None:
        """The rate this element pins by itself (Element::declared_rate), if any."""
        return None

    def step(self, inputs: list[float]) -> None:
        raise NotImplementedError


class Constant(Element):
    params = GENERIC + ("value",)

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.outputs[0] = _number(params, "value", 0.0)

    def step(self, inputs):
        pass


class Gain(Element):
    params = ARITHMETIC + ("factor",)
    input_count = 1

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.factor = _number(params, "factor", 1.0)

    def step(self, inputs):
        self.outputs[0] = inputs[0] * self.factor


class Adder(Element):
    params = ACCUMULATING + ("weights",)

    def __init__(self, element_id, params):
        self.weights = _numbers(params, "weights")
        self.input_count = len(self.weights)
        super().__init__(element_id, params)

    def step(self, inputs):
        total = 0.0  # summed in input order, as AdderT does: the same value to the last bit
        for x, weight in zip(inputs, self.weights):
            total += x * weight
        self.outputs[0] = total


class Multiply(Element):
    params = ACCUMULATING + ("factors",)

    def __init__(self, element_id, params):
        self.factors = _numbers(params, "factors")
        self.input_count = len(self.factors)
        super().__init__(element_id, params)

    def step(self, inputs):
        product = 1.0
        for x, factor in zip(inputs, self.factors):
            product *= x * factor
        self.outputs[0] = product


class Delay(Element):
    """Unit delay z^-1 ("Delay" and "PreviousValue" are the same element)."""

    params = GENERIC + ("initial_value",)
    memory = True
    stateful = True
    input_count = 1

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.outputs[0] = _number(params, "initial_value", 0.0)

    def step(self, inputs):
        self.outputs[0] = inputs[0]


class Accumulator(Element):
    params = ACCUMULATING + ("initial_value",)
    stateful = True
    input_count = 1

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.outputs[0] = _number(params, "initial_value", 0.0)

    def step(self, inputs):
        self.outputs[0] += inputs[0]


class EulerIntegrator(Element):
    """y[n+1] = y[n] + dt * x[n]; causal memory, so it can close a loop."""

    params = GENERIC + ("dt", "initial_value")
    memory = True
    stateful = True
    input_count = 1

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.dt = _number(params, "dt", 1.0)
        self.outputs[0] = _number(params, "initial_value", 0.0)

    def rate(self):
        return rate_from_seconds(self.dt)

    def step(self, inputs):
        self.outputs[0] = self.outputs[0] + inputs[0] * self.dt


# Implicit trapezoid: at most this many fixed-point corrections per step, each
# state converged within 8 machine epsilons (s7l2/docs/TRAPEZOID_INTEGRATION.md).
TRAPEZOID_ITERATIONS = 64
TRAPEZOID_TOLERANCE = math.ldexp(1.0, 4 - 53)


class TrapezoidIntegrator(Element):
    """mode "implicit" (default): y[n+1] = y[n] + dt/2 * (f(y[n]) + f(y[n+1])), solved by
    Graph together with every other implicit state; causal memory.
    mode "sampled": y[n] = y[n-1] + dt/2 * (x[n] + x[n-1]) of supplied samples; direct feedthrough.
    """

    params = GENERIC + ("dt", "initial_value", "mode")
    stateful = True
    input_count = 1

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.implicit = _choice(params, "mode", ("implicit", "sampled")) == "implicit"
        self.memory = self.implicit
        self.half_dt = _number(params, "dt", 1.0) / 2
        self.outputs[0] = _number(params, "initial_value", 0.0)
        self.previous = None
        self.base_value = self.base_input = self.candidate = 0.0

    def rate(self):
        return rate_from_seconds(self.half_dt * 2)

    def step(self, inputs):
        if self.implicit:
            raise RuntimeError("an implicit TrapezoidIntegrator is stepped by the graph's coupled numerical stage")
        x = inputs[0]
        if self.previous is not None:
            self.outputs[0] = self.outputs[0] + (x + self.previous) * self.half_dt
        self.previous = x

    def prepare_trapezoid_step(self, inputs):
        """Forward-Euler predictor from the published state and its current derivative."""
        self.base_value, self.base_input = self.outputs[0], inputs[0]
        self.candidate = self.base_value + self.base_input * (self.half_dt * 2)

    def correct_trapezoid_candidate(self, inputs) -> bool:
        """Trapezoidal correction from the derivative at the published candidate; True once converged."""
        self.candidate = self.base_value + (self.base_input + inputs[0]) * self.half_dt
        magnitude, difference = abs(self.candidate), abs(self.candidate - self.outputs[0])
        if not (math.isfinite(magnitude) and math.isfinite(difference)):
            raise RuntimeError("TrapezoidIntegrator produced a non-finite candidate")
        return difference <= TRAPEZOID_TOLERANCE * (1 + magnitude)

    def publish_trapezoid_candidate(self):
        self.outputs[0] = self.candidate


class AnalogOscillator(Element):
    params = GENERIC + ("amplitude", "frequency_hz", "sample_rate_hz", "phase")
    stateful = True

    def __init__(self, element_id, params):
        super().__init__(element_id, params)
        self.amplitude = _number(params, "amplitude", 1.0)
        self.sample_rate = _number(params, "sample_rate_hz", 1.0)
        if not self.sample_rate > 0:
            raise SchemaError("AnalogOscillator requires a positive sample rate")
        self.increment = 2 * math.pi * _number(params, "frequency_hz", 1.0) / self.sample_rate
        self.phase = _number(params, "phase", 0.0)

    def rate(self):
        return rate_from_hz(self.sample_rate)

    def step(self, inputs):
        self.outputs[0] = self.amplitude * math.sin(self.phase)
        self.phase += self.increment
        if abs(self.phase) > 2 * math.pi:
            self.phase = math.fmod(self.phase, 2 * math.pi)


ELEMENT_TYPES: dict[str, type[Element]] = {
    "Constant": Constant,
    "Gain": Gain,
    "Adder": Adder,
    "Multiply": Multiply,
    "Delay": Delay,
    "PreviousValue": Delay,
    "Accumulator": Accumulator,
    "EulerIntegrator": EulerIntegrator,
    "TrapezoidIntegrator": TrapezoidIntegrator,
    "AnalogOscillator": AnalogOscillator,
}

# Data-plane elements a node fragment may contain; s7py has no data plane yet.
STREAM_ELEMENTS = ("NetSink", "NetSource")


def _index(value, what: str) -> int:
    if value is None:
        return 0  # an omitted port is port 0, as in s7runtime's schema loader
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SchemaError(f"{what} must be a non-negative integer")
    return value


class Graph:
    """A compiled schema: elements in execution order, ready to step.

    rate seeds every element that pins no rate of its own (schema_rate(), or a
    deployment's model-time step); a connected set of elements with neither is refused.
    """

    def __init__(self, schema: dict, rate: Fraction | None = None):
        self.name = schema.get("name", "schema") if isinstance(schema.get("name"), str) else "schema"
        self.elements: dict[str, Element] = {}
        elements = schema.get("elements", [])
        connections = schema.get("connections", [])
        if not isinstance(elements, list) or not isinstance(connections, list):
            raise SchemaError("'elements' and 'connections' must be arrays")

        for entry in elements:
            if not isinstance(entry, dict) or not isinstance(entry.get("id"), str) or not entry["id"]:
                raise SchemaError("every element needs a non-empty string 'id'")
            element_id, type_name = entry["id"], entry.get("type")
            if element_id in self.elements:
                raise SchemaError(f"duplicate element id '{element_id}'")
            if "schema" in entry:
                raise SchemaError(f"element '{element_id}': nested schemas are not supported by s7py")
            if type_name in STREAM_ELEMENTS:
                raise SchemaError(f"element '{element_id}': data streams ({type_name}) are not supported by s7py")
            if type_name not in ELEMENT_TYPES:
                raise SchemaError(f"element '{element_id}': unknown element type '{type_name}'")
            params = entry.get("params", {})
            if not isinstance(params, dict):
                raise SchemaError(f"element '{element_id}': 'params' must be an object")
            element_type = ELEMENT_TYPES[type_name]
            try:
                _check_params(params, element_type.params)
                self.elements[element_id] = element_type(element_id, params)
            except SchemaError as error:
                raise SchemaError(f"element '{element_id}': {error}") from None

        # drivers[element][port] = (driving element, its output port); each input has exactly one driver.
        self.drivers: dict[str, list[tuple[Element, int] | None]] = {
            e.id: [None] * e.input_count for e in self.elements.values()}
        for c in connections:
            if not isinstance(c, dict):
                raise SchemaError("a connection must be an object")
            source, target = self.elements.get(c.get("from_element")), self.elements.get(c.get("to_element"))
            if source is None or target is None:
                raise SchemaError(f"connection {c.get('from_element')} -> {c.get('to_element')}: unknown element")
            from_port = _index(c.get("from_port"), "from_port")
            if from_port >= source.output_count:
                raise SchemaError(f"connection from '{source.id}': output port {from_port} does not exist")
            port = _index(c.get("to_port"), "to_port")
            if port >= target.input_count:
                raise SchemaError(f"connection to '{target.id}': input port {port} does not exist")
            if self.drivers[target.id][port] is not None:
                raise SchemaError(f"input '{target.id}':{port} has more than one driver")
            self.drivers[target.id][port] = (source, from_port)
        for element_id, ports in self.drivers.items():
            for port, driver in enumerate(ports):
                if driver is None:
                    raise SchemaError(f"input '{element_id}':{port} is not connected")

        self.causal_order = self._causal_order()
        self.memory_order = [e for e in self.elements.values() if e.memory]
        self._resolve_rates(rate)
        self.trapezoids = [e for e in self.memory_order if isinstance(e, TrapezoidIntegrator)]
        self.trapezoid_rhs = self._trapezoid_rhs()
        self._staged: list[list[float]] | None = None  # memory outputs to publish at the next step
        self.steps = 0

    def _causal_order(self) -> list[Element]:
        """Topological order of feedthrough elements; an edge out of causal memory does not count."""
        order, state = [], {}

        def visit(element: Element, path: list[str]):
            if state.get(element.id) == "done":
                return
            if state.get(element.id) == "visiting":
                raise SchemaError("cycle without causal memory: " + " -> ".join(path + [element.id]))
            state[element.id] = "visiting"
            for driver, _ in self.drivers[element.id]:
                if not driver.memory:
                    visit(driver, path + [element.id])
            state[element.id] = "done"
            order.append(element)

        for element in self.elements.values():
            if not element.memory:
                visit(element, [])
        return order

    def _resolve_rates(self, seed: Fraction | None) -> None:
        """RateResolver: connected elements share one rate, pinned by an element or the seed."""
        root = {element_id: element_id for element_id in self.elements}

        def find(element_id: str) -> str:
            while root[element_id] != element_id:
                root[element_id] = root[root[element_id]]
                element_id = root[element_id]
            return element_id

        for element_id, ports in self.drivers.items():
            for driver, _ in ports:
                root[find(driver.id)] = find(element_id)

        pinned: dict[str, tuple[Fraction, str]] = {}
        members: dict[str, list[str]] = {}
        for element in self.elements.values():
            group = find(element.id)
            members.setdefault(group, []).append(element.id)
            try:
                declared = element.rate()
            except SchemaError as error:
                raise SchemaError(f"element '{element.id}': {error}") from None
            if declared is None:
                continue
            if group not in pinned:
                pinned[group] = (declared, element.id)
            elif pinned[group][0] != declared:
                rate, by = pinned[group]
                raise SchemaError(f"rate conflict: '{element.id}' declares {rate_text(declared)} but '{by}', "
                                  f"connected to it, declares {rate_text(rate)}; insert a rate-changing element")
        if seed is None:
            for group, ids in members.items():
                if group not in pinned:
                    raise SchemaError(f"the rate of '{ids[0]}' cannot be determined (connected to: {', '.join(ids)}); "
                                      "pin a rate on one of them (e.g. an integrator's \"dt\"), or set the schema's dt")

    def require_model_time_rate(self, rate: Fraction) -> None:
        """The run's model-time rate must be every element's own (NodeRuntime::set_model_time_rate)."""
        for element in self.elements.values():
            declared = element.rate()
            if declared is not None and declared != rate:
                raise SchemaError(f"model-time rate {rate_text(rate)} conflicts with element '{element.id}' at "
                                  f"{rate_text(declared)}; match the diagram's dt and the element's discretization")

    def _trapezoid_rhs(self) -> list[Element]:
        """The stateless elements an implicit TrapezoidIntegrator's derivative depends on through
        a trial state; the solver reevaluates them, so none may keep state (validation.cpp)."""
        varying: dict[str, bool] = {}
        visiting: set[str] = set()

        def visit(element: Element) -> bool:
            if element in self.trapezoids:
                return True
            if element.memory:
                return False
            if element.id in varying:
                return varying[element.id]
            if element.id in visiting:
                raise SchemaError("cycle without causal memory in a TrapezoidIntegrator derivative graph")
            visiting.add(element.id)
            depends = False
            for driver, _ in self.drivers[element.id]:
                depends = visit(driver) or depends
            visiting.discard(element.id)
            varying[element.id] = depends
            if depends and element.stateful:
                raise SchemaError(f"an implicit TrapezoidIntegrator's derivative depends on stateful direct-feedthrough "
                                  f"element '{element.id}'; only stateless operations may be reevaluated")
            return depends

        for integrator in self.trapezoids:
            for driver, _ in self.drivers[integrator.id]:
                visit(driver)
        return [e for e in self.causal_order if varying.get(e.id)]

    def _inputs(self, element: Element) -> list[float]:
        return [driver.outputs[port] for driver, port in self.drivers[element.id]]

    def step(self) -> None:
        """One step, all or nothing for published outputs (NodeRuntime::step): a step that raises
        leaves every output as it was, and the next step retries it. Private element state
        (an Accumulator's sum, a TrapezoidIntegrator's previous sample) is not rolled back."""
        memory = self.memory_order
        staged, self._staged = self._staged, None
        if staged is not None:
            published = [e.outputs[:] for e in memory]
            for element, values in zip(memory, staged):
                element.outputs[:] = values
        causal = [e.outputs[:] for e in self.causal_order]
        try:
            for element in self.causal_order:
                element.step(self._inputs(element))
            solved = self._solve_trapezoids()
        except Exception:
            for element, values in zip(self.causal_order, causal):
                element.outputs[:] = values
            if staged is not None:
                for element, values in zip(memory, published):
                    element.outputs[:] = values
                self._staged = staged
            raise
        # Causal memory computes its next outputs from this step's inputs, then shows
        # this step's outputs again until the next step publishes them.
        next_outputs = []
        for element in memory:
            if element in solved:
                next_outputs.append(solved[element])
                continue
            current = element.outputs[:]
            try:
                element.step(self._inputs(element))
            finally:
                next_outputs.append(element.outputs[:])
                element.outputs[:] = current
        self._staged = next_outputs if memory else None
        self.steps += 1

    def _solve_trapezoids(self) -> dict[Element, list[float]]:
        """The implicit trapezoid stage: all implicit states solved together by fixed-point
        iteration, reevaluating their derivative cone; every trial output is restored after."""
        if not self.trapezoids:
            return {}
        trial = self.trapezoids + self.trapezoid_rhs
        base = [e.outputs[:] for e in trial]
        try:
            for integrator in self.trapezoids:
                integrator.prepare_trapezoid_step(self._inputs(integrator))
            for integrator in self.trapezoids:
                integrator.publish_trapezoid_candidate()
            for _ in range(TRAPEZOID_ITERATIONS):
                for element in self.trapezoid_rhs:
                    element.step(self._inputs(element))
                converged = True
                # Every correction reads the same iterate: publish only after all are formed.
                for integrator in self.trapezoids:
                    converged = integrator.correct_trapezoid_candidate(self._inputs(integrator)) and converged
                for integrator in self.trapezoids:
                    integrator.publish_trapezoid_candidate()
                if converged:
                    return {integrator: integrator.outputs[:] for integrator in self.trapezoids}
            raise RuntimeError(f"implicit TrapezoidIntegrator did not converge after {TRAPEZOID_ITERATIONS} "
                               "iterations; reduce dt (the fixed-point solver needs a contractive step)")
        finally:
            for element, values in zip(trial, base):
                element.outputs[:] = values

    def sample(self, element_id: str, port: int = 0) -> float:
        return self.elements[element_id].outputs[port]

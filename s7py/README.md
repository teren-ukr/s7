# s7py — minimal S7 headless node in Python

A headless S7 runtime node written in Python. It speaks the S7 control protocol (`../doc/S7_Control_Protocol_MVP.md`) the same way the C++ `s7runtime` does, so Studio can discover it and Studio or `s7ctl` can deploy diagrams to it, and it runs its part of a diagram for a subset of the built-in elements.

It needs only the Python standard library (3.10+). TLS mode also needs the `cryptography` package (`pip install cryptography`), which it uses to read certificate SAN and Extended Key Usage.

## What it does

- **Control protocol v1**: `HELLO`, `GET_NODE_INFO`, `GET_PEERS`, `PEER_ANNOUNCE`, `LIST_DEPLOYMENTS`, `GET_NETWORK_CONFIGURATION`, `GET_STREAM_STATUS`, `PREPARE_DEPLOYMENT` / `COMMIT_DEPLOYMENT` / `ABORT_DEPLOYMENT` (with `activate_at_ns`), and chunked configuration transfer. Errors, idempotent repeats, limits and expiry follow `s7runtime/src/control_plane_mvp.cpp`.
- **Security**: `wss://` with mutual TLS. Mutations are accepted only from the pinned Studio certificate carrying the control-node key purpose, and never on the strength of JSON fields. Plain `ws://` serves read-only requests on loopback.
- **Digests**: RFC 8785 canonical JSON and the `sha256:` configuration digest, checked against the fixture digests computed by `tools/gen_control_fixtures.py`.
- **Execution**: a node's part of a diagram is validated as by `s7core` (parameters against each element's declaration, port indices, one driver per input, every input connected, cycles through causal memory, and one rate per connected set of elements: `../doc/S7_Sample_Rate_Model.md`), compiled into causal order and stepped. Causal memory publishes what it computed at the start of the next step, so every value read after a step belongs to that step; a step that fails leaves every published output as it was. A diagram with `dt` runs on a UTC grid from its activation time and catches up when behind; others run at `execution.step_rate_hz`.
- **Rates**: an element with a time step (`EulerIntegrator`, `TrapezoidIntegrator` `dt`, `AnalogOscillator` `sample_rate_hz`) pins the rate of everything connected to it. Elements that pin none take the deployed diagram's `dt`, or, in the startup graph, its own `dt`, else `execution.step_rate_hz`; a graph with neither is refused. In a deployed diagram every element's own rate must also equal its `dt`. A rate is the exact rational nearest to the configured binary64 value (so 0.0010000001 s and 0.0010000002 s differ, and 44.1 kHz stays 44.1 kHz), as `s7::Rate::from_seconds`.
- **Elements** (F64 only): `Constant`, `Gain`, `Adder`, `Multiply`, `Delay`, `PreviousValue`, `Accumulator`, `EulerIntegrator`, `TrapezoidIntegrator` (implicit by default, all its states solved together each step, or `"mode": "sampled"`; `../s7l2/docs/TRAPEZOID_INTEGRATION.md`), `AnalogOscillator`.
- **State directory**: holds the node UUID (taken from the certificate's `spiffe://s7/node/<uuid>` SAN in TLS mode), the peer cache, and the active deployment, which is restored on restart. The directory is locked against a second process.
- **Clock**: synchronization is read from the kernel (`ntp_adjtime`) on Linux. Use `"clock": {"assume_synchronized": true}` elsewhere or in tests.

## Not implemented

- **Data plane** (`NetSink` / `NetSource`, wire protocol v1). `NODE_INFO` advertises no packet versions, and a node part containing a stream end is refused as `NOT_READY` (`INVALID_CONFIGURATION`). Each node must therefore run a self-contained part of a diagram.
- Signal types other than F64, nested schemas, plugins and schema libraries.
- Outbound peer probing: seed peers and announcements are only listed.

## Run

From this directory:

```bash
# plain ws://127.0.0.1:9012, steps a counter at 10 Hz and prints it once per second
python3 -m s7node --schema examples/node_plain.json --state-dir /tmp/s7py-a --watch count

# mTLS on wss://127.0.0.1:9012 as node 33333333-… (s7l2 test certificate), the test Studio pinned
python3 -m s7node --schema examples/node_tls.json --state-dir /tmp/s7py-b --watch position --watch velocity
```

Then deploy to it from `../s7l2`:

```bash
TLS="--cert s7runtime/examples/certs/s7_studio.cert.pem --key s7runtime/examples/certs/s7_studio.key.pem --ca s7runtime/examples/certs/s7_root_ca.cert.pem"
./build/s7ctl/s7ctl deploy ../s7py/examples/damped_oscillator.s7diagram $TLS
./build/s7ctl/s7ctl info wss://127.0.0.1:9012 $TLS
```

The node schema file uses the `s7runtime` format: `websocket.server` (`port`, `bind_address`, `tls` with `cert_file` / `key_file` / `ca_file`), `control` (`studio_key_purpose_oid`, `studio_certificate_sha256`, `max_configuration_bytes`), `clock`, `execution.step_rate_hz`, an optional `node_name`, and an optional startup graph (`dt`, `elements`, `connections`). `examples/node_tls.json` pins the fingerprint of the current test Studio certificate. Regenerating the s7l2 test certificates changes that fingerprint, so update it with `openssl x509 -in s7_studio.cert.pem -noout -fingerprint -sha256`.

Options: `python3 -m s7node --help`.

## Test

```bash
python3 -m unittest discover -s tests
```

`tools/check_control_fixtures.py` runs the control protocol conformance script (`../s7l2/s7runtime/tests/fixtures/control_v1.json`) against any node. `--skip-streams` leaves out the steps that need a data stream. The test suite runs it against this node over mTLS.

## Layout

| File | Content |
|---|---|
| `s7node/control.py` | Control protocol messages, authorization, deployments, transfers, persistence |
| `s7node/graph.py` | Elements, validation, causal ordering, stepping |
| `s7node/runtime.py` | Executor: grid / rate pacing, scheduled activation |
| `s7node/diagram.py` | A node's part of a deployed diagram |
| `s7node/jcs.py` | RFC 8785 canonical JSON, configuration digest |
| `s7node/websocket.py` | Minimal RFC 6455 server and client on asyncio |
| `s7node/tls.py` | TLS contexts, certificate identity (fingerprint, SAN, EKU) |
| `s7node/clock.py` | UTC clock synchronization state |
| `s7node/node.py` | Configuration, state directory, server, CLI |

## License

GPL-3.0-or-later; the examples are CC0-1.0. See [`../LICENSING.md`](../LICENSING.md).

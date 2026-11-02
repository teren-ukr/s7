# S7

S7 is a platform for building, running and observing distributed causal systems: signal processing, software-defined radio, distributed sensing, simulation of dynamic systems. A system is a schema of elements and connections. It is validated, compiled into an executable graph and stepped by headless runtime nodes, which may sit on different machines and exchange typed data streams. Studio is an optional GUI for drawing diagrams, deploying them to nodes and watching them run.

Causality comes before clock time: the result of a schema is defined by its graph, not by the timing of the machines that run it. Network boundaries are explicit elements, and nodes trust each other through X.509 identities over mutual TLS.

The project is in pre-MVP development. APIs, file formats and protocols may still change without backward compatibility.

## Repository

| Directory | Content |
|---|---|
| [`doc/`](doc/README.md) | Language-neutral documentation: vision, formal model, architecture, terminology, architectural decisions, and the control and data-stream protocols that every implementation speaks |
| [`s7l2/`](s7l2/README.md) | C++26 reference implementation: core model and compiler, headless runtime `s7runtime`, transport and lossless data streams, `s7ctl` command-line tool, element plugins, and the Qt6 Studio. Builds on Linux, and cross-builds for Windows on Linux |
| [`s7py/`](s7py/README.md) | Minimal headless node in Python (standard library only): the control protocol, deployments over mTLS, and execution of a subset of the built-in elements, F64 only. It has no data streams yet |
| [`s7java/`](s7java/README.md) | Minimal data node in Java (standard library only, Java 21+): the data stream wire format and lossless delivery over mTLS, and its part of a deployed diagram, F64 only. It has no control plane yet: its part comes from a deployed diagram file |

The implementations interoperate through the protocols in `doc/`. Their conformance data lives in `s7l2/s7runtime/tests/fixtures/` (control protocol) and `s7l2/s7transport/tests/fixtures/` (wire format). For example, Studio or `s7ctl` can deploy a diagram to a Python node.

## Where to start

- What S7 is and why: [`doc/S7_VISION.md`](doc/S7_VISION.md), then [`doc/S7_Formal_Model.md`](doc/S7_Formal_Model.md).
- Build and run the C++ runtime and Studio: [`s7l2/README.md`](s7l2/README.md), with its docs index in [`s7l2/docs/INDEX.md`](s7l2/docs/INDEX.md).
- Run a Python node: [`s7py/README.md`](s7py/README.md).
- Write another implementation: [`doc/S7_Control_Protocol_MVP.md`](doc/S7_Control_Protocol_MVP.md) and [`doc/S7_Network_Wire_Protocol_v1.md`](doc/S7_Network_Wire_Protocol_v1.md).

## License

S7 is free software. Studio, `s7ctl`, the tests, tools and `s7py` are licensed under the GNU General Public License, version 3 or later ([`LICENSE`](LICENSE)). The runtime and the plugin SDK (`s7core` and the libraries `s7runtime` is built from) are licensed under the GNU Lesser General Public License, version 3 or later, so element plugins and applications that embed the runtime may use any licence. Documentation is CC-BY-4.0; example models and protocol fixtures are CC0-1.0. Diagrams and results you create with S7 are your own.

Details, including the plugin permission and third-party components: [`LICENSING.md`](LICENSING.md).

## Development with AI tools

This project was developed with the help of Claude, GitHub Copilot and Codex. The authors will continue to use AI tools to develop faster and to make the software better.

Many thanks to the companies and engineers who build these AI tools: they make development a real pleasure.

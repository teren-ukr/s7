# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""The headless node: configuration, identity, control server and the stepping loop."""
import argparse
import asyncio
import json
import os
import platform
import signal
import sys
import time
import uuid
from pathlib import Path

from . import __version__
from .clock import Clock
from .control import Authorization, ControlPlane, Descriptor
from .graph import ELEMENT_TYPES, Graph, SchemaError, schema_rate
from .runtime import Executor
from .tls import ControlPeer, certificate_node_uuid, control_peer, load_certificate_file, server_context
from .websocket import WebSocketError, accept

MAX_CONTROL_MESSAGE_BYTES = 4 * 1024 * 1024


def log(message: str) -> None:
    print(message, flush=True)


class NodeConfig:
    """The node's schema file, in the s7runtime format: websocket, control, clock, execution and a startup graph."""

    def __init__(self, document: dict):
        server = document.get("websocket", {}).get("server", {})
        tls = server.get("tls")
        self.tls = isinstance(tls, dict) and tls.get("enabled", True) is not False
        self.cert_file = tls.get("cert_file", "") if self.tls else ""
        self.key_file = tls.get("key_file", "") if self.tls else ""
        self.ca_file = tls.get("ca_file", "") if self.tls else ""
        if self.tls and not (self.cert_file and self.key_file and self.ca_file):
            raise ValueError("websocket.server.tls needs cert_file, key_file and ca_file")
        self.port = int(server.get("port", 9002))
        # Plain WebSocket is for local development: loopback only unless asked otherwise.
        self.bind_address = server.get("bind_address", "0.0.0.0" if self.tls else "127.0.0.1")

        control = document.get("control", {})
        self.authorization = Authorization(
            studio_key_purpose_oid=control.get("studio_key_purpose_oid", ""),
            studio_certificate_sha256=control.get("studio_certificate_sha256", "").replace(":", "").lower(),
        )
        self.max_configuration_bytes = int(control.get("max_configuration_bytes", 1024 * 1024))

        clock = document.get("clock", {})
        self.clock = Clock(float(clock.get("max_error_ms", 250.0)), bool(clock.get("assume_synchronized", False)))
        self.step_rate_hz = float(document.get("execution", {}).get("step_rate_hz", 0.0))
        self.node_name = document.get("node_name")
        self.startup_schema = {k: document[k] for k in ("name", "dt", "elements", "connections") if k in document}

    @classmethod
    def load(cls, path: str | None) -> "NodeConfig":
        if path is None:
            return cls({})
        with open(path, encoding="utf-8") as file:
            return cls(json.load(file))


class StateDirectory:
    """Node identity, peer cache and active deployment; locked so two nodes never share it."""

    def __init__(self, path: Path):
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self._lock = open(path / "lock", "a+")
        try:
            if sys.platform == "win32":
                import msvcrt

                msvcrt.locking(self._lock.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError(f"state directory '{path}' is in use by another node") from None

    def node_uuid(self, certificate_uuid: str | None) -> str:
        """node_uuid.txt; a certificate's UUID is authoritative and must match a stored one."""
        file = self.path / "node_uuid.txt"
        stored = file.read_text().strip().lower() if file.exists() else ""
        if stored:
            uuid.UUID(stored)
        if certificate_uuid:
            if stored and stored != certificate_uuid:
                raise RuntimeError(f"state directory '{self.path}' belongs to node {stored}, "
                                   f"but the certificate identifies node {certificate_uuid}")
            identity = certificate_uuid
        else:
            identity = stored or str(uuid.uuid4())
        if identity != stored:
            file.write_text(identity + "\n")
        return identity


def os_family() -> str:
    return {"linux": "linux", "win32": "windows", "darwin": "macos"}.get(sys.platform, sys.platform)


def architecture() -> str:
    machine = platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


class Node:
    def __init__(self, config: NodeConfig, state: StateDirectory, *, step_rate_hz: float | None = None):
        self.config = config
        certificate = load_certificate_file(config.cert_file) if config.tls else None
        node_uuid = state.node_uuid(certificate_node_uuid(certificate) if certificate else None)
        host = config.bind_address if config.bind_address not in ("0.0.0.0", "::") else "127.0.0.1"
        self.descriptor = Descriptor(
            node_uuid=node_uuid,
            node_name=config.node_name or f"node-{node_uuid[:8]}",
            instance_id=str(uuid.uuid4()),
            started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            listen_url=f"{'wss' if config.tls else 'ws'}://{host}:{config.port}",
            os_family=os_family(),
            architecture=architecture(),
            runtime_version=f"s7py-{__version__}",
            element_types=sorted(ELEMENT_TYPES),
            certificate={"common_name": certificate.common_name, "fingerprint_sha256": certificate.fingerprint_sha256}
            if certificate else {},
        )
        if certificate and not certificate.common_name:
            del self.descriptor.certificate["common_name"]
        self.executor = Executor(config.step_rate_hz if step_rate_hz is None else step_rate_hz, log=log)
        self.control = ControlPlane(
            self.descriptor, self.executor, config.clock, state_dir=state.path, authorization=config.authorization,
            max_configuration_bytes=config.max_configuration_bytes, log=log,
        )
        self.ssl = server_context(config.cert_file, config.key_file, config.ca_file) if config.tls else None

    async def _serve_connection(self, reader, writer) -> None:
        try:
            ws = await accept(reader, writer, paths=("/control", "/data"), max_message_bytes=MAX_CONTROL_MESSAGE_BYTES)
        except (WebSocketError, ConnectionError, OSError):
            writer.close()
            return
        if ws is None:
            return
        if ws.path == "/data":
            # C++ peers open their data connection along with the control one. Without
            # a data plane this node has no streams, so nothing should arrive; drop it.
            while await ws.recv() is not None:
                pass
            return
        try:
            peer = control_peer(ws.ssl_object)
        except Exception as ex:
            log(f"control.peer_certificate_unreadable {ex}")
            peer = ControlPeer(tls=True)
        # Synchronous profile: one outstanding request per connection.
        while (message := await ws.recv()) is not None:
            if isinstance(message, bytes):
                await ws.close(1003, "text messages only")
                break
            await ws.send(self.control.handle_json(peer, message))

    async def serve(self, seconds: float | None = None) -> None:
        if not self.control.restore_deployment() and self.config.startup_schema.get("elements"):
            # Seeded by its own dt, else the rate it is stepped at (s7runtime build_schema_from_definition).
            rate = schema_rate(self.config.startup_schema, self.executor.step_rate_hz)
            self.executor.run_startup(Graph(self.config.startup_schema, rate))
        server = await asyncio.start_server(self._serve_connection, self.config.bind_address, self.config.port,
                                            ssl=self.ssl, limit=MAX_CONTROL_MESSAGE_BYTES)
        d = self.descriptor
        log(f"runtime.node_uuid={d.node_uuid}")
        log(f"runtime.node_name={d.node_name}")
        log(f"runtime.listen_url={d.listen_url}/control")
        log(f"runtime.node_identity.source={'certificate' if self.ssl else 'persistent_storage'}")
        if not self.config.authorization.configured():
            log("runtime.control.authorized_studio=none (deployments are refused)")
        stepping = asyncio.create_task(self.executor.run())
        try:
            async with server:
                if seconds is None:
                    await asyncio.Event().wait()
                else:
                    await asyncio.sleep(seconds)
        finally:
            stepping.cancel()
            log(f"runtime.execution.steps={self.executor.graph.steps if self.executor.graph else 0}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="s7node", description="Minimal S7 headless node in Python.")
    parser.add_argument("--schema", help="node schema file (s7runtime format: websocket, control, clock, execution, "
                                         "and an optional startup graph)")
    parser.add_argument("--state-dir", default=str(Path.home() / ".s7py" / "default-node"),
                        help="node identity, peer cache and active deployment; each node needs its own")
    parser.add_argument("--port", type=int, help="control port (overrides websocket.server.port)")
    parser.add_argument("--seed-peer", action="append", default=[], help="peer endpoint to list in GET_PEERS")
    parser.add_argument("--step-rate", type=float, help="steps per second of graphs without dt (0: do not step)")
    parser.add_argument("--serve-seconds", type=float, help="stop after this many seconds (default: serve forever)")
    parser.add_argument("--watch", action="append", default=[], metavar="ELEMENT",
                        help="print this element's output once per second")
    args = parser.parse_args(argv)

    try:
        config = NodeConfig.load(args.schema)
        if args.port is not None:
            config.port = args.port
        node = Node(config, StateDirectory(Path(args.state_dir)), step_rate_hz=args.step_rate)
    except (OSError, ValueError, RuntimeError, SchemaError) as ex:
        print(f"error: {ex}", file=sys.stderr)
        return 1
    for endpoint in args.seed_peer:
        node.control.add_seed_peer(endpoint)
    node.executor.watch(args.watch)

    async def run():
        task = asyncio.create_task(node.serve(args.serve_seconds))
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, task.cancel)
            except (NotImplementedError, RuntimeError):  # Windows: Ctrl+C raises KeyboardInterrupt instead
                pass
        try:
            await task
        except asyncio.CancelledError:
            pass

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
    except (OSError, SchemaError) as ex:  # SchemaError: the startup graph does not build
        print(f"error: {ex}", file=sys.stderr)
        return 1
    return 0

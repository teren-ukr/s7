# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Data streams between nodes over WebSocket /data connections, as s7transport's transport.cpp
(StreamTable and BeastRuntimeNetEndpoint) carries them.

StreamTable holds every stream of the node and the blocking graph-side API: publish() waits
for room in a full send log up to max_block_ms (backpressure), receive() waits for data up to
max_wait_ms. The graph steps in a worker thread; the asyncio loop runs the connections. One
threading.Condition guards every StreamProducer / StreamConsumer, as the C++ mutex does.

DataEndpoint runs the connections. A consumer node connects to the /data endpoint of each
producer node of its streams and RESUMEs every stream it consumes from that node after each
(re)connect; the producer replays from its send log and continues. Each side announces its
node UUID in the handshake (S7-Node header). A connection's peer node is the node of its
verified certificate over TLS, otherwise the announced (or, for a data peer, configured) node.
"""
import asyncio
import threading
import time
from collections import deque
from dataclasses import dataclass, field

from . import stream, wire
from .tls import certificate_node_uuid, control_peer
from .websocket import WebSocketError, connect

MAX_RECENT_FAULTS = 16
MAX_QUEUED_WRITES = 64  # per connection, before the producer waits for write completions
TICK_SECONDS = 0.001
RECONNECT_SECONDS = 1.0
NODE_HEADER = "S7-Node"  # the sender's node UUID, in both handshake directions
MAX_DATA_MESSAGE_BYTES = wire.MAX_PAYLOAD_BYTES + 4096

PRODUCER, CONSUMER = "producer", "consumer"


def _certificate_node(certificate) -> str:
    """The node UUID of a certificate's spiffe://s7/node/<uuid> SAN, or "" (an unidentified peer)."""
    try:
        return certificate_node_uuid(certificate) if certificate else ""
    except ValueError:
        return ""


def _utc_text(ns: int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ns // 1_000_000_000)) + f".{ns // 1_000_000 % 1000:03d}Z"


@dataclass
class StreamEntry:
    handle: int
    role: str
    config: stream.StreamConfig
    producer: stream.StreamProducer | None = None
    consumer: stream.StreamConsumer | None = None
    open: bool = True  # owned by an element; a closed stream keeps its state
    unauthorized: int = 0
    recent_faults: deque = field(default_factory=lambda: deque(maxlen=MAX_RECENT_FAULTS))
    noted: str | None = None  # the stream fault already in recent_faults
    late_noted_ns: int = 0  # LATE goes to recent_faults at most once a second

    def fault_code(self) -> str | None:
        return (self.producer or self.consumer).fault_code

    def note(self, code: str, detail: str = "") -> None:
        self.recent_faults.append({"code": code, "detail": detail, "at": _utc_text(time.time_ns())})

    def note_fault(self) -> None:
        """Records the stream's fault once, when it is first seen."""
        code = self.fault_code()
        if code is not None and code != self.noted:
            self.note(code)
        self.noted = code

    def note_late(self) -> None:
        now = time.monotonic_ns()
        if now - self.late_noted_ns < 1_000_000_000:
            return
        self.late_noted_ns = now
        self.note(stream.LATE, f"latency_ms={self.consumer.latency.last_ns // 1_000_000} "
                               f"max_latency_ms={self.config.max_latency_ms or 0}")


class StreamTable:
    def __init__(self, sequences):
        self.sequences = sequences
        self.changed = threading.Condition()
        self.entries: dict[int, StreamEntry] = {}
        self.producers: dict[bytes, int] = {}
        self.consumers: dict[bytes, int] = {}
        self.next_handle = 1
        self.clock_usable = True
        # Called with the lock held after producer data or consumer streams changed, so the
        # transport can send; they only schedule work and never block.
        self.on_producer_data = lambda entry: None
        self.on_consumer_opened = lambda entry: None

    def open(self, config: stream.StreamConfig, role: str) -> int:
        """Reopening a closed stream of the same type continues it (a redeployed graph takes over
        the stream without loss); another type starts anew."""
        with self.changed:
            index = self.producers if role == PRODUCER else self.consumers
            handle = index.get(config.stream_id)
            if handle is not None:
                existing = self.entries[handle]
                if existing.open:
                    raise ValueError(f"Stream {wire.stream_id_text(config.stream_id)} is already open as {role}.")
                if existing.config.type == config.type:
                    existing.open = True
                    for name in ("max_block_ms", "max_wait_ms", "producer_node", "consumer_nodes", "max_latency_ms"):
                        setattr(existing.config, name, getattr(config, name))
                    self.changed.notify_all()
                    return handle
                del self.entries[handle]
                del index[config.stream_id]
            handle = self.next_handle
            self.next_handle += 1
            entry = StreamEntry(handle, role, config)
            if role == PRODUCER:
                entry.producer = stream.StreamProducer(config, self.sequences)
                entry.producer.stamp_send_time = self.clock_usable
            else:
                entry.consumer = stream.StreamConsumer(config, handle)  # the alias is the handle
            self.entries[handle] = entry
            index[config.stream_id] = handle
            if role == CONSUMER:
                self.on_consumer_opened(entry)
            else:
                self.on_producer_data(entry)  # apply RESUMEs that arrived before the producer opened
            return handle

    def close(self, handle: int) -> None:
        with self.changed:
            if handle in self.entries:
                self.entries[handle].open = False
                self.changed.notify_all()

    def publish(self, handle: int, elements: list, times=()) -> str | None:
        """Returns the stream's fault, if any: a faulted stream drops data and the graph continues
        only to raise it. Blocks on a full send log up to max_block_ms (then SEND_LOG_OVERFLOW)."""
        with self.changed:
            entry = self._require(handle, PRODUCER)
            producer = entry.producer
            done = 0
            deadline = None
            while done < len(elements):
                if producer.fault_code is not None:
                    return producer.fault_code
                now = time.monotonic_ns()
                done += producer.append(elements[done:], now, times)
                self.on_producer_data(entry)
                if done == len(elements):
                    break
                if deadline is None:
                    deadline = now + entry.config.max_block_ms * stream.MS
                wait_start = time.monotonic_ns()
                room = self.changed.wait_for(
                    lambda: handle not in self.entries or not producer.log_full() or producer.fault_code is not None,
                    max(0.0, (deadline - time.monotonic_ns()) / 1e9))
                if handle not in self.entries:
                    return None
                producer.blocked_total_ms += (time.monotonic_ns() - wait_start) // stream.MS
                if not room:
                    producer.fault(stream.SEND_LOG_OVERFLOW)
                    return stream.SEND_LOG_OVERFLOW
            return None

    def receive(self, handle: int, count: int):
        """(elements, fault, times of the first element). Waits for data up to max_wait_ms (then UNDERRUN)."""
        with self.changed:
            entry = self._require(handle, CONSUMER)
            consumer = entry.consumer
            taken: list = []
            first_times: list = []
            deadline = time.monotonic_ns() + entry.config.max_wait_ms * stream.MS
            while True:
                taken += consumer.take(count - len(taken), first_times if not taken else None)
                if len(taken) == count or consumer.fault_code is not None:
                    break
                data = self.changed.wait_for(
                    lambda: handle not in self.entries or consumer.available() > 0 or consumer.fault_code is not None,
                    max(0.0, (deadline - time.monotonic_ns()) / 1e9))
                if handle not in self.entries:
                    return taken, None, first_times
                if not data:
                    consumer.fault(stream.UNDERRUN)
                    break
            return taken, consumer.fault_code, first_times

    def statuses(self) -> list[dict]:
        """GET_STREAM_STATUS entries, in the C++ control plane's form."""
        with self.changed:
            result = []
            for entry in self.entries.values():
                entry.note_fault()
                status = {"stream_id": wire.stream_id_text(entry.config.stream_id), "role": entry.role,
                          "data_type": entry.config.type.name}
                latency = {"samples": 0, "min_ns": 0, "mean_ns": 0, "p50_ns": 0, "p99_ns": 0, "max_ns": 0, "last_ns": 0, "late": 0}
                counters = {"next_sequence": 0, "packets": 0, "elements": 0, "replayed": 0, "lost_resumes": 0,
                            "duplicates_discarded": 0, "malformed": 0, "unauthorized": entry.unauthorized,
                            "send_log_depth": 0, "buffered_elements": 0, "blocked_ms_total": 0}
                if entry.producer:
                    p = entry.producer
                    s = p.stats()
                    fault = p.fault_code
                    state = "faulted" if fault else "closed" if not entry.open else "blocked" if p.log_full() else "active"
                    counters.update(next_sequence=p.next_sequence, packets=s["packets"], elements=s["elements"],
                                    replayed=s["replayed"], lost_resumes=s["lost_resumes"],
                                    send_log_depth=s["send_log_depth"], blocked_ms_total=s["blocked_ms_total"])
                else:
                    c = entry.consumer
                    s = c.stats()
                    fault = c.fault_code
                    state = "faulted" if fault else "active" if entry.open else "closed"
                    counters.update(next_sequence=s["next_expected"], packets=s["packets"], elements=s["elements"],
                                    duplicates_discarded=s["duplicates_discarded"], malformed=s["malformed"],
                                    buffered_elements=s["buffered_elements"])
                    stats = c.latency.stats()
                    latency = {"samples": stats["samples"], "min_ns": stats["min"], "mean_ns": stats["mean"],
                               "p50_ns": stats["p50"], "p99_ns": stats["p99"], "max_ns": stats["max"],
                               "last_ns": stats["last"], "late": stats["late"]}
                status.update(state=state, fault=fault or "NONE", **counters, recent_faults=list(entry.recent_faults),
                              latency=latency)
                result.append(status)
            return result

    def recover(self, stream_id: bytes) -> bool:
        with self.changed:
            found = False
            for index in (self.producers, self.consumers):
                handle = index.get(stream_id)
                if handle is not None:
                    entry = self.entries[handle]
                    entry.note_fault()
                    (entry.producer or entry.consumer).recover()
                    if entry.producer:
                        self.on_producer_data(entry)
                    found = True
            self.changed.notify_all()
            return found

    def set_clock_usable(self, usable: bool) -> None:
        with self.changed:
            self.clock_usable = usable
            for entry in self.entries.values():
                if entry.producer:
                    entry.producer.stamp_send_time = usable

    def note_all(self, code: str, detail: str) -> None:
        with self.changed:
            for entry in self.entries.values():
                entry.note(code, detail)

    def _require(self, handle: int, role: str) -> StreamEntry:
        entry = self.entries.get(handle)
        if entry is None or entry.role != role:
            raise ValueError(f"Not an open {role} stream.")
        return entry

    # Lock held by the caller.
    def find_producer(self, stream_id: bytes) -> StreamEntry | None:
        handle = self.producers.get(stream_id)
        return None if handle is None else self.entries[handle]

    def find_consumer_by_alias(self, alias: int) -> StreamEntry | None:
        entry = self.entries.get(alias)
        return entry if entry is not None and entry.role == CONSUMER else None


@dataclass
class DataPeer:
    """A producer node a consumer connects to: its /data endpoint and identity."""
    url: str
    node_uuid: str
    trusted_plaintext: bool = False


@dataclass
class Link:
    key: str
    peer: DataPeer
    ssl: object  # an ssl.SSLContext for wss://, or None
    reconnect_scheduled: bool = False


class Connection:
    """A /data WebSocket connection, used on the asyncio loop only."""

    def __init__(self, ws, *, outbound: bool, link: Link | None = None):
        self.ws = ws
        self.outbound = outbound
        self.link = link
        self.peer_node = ""
        self.consumer_key = "anonymous"
        # Consumer side: aliases of the local consumer streams RESUMEd here; packets for any
        # other alias are refused.
        self.resumed: set[int] = set()
        # Producer side: streams this peer consumes, alias (theirs) -> local handle, and back.
        self.producing: dict[int, int] = {}
        self.producing_alias: dict[int, int] = {}
        self.pending_resumes: dict[bytes, wire.ControlMessage] = {}  # for streams not (yet) produced here
        self.writes: asyncio.Queue = asyncio.Queue()
        self.closed = False


def _parse_ws_url(url: str) -> tuple[bool, str, int, str]:
    """(secure, host, port, path) of a ws:// or wss:// URL; IPv6 hosts bracketed."""
    if url.startswith("wss://"):
        secure, rest = True, url[6:]
    elif url.startswith("ws://"):
        secure, rest = False, url[5:]
    else:
        raise ValueError(f"Expected a ws:// or wss:// URL: '{url}'.")
    host_port, slash, path = rest.partition("/")
    path = "/" + path if slash else "/"
    if host_port.startswith("["):
        host, _, port = host_port[1:].partition("]:")
    else:
        if host_port.count(":") > 1:
            raise ValueError(f"IPv6 WebSocket addresses must be bracketed: '{url}'.")
        host, _, port = host_port.partition(":")
    if not host or not port.isdigit():
        raise ValueError(f"Expected host:port in '{url}'.")
    return secure, host, int(port), path


def data_path(path: str) -> str:
    """The /data target next to a URL's path: ws://host:port[/prefix]/control or /data -> [/prefix]/data."""
    for suffix in ("/control", "/data"):
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    return path.rstrip("/") + "/data"


class DataEndpoint:
    def __init__(self, table: StreamTable, node_uuid: str, *, client_ssl=None, tls_enabled: bool = False, log=print):
        self.table = table
        self.node_uuid = node_uuid
        self.client_ssl = client_ssl  # factory: () -> ssl.SSLContext with this node's certificate (mTLS)
        self.tls_enabled = tls_enabled
        self.log = log
        self.loop: asyncio.AbstractEventLoop | None = None
        self.connections: set[Connection] = set()
        self.links: dict[str, Link] = {}
        self.consumer_sources: dict[int, Connection] = {}  # consumer handle -> its data source
        self.routes: dict[tuple[int, str], Connection] = {}  # (producer handle, consumer key) -> connection
        self.errors: deque = deque(maxlen=32)
        self.messages_sent = self.messages_received = self.malformed_messages = 0
        self._pump_scheduled = False
        table.on_producer_data = self._schedule_pump
        table.on_consumer_opened = self._consumer_opened

    def start(self) -> asyncio.Task:
        self.loop = asyncio.get_running_loop()
        return asyncio.create_task(self._ticks())

    def record_error(self, error: str) -> None:
        self.errors.append(error)
        self.log(f"runtime.transport.error={error}")

    # ---- callbacks from the stream table (any thread, lock held) -------------------------

    def _schedule_pump(self, entry=None) -> None:
        if self.loop is None or self._pump_scheduled:
            return
        self._pump_scheduled = True
        self.loop.call_soon_threadsafe(self._pump_all)

    def _consumer_opened(self, entry: StreamEntry) -> None:
        if self.loop is None:
            return
        resume = entry.consumer.resume_message()
        producer_node = entry.config.producer_node

        def send_resumes():
            for connection in list(self.connections):
                if not connection.closed and self._may_produce(connection, producer_node):
                    connection.resumed.add(resume.stream_alias)
                    self._send(connection, wire.encode_control_message(resume))
        self.loop.call_soon_threadsafe(send_resumes)

    # ---- connections (loop) --------------------------------------------------------------

    @staticmethod
    def _may_produce(connection: Connection, producer_node: str) -> bool:
        return not producer_node or connection.peer_node == producer_node

    @staticmethod
    def _may_consume(connection: Connection, config: stream.StreamConfig) -> bool:
        return not config.consumer_nodes or connection.peer_node in config.consumer_nodes

    @staticmethod
    def _describe(connection: Connection) -> str:
        return f"node {connection.peer_node}" if connection.peer_node else "an unidentified peer"

    async def serve_inbound(self, ws, claimed_node: str) -> None:
        """An accepted /data connection (the node's listener hands it over after the handshake)."""
        connection = Connection(ws, outbound=False)
        await self._run(connection, claimed_node)

    async def _run(self, connection: Connection, claimed_node: str) -> None:
        peer = control_peer(connection.ws.ssl_object) if connection.ws.ssl_object else None
        certificate = peer.certificate if peer else None
        if connection.ws.ssl_object is not None:
            connection.peer_node = _certificate_node(certificate)
        else:
            connection.peer_node = claimed_node or (connection.link.peer.node_uuid if connection.link else "")
        if certificate:
            connection.consumer_key = certificate.fingerprint_sha256
        elif connection.peer_node:
            connection.consumer_key = "node:" + connection.peer_node
        self.connections.add(connection)
        writer = asyncio.create_task(self._writer(connection))
        self._on_data_connection(connection)
        try:
            while (message := await connection.ws.recv()) is not None:
                self.messages_received += 1
                if isinstance(message, str):
                    continue  # the data channel carries binary messages only
                self._on_message(connection, message)
                if connection.closed:
                    break
        finally:
            self._close(connection)
            writer.cancel()

    def _on_data_connection(self, connection: Connection) -> None:
        """Resume every local consumer stream on a new data connection."""
        resumes = []
        with self.table.changed:
            for entry in self.table.entries.values():
                if entry.consumer and self._may_produce(connection, entry.config.producer_node):
                    resume = entry.consumer.resume_message()
                    connection.resumed.add(resume.stream_alias)
                    resumes.append(wire.encode_control_message(resume))
        for message in resumes:
            self._send(connection, message)

    def _send(self, connection: Connection, message: bytes) -> None:
        if not connection.closed:
            connection.writes.put_nowait(message)

    async def _writer(self, connection: Connection) -> None:
        try:
            while True:
                message = await connection.writes.get()
                await connection.ws.send(message)
                self.messages_sent += 1
                if connection.writes.qsize() < MAX_QUEUED_WRITES // 2:
                    self._pump_connection(connection)
        except (ConnectionError, OSError, WebSocketError):
            self._close(connection)

    def _close(self, connection: Connection) -> None:
        if connection.closed:
            return
        connection.closed = True
        connection.ws.writer.close()
        with self.table.changed:
            for handle in connection.producing_alias:
                key = (handle, connection.consumer_key)
                if self.routes.get(key) is connection:
                    del self.routes[key]
                    entry = self.table.entries.get(handle)
                    if entry and entry.producer:
                        entry.producer.detach(connection.consumer_key)
        self.connections.discard(connection)
        # A dropped connection to a current data peer reconnects.
        if connection.outbound and connection.link:
            self._schedule_reconnect(connection.link)

    def _on_message(self, connection: Connection, message: bytes) -> None:
        try:
            if wire.is_control_message(message):
                self._on_stream_control(connection, wire.decode_control_message(message))
            else:
                self._on_data_packet(connection, wire.decode_data_packet(message))
        except wire.FormatError as error:
            self.malformed_messages += 1
            self.record_error(f"malformed message from peer: {error}")
            self._close(connection)  # the peer reconnects and resumes

    def _on_stream_control(self, connection: Connection, message: wire.ControlMessage) -> None:
        with self.table.changed:
            if message.kind == wire.ACK:
                handle = connection.producing.get(message.stream_alias)
                entry = self.table.entries.get(handle) if handle is not None else None
                if entry and entry.producer:
                    entry.producer.acknowledge(connection.consumer_key, message.next_expected)
                    self.table.changed.notify_all()
            else:
                next_expected = 0 if message.kind == wire.RESUME_NO_STATE else message.next_expected
                entry = self.table.find_producer(message.stream_id)
                if entry is None:
                    # Not produced here (yet): remember it in case the producer opens later.
                    connection.pending_resumes[message.stream_id] = wire.ControlMessage(
                        message.kind, message.stream_alias, next_expected, message.stream_id)
                    return
                if not self._attach(connection, entry, message.stream_alias, next_expected):
                    return
        self._pump_connection(connection)

    def _attach(self, connection: Connection, entry: StreamEntry, alias: int, next_expected: int) -> bool:
        """Lock held. The latest RESUME wins: a consumer receives a stream through one connection,
        so packets are never sent on two at once. A peer that is not a configured consumer is refused."""
        if not self._may_consume(connection, entry.config):
            entry.unauthorized += 1
            entry.note(stream.UNAUTHORIZED_CONSUMER, self._describe(connection))
            self.record_error(f"refused RESUME of stream {wire.stream_id_text(entry.config.stream_id)} from "
                              f"{self._describe(connection)}: not a configured consumer")
            return False
        key = (entry.handle, connection.consumer_key)
        previous = self.routes.get(key)
        if previous is not None and previous is not connection:
            alias_there = previous.producing_alias.pop(entry.handle, None)
            if alias_there is not None:
                previous.producing.pop(alias_there, None)
        self.routes[key] = connection
        entry.producer.resume(connection.consumer_key, alias, next_expected)
        connection.producing[alias] = entry.handle
        connection.producing_alias[entry.handle] = alias
        self.table.changed.notify_all()
        return True

    def _on_data_packet(self, connection: Connection, packet: wire.DataPacket) -> None:
        with self.table.changed:
            entry = self.table.find_consumer_by_alias(packet.stream_alias)
            if entry is None:
                return  # a stream closed meanwhile
            if packet.stream_alias not in connection.resumed:
                # Not RESUMEd here: this peer is not the stream's producer.
                entry.unauthorized += 1
                entry.note(stream.UNAUTHORIZED_PRODUCER, self._describe(connection))
                refused = wire.stream_id_text(entry.config.stream_id)
            else:
                refused = None
                if entry.consumer.on_packet(packet, time.monotonic_ns()):
                    entry.note_late()
                self.consumer_sources[entry.handle] = connection
                self.table.changed.notify_all()
        if refused:
            self.record_error(f"refused packets of stream {refused} from {self._describe(connection)}: "
                              "not the configured producer")
            self._close(connection)

    def _pump_all(self) -> None:
        self._pump_scheduled = False
        for connection in list(self.connections):
            if not connection.closed:
                self._apply_pending_resumes(connection)
                self._pump_connection(connection)

    def _apply_pending_resumes(self, connection: Connection) -> None:
        if not connection.pending_resumes:
            return
        with self.table.changed:
            for stream_id in list(connection.pending_resumes):
                entry = self.table.find_producer(stream_id)
                if entry is not None:
                    message = connection.pending_resumes.pop(stream_id)
                    self._attach(connection, entry, message.stream_alias, message.next_expected)

    def _pump_connection(self, connection: Connection) -> None:
        """Sends the producer streams' next packets, bounded by the write queue (the rest follows
        as writes complete)."""
        if connection.closed:
            return
        with self.table.changed:
            progress = True
            while progress and connection.writes.qsize() < MAX_QUEUED_WRITES:
                progress = False
                for handle in list(connection.producing_alias):
                    entry = self.table.entries.get(handle)
                    if entry is None:
                        continue
                    message = entry.producer.next_message(connection.consumer_key)
                    if message is not None:
                        self._send(connection, message)
                        progress = True

    async def _ticks(self) -> None:
        """Every millisecond: flush due batches and send due acknowledgements."""
        while True:
            await asyncio.sleep(TICK_SECONDS)
            now = time.monotonic_ns()
            flushed = False
            acks = []
            with self.table.changed:
                for entry in self.table.entries.values():
                    if entry.producer:
                        flushed |= entry.producer.flush(now)
                    else:
                        ack = entry.consumer.ack_due(now)
                        source = self.consumer_sources.get(entry.handle)
                        if ack is not None and source is not None:
                            acks.append((source, wire.encode_control_message(ack)))
                if flushed:
                    self.table.changed.notify_all()
            for connection, message in acks:
                self._send(connection, message)
            if flushed:
                for connection in list(self.connections):
                    self._pump_connection(connection)

    # ---- data peers (consumer side) --------------------------------------------------------

    def check_peers(self, peers: list[DataPeer]) -> None:
        """PREPARE (runtime_service.cpp stage): this node has no trusted_plaintext data listener, and
        with TLS credentials a plaintext endpoint needs that explicit policy."""
        for peer in peers:
            if peer.trusted_plaintext:
                raise ValueError("This node has not enabled trusted_plaintext data transport.")
            if self.tls_enabled and not _parse_ws_url(peer.url)[0]:
                raise ValueError("Plaintext data endpoints require explicit trusted_plaintext policy.")

    def set_data_peers(self, peers: list[DataPeer]) -> None:
        """Connects to every producer node of this node's consumer streams; drops links no longer wanted."""
        wanted = {}
        for peer in peers:
            secure, _, _, _ = _parse_ws_url(peer.url)
            if peer.trusted_plaintext and secure:
                raise ValueError("trusted_plaintext data requires a ws:// endpoint.")
            if not peer.trusted_plaintext and self.tls_enabled and not secure:
                raise ValueError("Plaintext data with TLS node credentials requires explicit trusted_plaintext permission.")
            context = self.client_ssl() if secure and self.client_ssl else None
            if secure and context is None:
                raise ValueError(f"data peer {peer.url} needs TLS, but this node has no TLS credentials")
            wanted[f"data:{peer.url}#{peer.node_uuid}"] = Link(f"data:{peer.url}#{peer.node_uuid}", peer, context)
        for key in [k for k in self.links if k not in wanted]:
            link = self.links.pop(key)
            for connection in list(self.connections):
                if connection.link is link:
                    self._close(connection)
        for key, link in wanted.items():
            if key not in self.links:
                self.links[key] = link
                asyncio.ensure_future(self._connect(link), loop=self.loop)

    def _schedule_reconnect(self, link: Link) -> None:
        if link.reconnect_scheduled or self.links.get(link.key) is not link:
            return
        link.reconnect_scheduled = True
        self.loop.call_later(RECONNECT_SECONDS, self._reconnect, link)

    def _reconnect(self, link: Link) -> None:
        link.reconnect_scheduled = False
        if self.links.get(link.key) is link:
            asyncio.ensure_future(self._connect(link), loop=self.loop)

    async def _connect(self, link: Link) -> None:
        secure, host, port, path = _parse_ws_url(link.peer.url)
        try:
            ws = await asyncio.wait_for(connect(host, port, data_path(path), ssl=link.ssl,
                                                max_message_bytes=MAX_DATA_MESSAGE_BYTES,
                                                headers={NODE_HEADER: self.node_uuid}), 10)
        except (OSError, WebSocketError, asyncio.TimeoutError) as error:
            self._schedule_reconnect(link)
            self.log(f"runtime.transport.connect_failed url={link.peer.url} error={error}")
            return
        if self.links.get(link.key) is not link:
            ws.writer.close()
            return
        claimed = ws.headers.get(NODE_HEADER.lower(), "")
        expected = link.peer.node_uuid
        if ws.ssl_object is not None:
            certificate = control_peer(ws.ssl_object).certificate
            if expected and _certificate_node(certificate) != expected:
                self.record_error(f"data peer {host}:{port} is not node {expected} (certificate identity mismatch)")
                ws.writer.close()
                self._schedule_reconnect(link)
                return
        elif expected and claimed and claimed != expected:
            self.record_error(f"data peer {host}:{port} is node {claimed}, not node {expected} (identity mismatch)")
            ws.writer.close()
            self._schedule_reconnect(link)
            return
        await self._run(Connection(ws, outbound=True, link=link), claimed)

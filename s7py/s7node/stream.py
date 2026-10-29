# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Data streams between nodes (doc/S7_Network_Wire_Protocol_v1.md, section 12.1).

The stream descriptor of a deployed diagram, read as s7net's diagram_deployment.cpp
parse_streams() reads it, and lossless delivery as s7transport's stream_protocol.cpp
implements it, independent of any socket: the transport feeds StreamProducer and
StreamConsumer messages and time (monotonic nanoseconds) and sends what they return.

Producer: packs elements into packets (batching), numbers them, keeps them in a bounded
send log until every attached consumer acknowledged them, and replays from a consumer's
RESUME position. A full log is backpressure.
Consumer: delivers each sequence exactly once and in order, discards duplicates, faults
on a gap, and acknowledges what its graph consumed.

Elements are tuples of component bits, as in wire.
"""
import math
import os
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

from . import wire
from .clock import utc_now_ns

UINT32_MAX = 2**32 - 1


@dataclass(frozen=True)
class StreamEnd:
    node_uuid: str
    element: str
    port: int


@dataclass
class StreamDescriptor:
    stream_id: bytes
    producer: StreamEnd
    consumers: list[StreamEnd]
    data_type: wire.WireType
    timestamps: list[tuple[int, str]]  # (role, clock domain), ascending role
    max_elements_per_packet: int = 1024
    max_batch_latency_ms: int = 10
    send_log_max_packets: int = 4096
    max_block_ms: int = 2000
    max_wait_ms: int = 2000
    sample_rate: tuple[int, int] | None = None  # (numerator, denominator): uniformly sampled
    max_latency_ms: int | None = None

    @classmethod
    def from_json(cls, entry) -> "StreamDescriptor":
        if not isinstance(entry, dict):
            raise ValueError("streams: an entry must be an object.")
        stream_id = wire.parse_stream_id(_string(entry, "stream_id", "stream"))
        what = f"stream {wire.stream_id_text(stream_id)}"
        producer = _end(entry.get("producer"), f"{what} producer")
        consumers = entry.get("consumers")
        if not isinstance(consumers, list) or not consumers:
            raise ValueError(f"{what}: 'consumers' must be a non-empty array.")
        consumers = [_end(c, f"{what} consumer") for c in consumers]
        try:
            data_type = wire.wire_type(_string(entry, "data_type", what))
        except ValueError as error:
            raise ValueError(f"{what}: {error}") from None
        d = cls(stream_id, producer, consumers, data_type, [])
        d.max_elements_per_packet = _u32(entry, "max_elements_per_packet", d.max_elements_per_packet)
        d.max_batch_latency_ms = _u32(entry, "max_batch_latency_ms", d.max_batch_latency_ms)
        if "send_log" in entry:
            log = entry["send_log"]
            if not isinstance(log, dict):
                raise ValueError(f"{what}: 'send_log' must be an object.")
            d.send_log_max_packets = _u32(log, "max_packets", d.send_log_max_packets)
            d.max_block_ms = _u32(log, "max_block_ms", d.max_block_ms)
        d.max_wait_ms = _u32(entry, "max_wait_ms", d.max_wait_ms)
        if "max_latency_ms" in entry:
            d.max_latency_ms = _u32(entry, "max_latency_ms", 0)
        if "sample_rate" in entry:
            rate = entry["sample_rate"]
            if not isinstance(rate, dict):
                raise ValueError(f"{what}: 'sample_rate' must be an object.")
            d.sample_rate = (_index(rate, "numerator", f"{what} sample_rate"), _index(rate, "denominator", f"{what} sample_rate"))
            if 0 in d.sample_rate:
                raise ValueError(f"{what}: 'sample_rate' must be positive.")
        timestamps = entry.get("timestamps")
        if not isinstance(timestamps, list) or not timestamps:
            raise ValueError(f"{what}: 'timestamps' must declare at least one timestamp role.")
        for declaration in timestamps:
            if not isinstance(declaration, dict):
                raise ValueError(f"{what}: a timestamp declaration must be an object.")
            name = _string(declaration, "role", what)
            if name not in wire.ROLES:
                raise ValueError(f"Unknown timestamp role '{name}' (MODEL_TIME, SOURCE_TIME or PROCESSING_TIME).")
            d.timestamps.append((wire.ROLES[name], _string(declaration, "clock_domain", what)))
        roles = [role for role, _ in d.timestamps]
        if roles != sorted(set(roles)):
            raise ValueError(f"{what}: timestamp roles must be distinct and in ascending role order.")
        return d

    def to_json(self) -> dict:
        """Every member at its value or default, in the order diagram_deployment.cpp writes them."""
        out = {
            "stream_id": wire.stream_id_text(self.stream_id),
            "producer": _end_json(self.producer),
            "consumers": [_end_json(c) for c in self.consumers],
            "data_type": self.data_type.name,
            "max_elements_per_packet": self.max_elements_per_packet,
            "max_batch_latency_ms": self.max_batch_latency_ms,
            "send_log": {"max_packets": self.send_log_max_packets, "max_block_ms": self.max_block_ms},
            "max_wait_ms": self.max_wait_ms,
        }
        if self.sample_rate:
            out["sample_rate"] = {"numerator": self.sample_rate[0], "denominator": self.sample_rate[1]}
        out["timestamps"] = [{"role": wire.ROLE_NAMES[role], "clock_domain": domain} for role, domain in self.timestamps]
        if self.max_latency_ms is not None:
            out["max_latency_ms"] = self.max_latency_ms
        return out


def _is_integer(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _string(entry: dict, key: str, what: str) -> str:
    value = entry.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{what}: '{key}' must be a string.")
    return value


def _index(entry: dict, key: str, what: str) -> int:
    value = entry.get(key)
    if not _is_integer(value) or value < 0:
        raise ValueError(f"{what}: '{key}' must be a non-negative integer.")
    return value


def _u32(entry: dict, key: str, fallback: int) -> int:
    if key not in entry:
        return fallback
    value = entry[key]
    if not _is_integer(value) or value <= 0:
        raise ValueError(f"stream: '{key}' must be a positive integer.")
    return min(value, UINT32_MAX)


def _end(value, what: str) -> StreamEnd:
    if not isinstance(value, dict):
        raise ValueError(f"{what} must be an object.")
    return StreamEnd(_string(value, "node_uuid", what), _string(value, "element", what), _index(value, "port", what))


def _end_json(end: StreamEnd) -> dict:
    return {"node_uuid": end.node_uuid, "element": end.element, "port": end.port}


# ---- delivery (stream_protocol.cpp) --------------------------------------------------

SEQUENCE_GAP = "SEQUENCE_GAP"  # packets are missing (e.g. producer restart)
SEND_LOG_OVERFLOW = "SEND_LOG_OVERFLOW"  # backpressure lasted longer than max_block_ms
STREAM_STATE_LOST = "STREAM_STATE_LOST"  # a consumer cannot be resumed from the send log
MALFORMED_PACKET = "MALFORMED_PACKET"
TYPE_MISMATCH = "TYPE_MISMATCH"  # packet type differs from the stream's type
UNDERRUN = "UNDERRUN"  # the consumer waited longer than max_wait_ms for data
# Refused peers: reported in a stream's recent faults; they do not stop the stream.
TIMESTAMP_PROFILE_MISMATCH = "TIMESTAMP_PROFILE_MISMATCH"
UNAUTHORIZED_PRODUCER = "UNAUTHORIZED_PRODUCER"
UNAUTHORIZED_CONSUMER = "UNAUTHORIZED_CONSUMER"
CLOCK_UNSYNCHRONIZED = "CLOCK_UNSYNCHRONIZED"
LATE = "LATE"

SEQUENCE_RESERVATION = 65536
ACK_EVERY_PACKETS = 64
ACK_INTERVAL_NS = 50_000_000
MS = 1_000_000  # nanoseconds


def element_time_ns(rate: tuple[int, int], index: int) -> int:
    """Time of element `index` of a uniformly sampled stream from 0 ns: index / rate, rounded toward zero."""
    return min(index * 1_000_000_000 * rate[1] // rate[0], 2**63 - 1)


@dataclass
class StreamConfig:
    stream_id: bytes
    type: wire.WireType
    max_elements_per_packet: int = 1024
    max_batch_latency_ms: int = 10
    send_log_max_packets: int = 4096
    max_block_ms: int = 2000
    max_wait_ms: int = 2000  # consumer side: how long a step may wait for data
    # The nodes allowed at the other end (node UUIDs; empty: not checked).
    producer_node: str = ""
    consumer_nodes: list[str] = field(default_factory=list)
    # With a sample_rate the stream is uniformly sampled: packets carry no timestamps and the
    # element with index n has time n / sample_rate in each declared role. Without one, every
    # packet carries exactly the declared roles (ascending) for its single element.
    sample_rate: tuple[int, int] | None = None
    timestamp_roles: list[int] = field(default_factory=list)
    max_latency_ms: int | None = None  # consumer: packets later than this are counted late

    @property
    def explicit_timestamps(self) -> bool:
        return self.sample_rate is None and bool(self.timestamp_roles)

    @classmethod
    def from_descriptor(cls, d: StreamDescriptor) -> "StreamConfig":
        return cls(d.stream_id, d.data_type, d.max_elements_per_packet, d.max_batch_latency_ms, d.send_log_max_packets,
                   d.max_block_ms, d.max_wait_ms, d.producer.node_uuid, [c.node_uuid for c in d.consumers],
                   d.sample_rate, [role for role, _ in d.timestamps], d.max_latency_ms)


class LatencyHistogram:
    """End-to-end latency, SEND_TIME to arrival over synchronized UTC clocks. Percentiles come
    from a log2 histogram of microseconds, so they are upper bounds within a factor of two."""

    BUCKETS = 40  # bucket k: latencies below 2^k microseconds

    def __init__(self):
        self.counts = [0] * self.BUCKETS
        self.samples = self.sum_ns = self.min_ns = self.max_ns = self.last_ns = self.late = 0

    def add(self, latency_ns: int, limit_ms: int | None) -> bool:
        micros = 0 if latency_ns <= 0 else latency_ns // 1000
        self.counts[min(micros.bit_length(), self.BUCKETS - 1)] += 1
        self.min_ns = latency_ns if self.samples == 0 else min(self.min_ns, latency_ns)
        self.max_ns = latency_ns if self.samples == 0 else max(self.max_ns, latency_ns)
        self.last_ns = latency_ns
        self.sum_ns += latency_ns
        self.samples += 1
        late = limit_ms is not None and latency_ns > limit_ms * MS
        self.late += late
        return late

    def stats(self) -> dict:
        def percentile(q: float) -> int:
            rank = math.ceil(q * self.samples)
            seen = 0
            for bucket, count in enumerate(self.counts):
                seen += count
                if seen >= rank and seen > 0:
                    return min(self.max_ns, (1 << bucket) * 1000)
            return self.max_ns

        mean = 0
        if self.samples:  # truncated toward zero, as the C++ int128 division
            mean = abs(self.sum_ns) // self.samples * (1 if self.sum_ns >= 0 else -1)
        return {"samples": self.samples, "min": self.min_ns, "mean": mean,
                "p50": percentile(0.50) if self.samples else 0, "p99": percentile(0.99) if self.samples else 0,
                "max": self.max_ns, "last": self.last_ns, "late": self.late}


class MemorySequenceStore:
    def __init__(self):
        self.ends: dict[bytes, int] = {}

    def reserved_end(self, stream_id: bytes) -> int:
        return self.ends.get(stream_id, 0)

    def reserve(self, stream_id: bytes, end: int) -> None:
        self.ends[stream_id] = end


class FileSequenceStore:
    """Durable sequence-range reservations (wire draft section 4), in the format of the C++ node:
    <directory>/<stream_id>.seq holding the reservation end in decimal and a newline, written to a
    temporary file, fsync'ed and renamed (platform.cpp write_file_atomically)."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, stream_id: bytes) -> Path:
        return self.directory / f"{wire.stream_id_text(stream_id)}.seq"

    def reserved_end(self, stream_id: bytes) -> int:
        path = self._path(stream_id)
        if not path.exists():
            return 0
        text = path.read_text().strip()
        if not text.isdigit():
            raise RuntimeError(f"Corrupt sequence reservation for stream {wire.stream_id_text(stream_id)}.")
        return int(text)

    def reserve(self, stream_id: bytes, end: int) -> None:
        path = self._path(stream_id)
        temporary = path.with_name(path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0), 0o600)
        try:
            os.write(fd, f"{end}\n".encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        if hasattr(os, "O_DIRECTORY"):  # make the rename itself durable
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)


@dataclass
class _Logged:
    sequence: int
    send_time_ns: int | None
    timestamps: list[tuple[int, int]]
    payload: bytes


@dataclass
class _Consumer:
    alias: int = 0
    next_to_send: int = 0
    acknowledged: int = 0
    attached: bool = False


class StreamProducer:
    def __init__(self, config: StreamConfig, sequences):
        if config.max_elements_per_packet == 0 or config.send_log_max_packets == 0:
            raise ValueError("Stream limits must be positive.")
        if config.sample_rate and 0 in config.sample_rate:
            raise ValueError("A stream's sample rate must be positive.")
        if config.timestamp_roles != sorted(set(config.timestamp_roles)):
            raise ValueError("A stream's timestamp roles must be distinct and in ascending role order.")
        if wire.payload_bytes(config.type, config.max_elements_per_packet) > wire.MAX_PAYLOAD_BYTES:
            raise ValueError(f"max_elements_per_packet exceeds the 256 KiB payload limit for {config.type.name}.")
        self.config = config
        self.sequences = sequences
        # Continue beyond the previous reservation: after a restart the consumer sees a gap,
        # never a reused sequence number.
        self.reserved_end = sequences.reserved_end(config.stream_id)
        self.next_sequence = self.reserved_end
        self.log: deque[_Logged] = deque()  # contiguous sequences
        self.consumers: dict[str, _Consumer] = {}
        self.pending: list[tuple[int, ...]] = []
        self.pending_times: list[tuple[int, int]] = []
        self.pending_since: int | None = None
        self.stamp_send_time = True  # only while this node's clock is synchronized
        self.fault_code: str | None = None
        self.packets = self.elements = self.replayed = self.lost_resumes = 0
        self.blocked_total_ms = 0

    def log_full(self) -> bool:
        return len(self.log) >= self.config.send_log_max_packets

    def append(self, elements: list, now_ns: int, times: list[tuple[int, int]] = ()) -> int:
        """Takes elements; returns how many: fewer when the send log is full (backpressure). The caller
        waits for acks and retries, and calls fault(SEND_LOG_OVERFLOW) after max_block_ms. A stream with
        explicit timestamps takes one element at a time with exactly its declared roles."""
        times = list(times)
        if self.config.explicit_timestamps:
            if len(elements) > 1 or (len(elements) == 1 and [r for r, _ in times] != self.config.timestamp_roles):
                raise ValueError(f"Stream {wire.stream_id_text(self.config.stream_id)} has explicit timestamps: "
                                 "publish one element at a time with its declared roles.")
        elif times:
            raise ValueError(f"Stream {wire.stream_id_text(self.config.stream_id)} takes no per-element timestamps.")
        if self.fault_code is not None:
            return len(elements)  # a faulted stream sends nothing; the graph is not held back
        if self.config.explicit_timestamps:
            if not elements or self.log_full():
                return 0
            self.pending = [elements[0]]
            self.pending_since = now_ns
            self.pending_times = times
            self._seal()
            return 1
        limit = self.config.max_elements_per_packet
        taken = 0
        while taken < len(elements):
            if len(self.pending) == limit:
                if self.log_full():
                    break
                self._seal()
            if not self.pending and self.log_full():
                break
            chunk = min(len(elements) - taken, limit - len(self.pending))
            if not self.pending:
                self.pending_since = now_ns
            self.pending.extend(elements[taken:taken + chunk])
            taken += chunk
        if len(self.pending) == limit and not self.log_full():
            self._seal()
        return taken

    def flush(self, now_ns: int, force: bool = False) -> bool:
        """Seals the partial packet if its oldest element waited max_batch_latency (or with force)."""
        if not self.pending or self.log_full() or self.fault_code is not None:
            return False
        if not force and now_ns - self.pending_since < self.config.max_batch_latency_ms * MS:
            return False
        self._seal()
        return True

    def flush_deadline(self) -> int | None:
        return None if not self.pending else self.pending_since + self.config.max_batch_latency_ms * MS

    def _seal(self) -> None:
        if self.next_sequence >= self.reserved_end:
            self.reserved_end = self.next_sequence + SEQUENCE_RESERVATION
            self.sequences.reserve(self.config.stream_id, self.reserved_end)
        self.log.append(_Logged(self.next_sequence, utc_now_ns() if self.stamp_send_time else None, self.pending_times,
                                wire.encode_elements(self.config.type, self.pending)))
        self.next_sequence += 1
        self.packets += 1
        self.elements += len(self.pending)
        self.pending, self.pending_times, self.pending_since = [], [], None

    def resume(self, consumer: str, alias: int, next_expected: int) -> None:
        """RESUME from a consumer: start transmitting at next_expected. A position older than the log
        starts at the oldest logged packet (the consumer faults on the gap); a position beyond
        next_sequence faults the stream (STREAM_STATE_LOST)."""
        oldest = self.log[0].sequence if self.log else self.next_sequence
        start = next_expected
        if next_expected < oldest:
            self.lost_resumes += 1
            start = oldest
        elif next_expected > self.next_sequence:
            self.lost_resumes += 1
            self.fault(STREAM_STATE_LOST)
            start = self.next_sequence
        entry = self.consumers.setdefault(consumer, _Consumer())
        entry.alias, entry.next_to_send, entry.attached = alias, start, True
        entry.acknowledged = max(entry.acknowledged, start)
        self.replayed += self.next_sequence - start
        self._trim()

    def detach(self, consumer: str) -> None:
        if consumer in self.consumers:
            self.consumers[consumer].attached = False  # keeps its retention position

    def acknowledge(self, consumer: str, next_expected: int) -> None:
        entry = self.consumers.get(consumer)
        if entry is None or next_expected > entry.next_to_send:
            return  # cannot acknowledge what was not sent
        entry.acknowledged = max(entry.acknowledged, next_expected)
        self._trim()

    def _trim(self) -> None:
        if not self.consumers:
            return  # nobody has the data yet
        lowest = min(c.acknowledged for c in self.consumers.values())
        while self.log and self.log[0].sequence < lowest:
            self.log.popleft()

    def next_message(self, consumer: str) -> bytes | None:
        """The next encoded packet for the consumer, or None if it is up to date."""
        entry = self.consumers.get(consumer)
        if (self.fault_code is not None or entry is None or not entry.attached
                or entry.next_to_send >= self.next_sequence or not self.log):
            return None
        index = entry.next_to_send - self.log[0].sequence
        if index >= len(self.log):
            return None
        logged = self.log[index]
        entry.next_to_send += 1
        return wire.encode_data_packet(wire.DataPacket(self.config.type, entry.alias, logged.sequence, logged.payload,
                                                       logged.timestamps, logged.send_time_ns))

    def fault(self, code: str) -> None:
        if self.fault_code is None:
            self.fault_code = code

    def recover(self) -> None:
        """RECOVER_STREAM: clears the fault; sending resumes."""
        self.fault_code = None

    def stats(self) -> dict:
        return {"packets": self.packets, "elements": self.elements, "replayed": self.replayed,
                "lost_resumes": self.lost_resumes, "send_log_depth": len(self.log), "blocked_ms_total": self.blocked_total_ms}


@dataclass
class _Buffered:
    sequence: int
    values: list[tuple[int, ...]]
    timestamps: list[tuple[int, int]]
    consumed: int = 0


class StreamConsumer:
    def __init__(self, config: StreamConfig, alias: int):
        self.config = config
        self.alias = alias
        self.next_expected = 0  # next sequence to accept
        self.consumed_up_to = 0  # every packet before this was fully taken by the graph
        self.acked_up_to = 0
        self.buffer: deque[_Buffered] = deque()
        self.buffered_elements = 0
        self.consumed_since_ack = 0
        self.last_ack_ns: int | None = None
        self.fault_code: str | None = None
        self.restart_at_next = False
        self.element_count_known = True  # false after a recovered fault
        self.latency = LatencyHistogram()
        self.packets = self.elements = self.duplicates = self.malformed = 0

    def resume_message(self) -> wire.ControlMessage:
        """Sent after every (re)connect."""
        return wire.ControlMessage(wire.RESUME, self.alias, self.next_expected, self.config.stream_id)

    def on_packet(self, packet: wire.DataPacket, now_ns: int, received_utc_ns: int | None = None) -> bool:
        """Delivered in order, duplicate discarded, or a gap / type mismatch, which faults the stream.
        A delivered packet with SEND_TIME adds a latency sample; returns whether it was late."""
        if self.fault_code is not None:
            return False
        if packet.type != self.config.type:
            self.fault(TYPE_MISMATCH)
            return False
        roles = [role for role, _ in packet.timestamps]
        if (roles != self.config.timestamp_roles) if self.config.explicit_timestamps else bool(roles):
            self.fault(TIMESTAMP_PROFILE_MISMATCH)
            return False
        if self.restart_at_next:
            self.restart_at_next = False
            self.next_expected = packet.sequence
            self.consumed_up_to = max(self.consumed_up_to, packet.sequence)
            self.acked_up_to = max(self.acked_up_to, packet.sequence)
        if packet.sequence < self.next_expected:
            self.duplicates += 1
            return False
        if packet.sequence > self.next_expected:
            self.fault(SEQUENCE_GAP)
            return False
        values = wire.decode_elements(self.config.type, packet.payload)
        self.buffer.append(_Buffered(packet.sequence, values, list(packet.timestamps)))
        self.buffered_elements += len(values)
        self.next_expected += 1
        self.packets += 1
        if self.last_ack_ns is None:
            self.last_ack_ns = now_ns
        if packet.send_time_ns is not None:
            arrival = received_utc_ns if received_utc_ns is not None else utc_now_ns()
            return self.latency.add(arrival - packet.send_time_ns, self.config.max_latency_ms)
        return False

    def on_malformed(self) -> None:
        self.malformed += 1
        self.fault(MALFORMED_PACKET)

    def available(self) -> int:
        return self.buffered_elements

    def take(self, max_count: int, first_times: list | None = None) -> list[tuple[int, ...]]:
        """Elements for the graph. first_times, if given, receives the times of the first element taken:
        its packet's records (explicit timestamps) or the times derived from the sample rate; empty when
        unknown (untimed, inside a multi-element packet, or uniformly sampled after a recovered fault)."""
        if first_times is not None:
            first_times.clear()
            if max_count > 0 and self.buffer:
                front = self.buffer[0]
                if self.config.sample_rate:
                    if self.element_count_known:
                        ns = element_time_ns(self.config.sample_rate, self.elements)
                        first_times.extend((role, ns) for role in self.config.timestamp_roles)
                elif front.consumed == 0:
                    first_times.extend(front.timestamps)
        out = []
        while len(out) < max_count and self.buffer:
            front = self.buffer[0]
            chunk = min(max_count - len(out), len(front.values) - front.consumed)
            out.extend(front.values[front.consumed:front.consumed + chunk])
            front.consumed += chunk
            self.buffered_elements -= chunk
            self.elements += chunk
            if front.consumed == len(front.values):
                self.consumed_up_to = front.sequence + 1
                self.consumed_since_ack += 1
                self.buffer.popleft()
        return out

    def ack_due(self, now_ns: int) -> wire.ControlMessage | None:
        """An ACK when 64 packets were consumed or 50 ms passed since the last one while something new was consumed."""
        if self.consumed_up_to <= self.acked_up_to:
            return None
        last = self.last_ack_ns if self.last_ack_ns is not None else 0
        if self.consumed_since_ack < ACK_EVERY_PACKETS and now_ns - last < ACK_INTERVAL_NS:
            return None
        self.acked_up_to = self.consumed_up_to
        self.consumed_since_ack = 0
        self.last_ack_ns = now_ns
        return wire.ControlMessage(wire.ACK, self.alias, self.acked_up_to)

    def fault(self, code: str) -> None:
        if self.fault_code is None:
            self.fault_code = code

    def recover(self) -> None:
        """RECOVER_STREAM: clears the fault and accepts the next packet received as the new start."""
        if self.fault_code is None:
            return  # a repeated RECOVER_STREAM changes nothing
        self.fault_code = None
        self.restart_at_next = True
        self.element_count_known = False  # the elements lost in the fault are not counted

    def stats(self) -> dict:
        return {"packets": self.packets, "elements": self.elements, "duplicates_discarded": self.duplicates,
                "malformed": self.malformed, "next_expected": self.next_expected, "buffered_elements": self.buffered_elements}

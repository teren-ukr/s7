# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Lossless delivery rules of the stream protocol, with a simulated link: the scenarios and
expectations of s7transport/tests/stream_protocol_smoke.cpp.

Run from s7py: python3 -m unittest discover -s tests
"""
import random
import sys
import tempfile
import unittest
from collections import deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from s7node import stream, wire  # noqa: E402

STREAM_ID = wire.parse_stream_id("0335c8e1-a3ab-4e8c-8b17-dc8170f5e370")
MS = stream.MS
T0 = 1_000_000_000_000  # an arbitrary monotonic time


def config(type_name, per_packet, log_packets, **more):
    return stream.StreamConfig(STREAM_ID, wire.wire_type(type_name), max_elements_per_packet=per_packet,
                               send_log_max_packets=log_packets, max_batch_latency_ms=10, **more)


def elements(type_name, numbers):
    return wire.from_values(wire.wire_type(type_name), numbers)


def numbers(type_name, items):
    return wire.values(wire.wire_type(type_name), items)


class Link:
    """Moves messages from producer to consumer; a reset loses what is in flight."""

    def __init__(self, producer, consumer, key="consumer"):
        self.producer, self.consumer, self.key = producer, consumer, key
        self.in_flight = deque()

    def connect(self):
        resume = self.consumer.resume_message()
        self.producer.resume(self.key, resume.stream_alias, resume.next_expected)

    def reset(self):
        self.in_flight.clear()
        self.producer.detach(self.key)

    def pump(self, now, deliver=None):
        """The producer sends what it has; up to `deliver` messages arrive."""
        while (message := self.producer.next_message(self.key)) is not None:
            self.in_flight.append(message)
        n = 0
        while self.in_flight and (deliver is None or n < deliver):
            self.consumer.on_packet(wire.decode_data_packet(self.in_flight.popleft()), now)
            n += 1

    def acknowledge(self, now):
        ack = self.consumer.ack_due(now)
        if ack is not None:
            decoded = wire.decode_control_message(wire.encode_control_message(ack))
            self.producer.acknowledge(self.key, decoded.next_expected)


def take_all(consumer, type_name="F64"):
    items = consumer.take(consumer.available())
    return numbers(type_name, items)


class StreamProtocolTest(unittest.TestCase):
    def test_batching_and_delivery(self):
        producer = stream.StreamProducer(config("F64", 4, 16), stream.MemorySequenceStore())
        consumer = stream.StreamConsumer(config("F64", 4, 16), 7)
        link = Link(producer, consumer)
        link.connect()
        values = [float(v) for v in range(1, 11)]
        self.assertEqual(producer.append(elements("F64", values), T0), 10)
        self.assertEqual(producer.stats()["packets"], 2, "two full packets sealed")
        self.assertFalse(producer.flush(T0 + 5 * MS), "partial batch waits for its latency")
        self.assertTrue(producer.flush(T0 + 10 * MS), "partial batch flushed after max_batch_latency")
        link.pump(T0)
        self.assertEqual(take_all(consumer), values, "values arrive once and in order")
        f64 = wire.wire_type("F64")
        consumer.on_packet(wire.DataPacket(f64, 7, 0, wire.encode_elements(f64, elements("F64", [1.0]))), T0)
        self.assertEqual((consumer.stats()["duplicates_discarded"], consumer.available()), (1, 0), "duplicate discarded")
        self.assertIsNone(consumer.fault_code, "duplicates are not faults")

    def test_gap_and_type_mismatch(self):
        f64, f32 = wire.wire_type("F64"), wire.wire_type("F32")
        consumer = stream.StreamConsumer(config("F64", 4, 16), 1)
        consumer.on_packet(wire.DataPacket(f64, 1, 1, wire.encode_elements(f64, elements("F64", [1.0]))), T0)
        self.assertEqual(consumer.fault_code, stream.SEQUENCE_GAP)
        typed = stream.StreamConsumer(config("F64", 4, 16), 1)
        typed.on_packet(wire.DataPacket(f32, 1, 0, wire.encode_elements(f32, elements("F32", [1.0]))), T0)
        self.assertEqual(typed.fault_code, stream.TYPE_MISMATCH)

    def test_reconnect_replays_without_loss(self):
        producer = stream.StreamProducer(config("I32", 1, 64), stream.MemorySequenceStore())
        consumer = stream.StreamConsumer(config("I32", 1, 64), 3)
        link = Link(producer, consumer)
        link.connect()
        for v in range(6):
            producer.append(elements("I32", [v]), T0)
        link.pump(T0, 3)  # packets 0..2 arrive, 3..5 are lost with the connection
        link.reset()
        self.assertEqual(producer.stats()["send_log_depth"], 6, "nothing acknowledged yet: all packets retained")
        link.connect()  # RESUME from next_expected = 3
        link.pump(T0)
        self.assertEqual(take_all(consumer, "I32"), [0, 1, 2, 3, 4, 5], "replay fills the loss exactly")
        self.assertEqual(consumer.stats()["duplicates_discarded"], 0, "resume does not resend delivered packets")

    def test_backpressure_and_acks(self):
        producer = stream.StreamProducer(config("F64", 1, 3), stream.MemorySequenceStore())
        consumer = stream.StreamConsumer(config("F64", 1, 3), 1)
        link = Link(producer, consumer)
        link.connect()
        values = elements("F64", [1.0, 2.0, 3.0, 4.0, 5.0])
        taken = producer.append(values, T0)
        self.assertTrue(taken == 3 and producer.log_full(), "a full send log stops new elements (backpressure)")
        link.pump(T0)
        take_all(consumer)
        link.acknowledge(T0)  # nothing yet: neither 64 packets nor 50 ms
        self.assertTrue(producer.log_full(), "ACK waits for 64 packets or 50 ms")
        link.acknowledge(T0 + 50 * MS)
        self.assertEqual(producer.stats()["send_log_depth"], 0, "acknowledged packets leave the log")
        self.assertEqual(producer.append(values[taken:], T0), 2, "room again after the ACK")

    def test_retention_and_two_consumers(self):
        producer = stream.StreamProducer(config("F64", 1, 64), stream.MemorySequenceStore())
        fast = stream.StreamConsumer(config("F64", 1, 64), 1)
        slow = stream.StreamConsumer(config("F64", 1, 64), 2)
        a, b = Link(producer, fast, "fast"), Link(producer, slow, "slow")
        a.connect()
        b.connect()
        for i in range(10):
            producer.append(elements("F64", [float(i)]), T0)
        a.pump(T0)
        take_all(fast)
        a.acknowledge(T0 + 50 * MS)
        self.assertEqual(producer.stats()["send_log_depth"], 10, "the log keeps what the slow consumer has not acknowledged")
        b.pump(T0, 4)
        b.reset()  # slow consumer disconnects; its packets stay
        b.connect()
        b.pump(T0)
        self.assertEqual(len(take_all(slow)), 10, "slow consumer resumes without loss")
        b.acknowledge(T0 + 50 * MS)
        self.assertEqual(producer.stats()["send_log_depth"], 0, "log trimmed once both acknowledged")

    def test_producer_restart_is_a_gap(self):
        with tempfile.TemporaryDirectory() as directory:
            sequences = stream.FileSequenceStore(Path(directory))
            consumer = stream.StreamConsumer(config("F64", 1, 64), 1)
            first = stream.StreamProducer(config("F64", 1, 64), sequences)
            link = Link(first, consumer)
            link.connect()
            first.append(elements("F64", [1.0]), T0)
            link.pump(T0)
            # The reservation is durable, in the C++ node's file format.
            self.assertEqual((Path(directory) / "0335c8e1-a3ab-4e8c-8b17-dc8170f5e370.seq").read_text(), "65536\n")

            restarted = stream.StreamProducer(config("F64", 1, 64), sequences)
            self.assertEqual(restarted.next_sequence, stream.SEQUENCE_RESERVATION, "continues beyond its reservation")
            link = Link(restarted, consumer)
            link.connect()  # RESUME from 1, which the restarted producer never had
            self.assertIsNone(restarted.fault_code, "a lost resume position does not fault the producer")
            self.assertEqual(restarted.stats()["lost_resumes"], 1, "the lost position is counted")
            restarted.append(elements("F64", [2.0]), T0)
            link.pump(T0)
            self.assertEqual(consumer.fault_code, stream.SEQUENCE_GAP, "the consumer faults on the gap")

            consumer.recover()  # RECOVER_STREAM: the next packet is the new start
            restarted.append(elements("F64", [2.0]), T0)
            link.pump(T0)
            self.assertIsNone(consumer.fault_code)
            self.assertEqual(take_all(consumer), [1.0, 2.0], "the value before the restart, then the new start")

            behind = stream.StreamProducer(config("F64", 1, 64), sequences)
            behind.resume("ahead", 1, behind.next_sequence + 10)
            self.assertEqual(behind.fault_code, stream.STREAM_STATE_LOST, "a resume beyond the producer is state loss")

    def test_soak_i12(self):
        """Random batching and random connection drops: every value exactly once, in order."""
        rng = random.Random(12345)
        c = config("I12", 7, 32)
        producer = stream.StreamProducer(c, stream.MemorySequenceStore())
        consumer = stream.StreamConsumer(c, 9)
        link = Link(producer, consumer)
        link.connect()
        now = T0
        sent, received = [], []
        resets = 0
        while len(sent) < 20000:
            chunk = [rng.randint(-2048, 2047) for _ in range(rng.randint(1, 20))]
            offset = 0
            while offset < len(chunk):
                offset += producer.append(elements("I12", chunk[offset:]), now)
                if offset < len(chunk):  # blocked: let the consumer catch up
                    link.pump(now)
                    received += take_all(consumer, "I12")
                    now += 60 * MS
                    link.acknowledge(now)
            sent += chunk
            now += (1 if rng.randint(0, 99) < 50 else 12) * MS
            producer.flush(now)
            link.pump(now, rng.randint(1, 20))
            if rng.randint(0, 99) < 5:
                link.reset()
                link.connect()
                resets += 1
            received += take_all(consumer, "I12")
            link.acknowledge(now)
        producer.flush(now, force=True)
        link.pump(now)
        received += take_all(consumer, "I12")
        self.assertIsNone(consumer.fault_code)
        self.assertIsNone(producer.fault_code)
        self.assertGreater(resets, 50)
        self.assertEqual(received, sent, "20000 I12 values delivered exactly once and in order through reconnects")

    def test_explicit_timestamps(self):
        c = config("F64", 64, 16, timestamp_roles=[wire.SOURCE_TIME, wire.PROCESSING_TIME])
        producer = stream.StreamProducer(c, stream.MemorySequenceStore())
        consumer = stream.StreamConsumer(c, 3)
        link = Link(producer, consumer)
        link.connect()
        for i in range(3):
            times = [(wire.SOURCE_TIME, 1000 * i), (wire.PROCESSING_TIME, 5000 + i)]
            self.assertEqual(producer.append(elements("F64", [float(i)]), T0, times), 1)
        self.assertEqual(producer.stats()["packets"], 3, "each stamped element is a packet of its own")
        with self.assertRaises(ValueError):
            producer.append(elements("F64", [9.0]), T0, [(wire.PROCESSING_TIME, 1)])
        link.pump(T0)
        for i in range(3):
            times = []
            self.assertEqual(numbers("F64", consumer.take(1, times)), [float(i)])
            self.assertEqual(times, [(wire.SOURCE_TIME, 1000 * i), (wire.PROCESSING_TIME, 5000 + i)])
        f64 = wire.wire_type("F64")
        payload = wire.encode_elements(f64, elements("F64", [1.0]))
        consumer.on_packet(wire.DataPacket(f64, 3, 3, payload, [(wire.MODEL_TIME, 0)]), T0)
        self.assertEqual(consumer.fault_code, stream.TIMESTAMP_PROFILE_MISMATCH)
        uniform = stream.StreamConsumer(config("F64", 4, 16), 1)
        uniform.on_packet(wire.DataPacket(f64, 1, 0, payload, [(wire.PROCESSING_TIME, 0)]), T0)
        self.assertEqual(uniform.fault_code, stream.TIMESTAMP_PROFILE_MISMATCH)

    def test_derived_timestamps(self):
        c = config("F64", 4, 16, sample_rate=(48000, 1), timestamp_roles=[wire.MODEL_TIME])
        producer = stream.StreamProducer(c, stream.MemorySequenceStore())
        consumer = stream.StreamConsumer(c, 1)
        link = Link(producer, consumer)
        link.connect()
        self.assertEqual(producer.append(elements("F64", [1.0] * 10), T0), 10)
        producer.flush(T0, force=True)
        link.pump(T0)
        times = []
        self.assertEqual(len(consumer.take(3, times)), 3)
        self.assertEqual(times, [(wire.MODEL_TIME, 0)], "element 0 at 0 ns")
        consumer.take(3, times)
        self.assertEqual(times, [(wire.MODEL_TIME, 62_500)], "element 3 at 3 / 48000 s")
        self.assertEqual(stream.element_time_ns((1, 3), 1_000_000_000_000), 2**63 - 1, "saturates")
        self.assertEqual(stream.element_time_ns((1_000_000_000, 1), 4 * 10**18), 4 * 10**18)
        self.assertEqual(stream.element_time_ns((3, 1), 1), 333_333_333, "rounded toward zero")
        consumer.recover()  # a healthy stream: nothing changes
        consumer.take(1, times)
        self.assertEqual(times, [(wire.MODEL_TIME, 125_000)])
        consumer.fault(stream.UNDERRUN)
        consumer.recover()
        consumer.take(1, times)
        self.assertEqual(times, [], "no invented times after a recovery")

    def test_latency(self):
        c = config("F64", 1, 256, max_latency_ms=10)
        sequences = stream.MemorySequenceStore()
        producer = stream.StreamProducer(c, sequences)
        consumer = stream.StreamConsumer(c, 1)
        resume = consumer.resume_message()
        producer.resume("k", resume.stream_alias, resume.next_expected)
        latencies = [(1 << i) * 1_000_000 for i in range(10)] + [1_000_000] * 100
        late = 0
        for latency in latencies:
            self.assertEqual(producer.append(elements("F64", [1.0]), T0), 1)
            packet = wire.decode_data_packet(producer.next_message("k"))
            self.assertIsNotNone(packet.send_time_ns, "the producer stamps SEND_TIME")
            late += consumer.on_packet(packet, T0, packet.send_time_ns + latency)
        stats = consumer.latency.stats()
        self.assertEqual((stats["samples"], stats["min"], stats["max"], stats["last"]), (110, 1_000_000, 512_000_000, 1_000_000))
        self.assertEqual((stats["late"], late), (6, 6), "16 to 512 ms are late for a 10 ms limit")
        self.assertTrue(1_000_000 <= stats["p50"] <= 2_048_000, stats["p50"])
        self.assertTrue(256_000_000 <= stats["p99"] <= 512_000_000, stats["p99"])
        self.assertEqual(stats["mean"], (1023 + 100) * 1_000_000 // 110)
        producer.resume("k", resume.stream_alias, 0)  # replays everything
        duplicate = wire.decode_data_packet(producer.next_message("k"))
        consumer.on_packet(duplicate, T0, duplicate.send_time_ns)
        self.assertEqual(consumer.latency.stats()["samples"], 110, "duplicates are not measured")
        unsynced = stream.StreamProducer(c, sequences)
        unsynced.stamp_send_time = False
        unsynced.resume("k", 1, 0)
        self.assertEqual(unsynced.append(elements("F64", [1.0]), T0), 1)
        self.assertIsNone(wire.decode_data_packet(unsynced.next_message("k")).send_time_ns)


if __name__ == "__main__":
    unittest.main()

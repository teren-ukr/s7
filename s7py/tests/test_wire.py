# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""The data stream wire format against the shared conformance fixtures (s7transport/tests/fixtures/wire_v1.json).

Run from s7py: python3 -m unittest discover -s tests
"""
import json
import math
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from s7node import wire  # noqa: E402
from s7node.stream import StreamDescriptor  # noqa: E402

FIXTURES = json.loads((ROOT.parent / "s7l2" / "s7transport" / "tests" / "fixtures" / "wire_v1.json").read_text())


def same(expected, actual) -> bool:
    """Fixture values: integers beyond 53 bits as decimal strings, complex values as [re, im], floats to the bit."""
    if isinstance(expected, list):
        return isinstance(actual, (list, tuple)) and len(expected) == len(actual) and all(map(same, expected, actual))
    if isinstance(expected, str):
        return int(expected) == actual
    if isinstance(expected, float) or isinstance(actual, float):
        return struct.pack("<d", float(expected)) == struct.pack("<d", float(actual))
    return expected == actual and type(actual) is int


def fixture_values(t, values):
    def number(v):
        return int(v) if isinstance(v, str) else v
    return [[number(p) for p in v] if t.complex else number(v) for v in values]


class WireFixtureTest(unittest.TestCase):
    def test_data_packets_decode_and_encode_to_the_fixture_bytes(self):
        for case in FIXTURES["data"]:
            with self.subTest(case["name"]):
                message = bytes.fromhex(case["hex"])
                packet = wire.decode_data_packet(message)
                self.assertEqual((packet.type.name, packet.stream_alias, packet.sequence, packet.send_time_ns),
                                 (case["type"], case["stream_alias"], case["sequence"], case["send_time_ns"]))
                self.assertEqual([(wire.ROLE_NAMES[r], ns) for r, ns in packet.timestamps],
                                 sorted(((t["role"], t["ns"]) for t in case["timestamps"]), key=lambda r: wire.ROLES[r[0]]))
                decoded = wire.values(packet.type, wire.decode_elements(packet.type, packet.payload))
                self.assertTrue(same(case["values"], decoded), f"{decoded}")
                elements = wire.from_values(packet.type, fixture_values(packet.type, case["values"]))
                rebuilt = wire.DataPacket(packet.type, case["stream_alias"], case["sequence"],
                                          wire.encode_elements(packet.type, elements),
                                          [(wire.ROLES[t["role"]], t["ns"]) for t in case["timestamps"]], case["send_time_ns"])
                self.assertEqual(wire.encode_data_packet(rebuilt).hex(), case["hex"])

    def test_unknown_noncritical_extensions_are_ignored(self):
        for case in FIXTURES["data_ignoring_extensions"]:
            with self.subTest(case["name"]):
                packet = wire.decode_data_packet(bytes.fromhex(case["hex"]))
                self.assertEqual((packet.type.name, packet.stream_alias, packet.sequence), (case["type"], case["stream_alias"], case["sequence"]))
                self.assertTrue(same(case["values"], wire.values(packet.type, wire.decode_elements(packet.type, packet.payload))))

    def test_control_messages(self):
        for case in FIXTURES["control"]:
            with self.subTest(case["name"]):
                message = wire.decode_control_message(bytes.fromhex(case["hex"]))
                stream_id = None if message.kind == wire.ACK else wire.stream_id_text(message.stream_id)
                self.assertEqual((message.kind, message.stream_alias, message.next_expected, stream_id),
                                 (case["kind"], case["stream_alias"], case["next_expected"], case["stream_id"]))
                self.assertEqual(wire.encode_control_message(message).hex(), case["hex"])

    def test_invalid_messages_are_rejected(self):
        for case in FIXTURES["invalid"]:
            message = bytes.fromhex(case["hex"])
            with self.subTest(case["name"]), self.assertRaises(wire.FormatError, msg=case["reason"]):
                if wire.is_control_message(message):
                    wire.decode_control_message(message)
                else:
                    packet = wire.decode_data_packet(message)
                    wire.decode_elements(packet.type, packet.payload)

    def test_descriptors(self):
        for case in FIXTURES["descriptors"]:
            with self.subTest(case["name"]):
                self.assertEqual(StreamDescriptor.from_json(case["descriptor"]).to_json(), case["canonical"])
        for case in FIXTURES["invalid_descriptors"]:
            with self.subTest(case["name"]), self.assertRaises(ValueError, msg=case["reason"]):
                StreamDescriptor.from_json(case["descriptor"])


class WireValueTest(unittest.TestCase):
    def test_bits_travel_unchanged(self):
        f64 = wire.wire_type("F64")
        payload_nan = 0x7FF8_0000_DEAD_BEEF
        for bits in (payload_nan, 0xFFF0_0000_0000_0001, 0x8000_0000_0000_0000, 1):  # NaN payloads, -0.0, a subnormal
            packet = wire.decode_data_packet(wire.encode_data_packet(
                wire.DataPacket(f64, 3, 9, wire.encode_elements(f64, [(bits,)]))))
            self.assertEqual(wire.decode_elements(f64, packet.payload), [(bits,)])

    def test_binary128_holds_every_binary64_value_exactly(self):
        f128 = wire.wire_type("F128")
        for value in (0.0, -0.0, 1.0, -2.5, 1 / 3, 5e-324, 2.2250738585072014e-308, 1.7976931348623157e308, math.inf, -math.inf):
            with self.subTest(value):
                (bits,), = wire.from_values(f128, [value])
                self.assertTrue(same(value, wire.component_value(f128, bits)))
        (bits,), = wire.from_values(f128, [1.0])
        self.assertEqual(bits, 0x3FFF << 112)
        self.assertTrue(math.isnan(wire.component_value(f128, wire.from_values(f128, [math.nan])[0][0])))

    def test_no_implicit_conversion(self):
        for type_name, value in (("F32", 0.1), ("F16", 1e10), ("I8", 128), ("U8", -1), ("I16", 1.0), ("U12", 4096)):
            with self.subTest(type_name), self.assertRaises(ValueError):
                wire.from_values(wire.wire_type(type_name), [value])

    def test_packed_12_bit(self):
        i12 = wire.wire_type("I12")
        for count in range(1, 6):
            numbers = [(-1) ** n * (n * 409 % 2048) for n in range(count)]
            payload = wire.encode_elements(i12, wire.from_values(i12, numbers))
            self.assertEqual(len(payload), wire.payload_bytes(i12, count))
            self.assertEqual(wire.values(i12, wire.decode_elements(i12, payload)), numbers)

    def test_payload_limit(self):
        u8 = wire.wire_type("U8")
        with self.assertRaisesRegex(wire.FormatError, "256 KiB"):
            wire.encode_data_packet(wire.DataPacket(u8, 1, 0, bytes(wire.MAX_PAYLOAD_BYTES + 1)))
        message = wire.encode_data_packet(wire.DataPacket(u8, 1, 0, bytes(wire.MAX_PAYLOAD_BYTES)))
        with self.assertRaisesRegex(wire.FormatError, "256 KiB"):
            wire.decode_data_packet(message + b"\0")


if __name__ == "__main__":
    unittest.main()

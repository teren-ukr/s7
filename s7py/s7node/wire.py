# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""The S7 data stream wire format, version 1 (doc/S7_Network_Wire_Protocol_v1.md, sections 7, 8 and 12.1).

Mirrors s7transport's wire_format.cpp: the same encoding, the same checks in the same
order. Every multi-byte field and value is little-endian, written explicitly.

A payload holds elements of one wire type. Each element is a tuple of component bit
patterns (one component, or real and imaginary / in-phase and quadrature): unsigned
integers of the component's width, two's complement for signed integers and the IEEE
interchange bits for floating point. Bits travel unchanged, so NaN payloads, infinities
and signed zeros are preserved; values() and from_values() convert to and from Python
numbers.
"""
import math
import struct
import uuid
from dataclasses import dataclass, field
from fractions import Fraction

DATA_VERSION = 1
CONTROL_VERSION = 0x80 | 1
DATA_HEADER_BYTES = 16
CONTROL_MESSAGE_BYTES = 32
MAX_PAYLOAD_BYTES = 256 * 1024
FLAG_EXTENSIONS = 0x01
TIMESTAMPS_EXTENSION = 0x8001  # critical
SEND_TIME_EXTENSION = 0x0002  # noncritical: when the producer sealed the packet
CRITICAL_EXTENSION_BIT = 0x8000
# What this implementation speaks, as NODE_INFO.data_protocol advertises it (section 12.1 item 4).
SUPPORTED_PACKET_VERSIONS = (DATA_VERSION,)
SUPPORTED_EXTENSIONS = (SEND_TIME_EXTENSION, TIMESTAMPS_EXTENSION)

MODEL_TIME, SOURCE_TIME, PROCESSING_TIME = 1, 2, 3
ROLE_NAMES = {MODEL_TIME: "MODEL_TIME", SOURCE_TIME: "SOURCE_TIME", PROCESSING_TIME: "PROCESSING_TIME"}
ROLES = {name: role for role, name in ROLE_NAMES.items()}

ACK, RESUME, RESUME_NO_STATE = 1, 2, 3


class FormatError(ValueError):
    """A malformed or unsupported message; the receiver drops it and reports a fault."""


@dataclass(frozen=True)
class WireType:
    name: str
    id: int
    kind: str  # "int", "uint" or "float", of each component
    bits: int  # per component
    complex: bool

    @property
    def components(self) -> int:
        return 2 if self.complex else 1


def _types():
    table = [("I8", 0x0001, "int", 8), ("U8", 0x0002, "uint", 8), ("I12", 0x0003, "int", 12), ("U12", 0x0004, "uint", 12),
             ("I16", 0x0005, "int", 16), ("U16", 0x0006, "uint", 16), ("I32", 0x0007, "int", 32), ("U32", 0x0008, "uint", 32),
             ("I64", 0x0009, "int", 64), ("U64", 0x000A, "uint", 64), ("I128", 0x000B, "int", 128),
             ("U128", 0x000C, "uint", 128), ("F16", 0x000D, "float", 16), ("F32", 0x000E, "float", 32),
             ("F64", 0x000F, "float", 64), ("F128", 0x0010, "float", 128),
             ("C16", 0x0101, "float", 16), ("C32", 0x0102, "float", 32), ("C64", 0x0103, "float", 64),
             ("C128", 0x0104, "float", 128), ("CI8", 0x0201, "int", 8), ("CU8", 0x0202, "uint", 8),
             ("CI16", 0x0203, "int", 16), ("CI32", 0x0204, "int", 32), ("CI64", 0x0205, "int", 64),
             ("CI128", 0x0206, "int", 128)]
    return {name: WireType(name, type_id, kind, bits, name.startswith("C")) for name, type_id, kind, bits in table}


TYPES = _types()
TYPES_BY_ID = {t.id: t for t in TYPES.values()}


def wire_type(name: str) -> WireType:
    try:
        return TYPES[name]
    except KeyError:
        raise ValueError(f"unknown signal type '{name}'") from None


# ---- payloads -----------------------------------------------------------------------

def _packed12_bytes(values: int) -> int:
    return 3 * (values // 2) + 2 * (values % 2)


def payload_bytes(t: WireType, count: int) -> int:
    values = count * t.components
    return _packed12_bytes(values) if t.bits == 12 else values * t.bits // 8


def payload_element_count(t: WireType, size: int) -> int:
    if t.bits == 12:
        if size % 3 == 1:
            raise FormatError("payload length is not a whole number of 12-bit values")
        values = (size // 3) * 2 + (1 if size % 3 == 2 else 0)
    else:
        if size % (t.bits // 8):
            raise FormatError(f"payload length is not a whole number of {t.name} values")
        values = size // (t.bits // 8)
    if values % t.components:
        raise FormatError("payload holds an incomplete complex value")
    return values // t.components


def encode_elements(t: WireType, elements) -> bytes:
    """Elements as tuples of component bits (see the module docstring)."""
    mask = (1 << t.bits) - 1
    codes = []
    for element in elements:
        if len(element) != t.components:
            raise ValueError(f"a {t.name} element has {t.components} component(s)")
        for part in element:
            if not 0 <= part <= mask:
                raise ValueError(f"component bits {part:#x} exceed {t.bits} bits")
            codes.append(part)
    if t.bits != 12:
        width = t.bits // 8
        return b"".join(part.to_bytes(width, "little") for part in codes)
    # Pairs of 12-bit values in a little-endian 24-bit word: first in bits 0-11,
    # second in 12-23; an odd last value in 16 bits.
    out = bytearray()
    for index in range(0, len(codes) - 1, 2):
        out += (codes[index] | codes[index + 1] << 12).to_bytes(3, "little")
    if len(codes) % 2:
        out += codes[-1].to_bytes(2, "little")
    return bytes(out)


def decode_elements(t: WireType, payload: bytes) -> list[tuple[int, ...]]:
    count = payload_element_count(t, len(payload)) * t.components
    if t.bits == 12:
        codes = []
        offset = 0
        while len(codes) + 2 <= count:
            word = int.from_bytes(payload[offset:offset + 3], "little")
            codes += [word & 0xFFF, word >> 12 & 0xFFF]
            offset += 3
        if len(codes) < count:
            code = int.from_bytes(payload[offset:offset + 2], "little")
            if code & 0xF000:
                raise FormatError("unused bits of a 12-bit value are not zero")
            codes.append(code)
    else:
        width = t.bits // 8
        codes = [int.from_bytes(payload[i:i + width], "little") for i in range(0, count * width, width)]
    return [tuple(codes[i:i + t.components]) for i in range(0, count, t.components)]


# ---- component bits <-> Python numbers ----------------------------------------------

_FLOAT_FORMATS = {16: ("<e", "<H"), 32: ("<f", "<I"), 64: ("<d", "<Q")}


def _float128_to_float(bits: int) -> float:
    """Nearest binary64 value (exact whenever the value is representable)."""
    negative = bits >> 127
    exponent = bits >> 112 & 0x7FFF
    fraction = bits & ((1 << 112) - 1)
    if exponent == 0x7FFF:
        value = math.inf if fraction == 0 else math.nan
    elif exponent == 0:
        value = float(Fraction(fraction, 1 << (16382 + 112)))
    else:
        value = float(Fraction((1 << 112) | fraction) * Fraction(2) ** (exponent - 16383 - 112))
    return -value if negative else value


def _float_to_float128(value: float) -> int:
    """The exact binary128 bits of a binary64 value."""
    bits = struct.unpack("<Q", struct.pack("<d", value))[0]
    sign, exponent, fraction = bits >> 63, bits >> 52 & 0x7FF, bits & ((1 << 52) - 1)
    if exponent == 0x7FF:  # infinity, or NaN with its payload in the top fraction bits
        return sign << 127 | 0x7FFF << 112 | fraction << 60
    if exponent == 0:
        if fraction == 0:
            return sign << 127
        shift = 53 - fraction.bit_length()  # normalize a binary64 subnormal
        exponent, fraction = 1 - shift, (fraction << shift) & ((1 << 52) - 1)
    return sign << 127 | (exponent - 1023 + 16383) << 112 | fraction << 60


def component_value(t: WireType, bits: int):
    if t.kind == "uint":
        return bits
    if t.kind == "int":
        return bits - (1 << t.bits) if bits >> (t.bits - 1) else bits
    if t.bits == 128:
        return _float128_to_float(bits)
    value_format, bits_format = _FLOAT_FORMATS[t.bits]
    return struct.unpack(value_format, struct.pack(bits_format, bits))[0]


def component_bits(t: WireType, value) -> int:
    """No implicit conversion: an integer must be in range, a float exactly representable."""
    if t.kind in ("int", "uint"):
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"a {t.name} component must be an integer")
        low, high = (-(1 << (t.bits - 1)), (1 << (t.bits - 1)) - 1) if t.kind == "int" else (0, (1 << t.bits) - 1)
        if not low <= value <= high:
            raise ValueError(f"{value} is out of range for {t.name}")
        return value & ((1 << t.bits) - 1)
    value = float(value)
    if t.bits == 128:
        return _float_to_float128(value)
    value_format, bits_format = _FLOAT_FORMATS[t.bits]
    try:
        bits = struct.unpack(bits_format, struct.pack(value_format, value))[0]
    except OverflowError:
        raise ValueError(f"{value!r} is not representable in {t.name}") from None
    if not math.isnan(value) and component_value(t, bits) != value:
        raise ValueError(f"{value!r} is not representable in {t.name}")
    return bits


def values(t: WireType, elements) -> list:
    """Python numbers: one per element, or (re, im) pairs for complex types."""
    numbers = [tuple(component_value(t, part) for part in element) for element in elements]
    return numbers if t.complex else [element[0] for element in numbers]


def from_values(t: WireType, numbers) -> list[tuple[int, ...]]:
    return [tuple(component_bits(t, part) for part in (number if t.complex else (number,))) for number in numbers]


# ---- data packets and stream control messages ----------------------------------------

@dataclass
class DataPacket:
    type: WireType
    stream_alias: int
    sequence: int
    payload: bytes
    timestamps: list[tuple[int, int]] = field(default_factory=list)  # (role, nanoseconds); empty: no TIMESTAMPS
    send_time_ns: int | None = None  # SEND_TIME: UTC ns when the producer sealed the packet


def _u(value: int, size: int) -> bytes:
    return (value & ((1 << (8 * size)) - 1)).to_bytes(size, "little")


def _get(message: bytes, offset: int, size: int) -> int:
    return int.from_bytes(message[offset:offset + size], "little")


def _signed64(value: int) -> int:
    return value - (1 << 64) if value >> 63 else value


def encode_data_packet(packet: DataPacket) -> bytes:
    if len(packet.payload) > MAX_PAYLOAD_BYTES:
        raise FormatError("payload exceeds 256 KiB")
    payload_element_count(packet.type, len(packet.payload))
    has_extensions = bool(packet.timestamps) or packet.send_time_ns is not None
    out = bytearray([DATA_VERSION, FLAG_EXTENSIONS if has_extensions else 0])
    out += _u(packet.type.id, 2) + _u(packet.stream_alias, 4) + _u(packet.sequence, 8)
    if has_extensions:
        records = sorted(packet.timestamps, key=lambda record: record[0])
        if any(a[0] == b[0] for a, b in zip(records, records[1:])):
            raise FormatError("a timestamp role appears twice")
        # u16 length of the TLV records, the records in ascending type order, zero padding to a multiple of 8.
        timestamps_length = 4 + 1 + 9 * len(records) if records else 0
        send_time_length = 4 + 8 if packet.send_time_ns is not None else 0
        out += _u(send_time_length + timestamps_length, 2)
        if packet.send_time_ns is not None:
            out += _u(SEND_TIME_EXTENSION, 2) + _u(8, 2) + _u(packet.send_time_ns, 8)
        if records:
            out += _u(TIMESTAMPS_EXTENSION, 2) + _u(1 + 9 * len(records), 2) + bytes([len(records)])
            for role, nanoseconds in records:
                out += bytes([role]) + _u(nanoseconds, 8)
        out += bytes(-(len(out) - DATA_HEADER_BYTES) % 8)
    return bytes(out) + packet.payload


def decode_data_packet(message: bytes) -> DataPacket:
    """Validates and decodes; raises FormatError."""
    if len(message) < DATA_HEADER_BYTES:
        raise FormatError("message shorter than the 16-byte header")
    if message[0] != DATA_VERSION:
        raise FormatError(f"unsupported data packet version {message[0]}")
    flags = message[1]
    if flags & ~FLAG_EXTENSIONS:
        raise FormatError("reserved flag bits are set")
    type_id = _get(message, 2, 2)
    if type_id not in TYPES_BY_ID:
        raise FormatError(f"unknown data type {type_id}")
    packet = DataPacket(TYPES_BY_ID[type_id], _get(message, 4, 4), _get(message, 8, 8), b"")

    payload_offset = DATA_HEADER_BYTES
    if flags & FLAG_EXTENSIONS:
        if len(message) < DATA_HEADER_BYTES + 2:
            raise FormatError("extension area is truncated")
        tlv_length = _get(message, DATA_HEADER_BYTES, 2)
        area = (2 + tlv_length + 7) // 8 * 8
        if DATA_HEADER_BYTES + area > len(message):
            raise FormatError("extension area exceeds the message")
        if any(message[DATA_HEADER_BYTES + 2 + tlv_length:DATA_HEADER_BYTES + area]):
            raise FormatError("extension padding is not zero")
        offset = DATA_HEADER_BYTES + 2
        end = offset + tlv_length
        seen_timestamps = False
        while offset < end:
            if offset + 4 > end:
                raise FormatError("truncated extension record")
            ext_type, ext_length = _get(message, offset, 2), _get(message, offset + 2, 2)
            offset += 4
            if offset + ext_length > end:
                raise FormatError("extension record exceeds the extension area")
            if ext_type == TIMESTAMPS_EXTENSION:
                if seen_timestamps:
                    raise FormatError("TIMESTAMPS extension appears twice")
                seen_timestamps = True
                if ext_length < 1:
                    raise FormatError("TIMESTAMPS extension is empty")
                count = message[offset]
                if ext_length != 1 + 9 * count:
                    raise FormatError("TIMESTAMPS length does not match its record count")
                for index in range(count):
                    base = offset + 1 + 9 * index
                    role = message[base]
                    if not 1 <= role <= 3:
                        raise FormatError(f"unknown timestamp role {role}")
                    if packet.timestamps and role <= packet.timestamps[-1][0]:
                        raise FormatError("timestamp roles are not in ascending order")
                    packet.timestamps.append((role, _signed64(_get(message, base + 1, 8))))
            elif ext_type == SEND_TIME_EXTENSION:
                if packet.send_time_ns is not None:
                    raise FormatError("SEND_TIME extension appears twice")
                if ext_length != 8:
                    raise FormatError("SEND_TIME extension is not 8 bytes")
                packet.send_time_ns = _signed64(_get(message, offset, 8))
            elif ext_type & CRITICAL_EXTENSION_BIT:
                raise FormatError(f"unknown critical extension {ext_type}")
            offset += ext_length
        payload_offset = DATA_HEADER_BYTES + area

    payload = bytes(message[payload_offset:])
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise FormatError("payload exceeds 256 KiB")
    payload_element_count(packet.type, len(payload))
    if not payload:
        raise FormatError("payload is empty")
    # An odd final 12-bit value occupies 16 bits whose top 4 bits must be zero.
    if packet.type.bits == 12 and len(payload) % 3 == 2 and payload[-1] & 0xF0:
        raise FormatError("unused bits of a 12-bit value are not zero")
    packet.payload = payload
    return packet


@dataclass(frozen=True)
class ControlMessage:
    kind: int  # ACK, RESUME or RESUME_NO_STATE (consumer -> producer)
    stream_alias: int
    next_expected: int
    stream_id: bytes = bytes(16)  # RFC 4122 byte order; zero in an ACK


def encode_control_message(message: ControlMessage) -> bytes:
    return (bytes([CONTROL_VERSION, message.kind]) + _u(0, 2) + _u(message.stream_alias, 4)
            + _u(message.next_expected, 8) + bytes(message.stream_id))


def decode_control_message(message: bytes) -> ControlMessage:
    if len(message) != CONTROL_MESSAGE_BYTES:
        raise FormatError("stream control message must be 32 bytes")
    if message[0] != CONTROL_VERSION:
        raise FormatError("not a stream control message")
    kind = message[1]
    if not 1 <= kind <= 3:
        raise FormatError(f"unknown stream control kind {kind}")
    if _get(message, 2, 2):
        raise FormatError("reserved field is not zero")
    return ControlMessage(kind, _get(message, 4, 4), _get(message, 8, 8), bytes(message[16:32]))


def is_control_message(message: bytes) -> bool:
    """A stream control message or a data packet, by the version byte."""
    return len(message) > 0 and message[0] == CONTROL_VERSION


# ---- stream ids ------------------------------------------------------------------------

def parse_stream_id(text: str) -> bytes:
    try:
        return uuid.UUID(text).bytes
    except (ValueError, TypeError, AttributeError):
        raise ValueError(f"Invalid stream id (expected a UUID): '{text}'.") from None


def stream_id_text(stream_id: bytes) -> str:
    return str(uuid.UUID(bytes=bytes(stream_id)))


def random_stream_id() -> bytes:
    """A version 4 UUID from the operating system's CSPRNG."""
    return uuid.uuid4().bytes

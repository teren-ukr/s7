// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.wire;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/**
 * The S7 data stream wire format, version 1 (doc/S7_Network_Wire_Protocol_v1.md, sections 7, 8 and 12.1).
 *
 * <p>Mirrors s7transport's wire_format.cpp: the same encoding and the same checks in the same order.
 * Every multi-byte field and value is little-endian, written byte by byte.
 *
 * <p>A payload holds elements of one wire type; each element is an array of component bit
 * patterns (one component, or real and imaginary / in-phase and quadrature) as unsigned
 * BigIntegers of the component's width: two's complement for signed integers, the IEEE
 * interchange bits for floating point. Bits travel unchanged, so NaN payloads, infinities
 * and signed zeros are preserved; {@link #values} and {@link #fromValues} convert to and
 * from Java numbers.
 */
public final class WireFormat {
    public static final int DATA_VERSION = 1;
    public static final int CONTROL_VERSION = 0x80 | 1;
    public static final int DATA_HEADER_BYTES = 16;
    public static final int CONTROL_MESSAGE_BYTES = 32;
    public static final int MAX_PAYLOAD_BYTES = 256 * 1024;
    public static final int FLAG_EXTENSIONS = 0x01;
    public static final int TIMESTAMPS_EXTENSION = 0x8001; // critical
    public static final int SEND_TIME_EXTENSION = 0x0002; // noncritical: when the producer sealed the packet
    public static final int CRITICAL_EXTENSION_BIT = 0x8000;

    public static final int MODEL_TIME = 1;
    public static final int SOURCE_TIME = 2;
    public static final int PROCESSING_TIME = 3;

    public static final int ACK = 1;
    public static final int RESUME = 2;
    public static final int RESUME_NO_STATE = 3;

    private WireFormat() {
    }

    /** A malformed or unsupported message; the receiver drops it and reports a fault. */
    public static final class FormatError extends RuntimeException {
        private static final long serialVersionUID = 1L;

        public FormatError(String message) {
            super(message);
        }
    }

    public static String roleName(int role) {
        return switch (role) {
            case MODEL_TIME -> "MODEL_TIME";
            case SOURCE_TIME -> "SOURCE_TIME";
            case PROCESSING_TIME -> "PROCESSING_TIME";
            default -> throw new IllegalArgumentException("unknown timestamp role " + role);
        };
    }

    public static int parseRole(String name) {
        return switch (name) {
            case "MODEL_TIME" -> MODEL_TIME;
            case "SOURCE_TIME" -> SOURCE_TIME;
            case "PROCESSING_TIME" -> PROCESSING_TIME;
            default -> throw new IllegalArgumentException(
                    "Unknown timestamp role '" + name + "' (MODEL_TIME, SOURCE_TIME or PROCESSING_TIME).");
        };
    }

    public record TimestampRecord(int role, long nanoseconds) {
    }

    /** sequence is an unsigned 64-bit number and streamAlias an unsigned 32-bit one, both held in a long. */
    public record DataPacket(WireType type, long streamAlias, long sequence, byte[] payload,
                             List<TimestampRecord> timestamps, Long sendTimeNs) {
        public DataPacket(WireType type, long streamAlias, long sequence, byte[] payload) {
            this(type, streamAlias, sequence, payload, List.of(), null);
        }
    }

    /** Consumer to producer: ACK, RESUME or RESUME_NO_STATE. streamId is 16 bytes, zero in an ACK. */
    public record ControlMessage(int kind, long streamAlias, long nextExpected, byte[] streamId) {
    }

    // ---- payloads -------------------------------------------------------------------

    private static int packed12Bytes(int values) {
        return 3 * (values / 2) + 2 * (values % 2);
    }

    public static int payloadBytes(WireType t, int count) {
        int values = count * t.components();
        return t.bits == 12 ? packed12Bytes(values) : values * (t.bits / 8);
    }

    public static int payloadElementCount(WireType t, int size) {
        int values;
        if (t.bits == 12) {
            if (size % 3 == 1) {
                throw new FormatError("payload length is not a whole number of 12-bit values");
            }
            values = (size / 3) * 2 + (size % 3 == 2 ? 1 : 0);
        } else {
            if (size % (t.bits / 8) != 0) {
                throw new FormatError("payload length is not a whole number of " + t.name() + " values");
            }
            values = size / (t.bits / 8);
        }
        if (values % t.components() != 0) {
            throw new FormatError("payload holds an incomplete complex value");
        }
        return values / t.components();
    }

    public static byte[] encodeElements(WireType t, List<BigInteger[]> elements) {
        BigInteger limit = BigInteger.ONE.shiftLeft(t.bits);
        List<BigInteger> codes = new ArrayList<>();
        for (BigInteger[] element : elements) {
            if (element.length != t.components()) {
                throw new IllegalArgumentException("a " + t.name() + " element has " + t.components() + " component(s)");
            }
            for (BigInteger part : element) {
                if (part.signum() < 0 || part.compareTo(limit) >= 0) {
                    throw new IllegalArgumentException("component bits exceed " + t.bits + " bits");
                }
                codes.add(part);
            }
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        if (t.bits != 12) {
            for (BigInteger part : codes) {
                putLe(out, part, t.bits / 8);
            }
            return out.toByteArray();
        }
        // Pairs of 12-bit values in a little-endian 24-bit word: first in bits 0-11,
        // second in 12-23; an odd last value in 16 bits.
        int index = 0;
        for (; index + 1 < codes.size(); index += 2) {
            long word = codes.get(index).longValue() | codes.get(index + 1).longValue() << 12;
            putLe(out, word, 3);
        }
        if (index < codes.size()) {
            putLe(out, codes.get(index).longValue(), 2);
        }
        return out.toByteArray();
    }

    public static List<BigInteger[]> decodeElements(WireType t, byte[] payload) {
        int count = payloadElementCount(t, payload.length) * t.components();
        List<BigInteger> codes = new ArrayList<>(count);
        if (t.bits == 12) {
            int offset = 0;
            while (codes.size() + 2 <= count) {
                long word = getLe(payload, offset, 3);
                codes.add(BigInteger.valueOf(word & 0xFFF));
                codes.add(BigInteger.valueOf(word >> 12 & 0xFFF));
                offset += 3;
            }
            if (codes.size() < count) {
                long code = getLe(payload, offset, 2);
                if ((code & 0xF000) != 0) {
                    throw new FormatError("unused bits of a 12-bit value are not zero");
                }
                codes.add(BigInteger.valueOf(code));
            }
        } else {
            int width = t.bits / 8;
            for (int offset = 0; offset < count * width; offset += width) {
                codes.add(getLeBig(payload, offset, width));
            }
        }
        List<BigInteger[]> elements = new ArrayList<>();
        for (int index = 0; index < count; index += t.components()) {
            elements.add(codes.subList(index, index + t.components()).toArray(new BigInteger[0]));
        }
        return elements;
    }

    // ---- component bits <-> Java numbers ---------------------------------------------

    /** Long or BigInteger for integer types, Double for floating point (binary128: the nearest binary64). */
    public static Number componentValue(WireType t, BigInteger bits) {
        switch (t.kind) {
            case UINT:
                return t.bits < 64 ? (Number) bits.longValue() : bits;
            case INT: {
                BigInteger value = bits.testBit(t.bits - 1) ? bits.subtract(BigInteger.ONE.shiftLeft(t.bits)) : bits;
                return t.bits <= 64 ? (Number) value.longValue() : value;
            }
            default:
                return switch (t.bits) {
                    case 16 -> (double) Float.float16ToFloat((short) bits.intValue());
                    case 32 -> (double) Float.intBitsToFloat(bits.intValue());
                    case 64 -> Double.longBitsToDouble(bits.longValue());
                    default -> float128ToDouble(bits);
                };
        }
    }

    /** No implicit conversion: an integer must be in range, a float exactly representable. */
    public static BigInteger componentBits(WireType t, Number value) {
        if (t.kind != WireType.Kind.FLOAT) {
            if (!(value instanceof Long || value instanceof Integer || value instanceof BigInteger)) {
                throw new IllegalArgumentException("a " + t.name() + " component must be an integer");
            }
            BigInteger v = value instanceof BigInteger b ? b : BigInteger.valueOf(value.longValue());
            BigInteger low = t.kind == WireType.Kind.INT ? BigInteger.ONE.shiftLeft(t.bits - 1).negate() : BigInteger.ZERO;
            BigInteger high = (t.kind == WireType.Kind.INT ? BigInteger.ONE.shiftLeft(t.bits - 1) : BigInteger.ONE.shiftLeft(t.bits))
                    .subtract(BigInteger.ONE);
            if (v.compareTo(low) < 0 || v.compareTo(high) > 0) {
                throw new IllegalArgumentException(v + " is out of range for " + t.name());
            }
            return v.signum() < 0 ? v.add(BigInteger.ONE.shiftLeft(t.bits)) : v;
        }
        double d = value.doubleValue();
        BigInteger bits;
        switch (t.bits) {
            case 16 -> {
                short h = Float.floatToFloat16((float) d);
                bits = BigInteger.valueOf(h & 0xFFFF);
                if (!Double.isNaN(d) && (double) Float.float16ToFloat(h) != d) {
                    throw new IllegalArgumentException(d + " is not representable in " + t.name());
                }
            }
            case 32 -> {
                float f = (float) d;
                bits = BigInteger.valueOf(Float.floatToRawIntBits(f) & 0xFFFFFFFFL);
                if (!Double.isNaN(d) && (double) f != d) {
                    throw new IllegalArgumentException(d + " is not representable in " + t.name());
                }
            }
            case 64 -> bits = new BigInteger(Long.toUnsignedString(Double.doubleToRawLongBits(d)));
            default -> bits = doubleToFloat128(d);
        }
        return bits;
    }

    /** One Number per element, or a Number[]{re, im} for complex types. */
    public static List<Object> values(WireType t, List<BigInteger[]> elements) {
        List<Object> out = new ArrayList<>();
        for (BigInteger[] element : elements) {
            if (t.complex) {
                out.add(new Number[]{componentValue(t, element[0]), componentValue(t, element[1])});
            } else {
                out.add(componentValue(t, element[0]));
            }
        }
        return out;
    }

    public static List<BigInteger[]> fromValues(WireType t, List<?> numbers) {
        List<BigInteger[]> out = new ArrayList<>();
        for (Object number : numbers) {
            if (t.complex) {
                Object[] parts = number instanceof List<?> list ? list.toArray() : (Object[]) number;
                out.add(new BigInteger[]{componentBits(t, (Number) parts[0]), componentBits(t, (Number) parts[1])});
            } else {
                out.add(new BigInteger[]{componentBits(t, (Number) number)});
            }
        }
        return out;
    }

    /** Nearest binary64 value (ties to even), exact whenever the value is representable. */
    static double float128ToDouble(BigInteger bits) {
        boolean negative = bits.testBit(127);
        int exponent = bits.shiftRight(112).intValue() & 0x7FFF;
        BigInteger fraction = bits.and(BigInteger.ONE.shiftLeft(112).subtract(BigInteger.ONE));
        double magnitude;
        if (exponent == 0x7FFF) {
            magnitude = fraction.signum() == 0 ? Double.POSITIVE_INFINITY : Double.NaN;
        } else {
            BigInteger m = exponent == 0 ? fraction : fraction.setBit(112);
            int e = (exponent == 0 ? 1 : exponent) - 16383 - 112; // value = m * 2^e
            if (m.signum() == 0) {
                magnitude = 0.0;
            } else {
                // keep 53 significant bits, and none below 2^-1074 (binary64 subnormals)
                int shift = Math.max(m.bitLength() - 53, -1074 - e);
                if (shift > 0) {
                    BigInteger kept = m.shiftRight(shift);
                    BigInteger rest = m.subtract(kept.shiftLeft(shift));
                    int half = rest.compareTo(BigInteger.ONE.shiftLeft(shift - 1));
                    if (half > 0 || (half == 0 && kept.testBit(0))) {
                        kept = kept.add(BigInteger.ONE);
                    }
                    m = kept;
                    e += shift;
                }
                magnitude = e > 1100 ? Double.POSITIVE_INFINITY : Math.scalb(m.doubleValue(), e);
            }
        }
        return negative ? -magnitude : magnitude;
    }

    /** The exact binary128 bits of a binary64 value. */
    static BigInteger doubleToFloat128(double value) {
        long bits = Double.doubleToRawLongBits(value);
        long sign = bits >>> 63;
        int exponent = (int) (bits >>> 52 & 0x7FF);
        long fraction = bits & ((1L << 52) - 1);
        BigInteger out;
        if (exponent == 0x7FF) { // infinity, or NaN with its payload in the top fraction bits
            out = BigInteger.valueOf(0x7FFF).shiftLeft(112).or(BigInteger.valueOf(fraction).shiftLeft(60));
        } else if (exponent == 0 && fraction == 0) {
            out = BigInteger.ZERO;
        } else {
            if (exponent == 0) { // normalize a binary64 subnormal
                int shift = 53 - (64 - Long.numberOfLeadingZeros(fraction));
                exponent = 1 - shift;
                fraction = (fraction << shift) & ((1L << 52) - 1);
            }
            out = BigInteger.valueOf(exponent - 1023 + 16383).shiftLeft(112).or(BigInteger.valueOf(fraction).shiftLeft(60));
        }
        return sign == 1 ? out.setBit(127) : out;
    }

    // ---- data packets and stream control messages -------------------------------------

    public static byte[] encodeDataPacket(DataPacket packet) {
        if (packet.payload().length > MAX_PAYLOAD_BYTES) {
            throw new FormatError("payload exceeds 256 KiB");
        }
        payloadElementCount(packet.type(), packet.payload().length);
        boolean extensions = !packet.timestamps().isEmpty() || packet.sendTimeNs() != null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(DATA_VERSION);
        out.write(extensions ? FLAG_EXTENSIONS : 0);
        putLe(out, packet.type().id, 2);
        putLe(out, packet.streamAlias(), 4);
        putLe(out, packet.sequence(), 8);
        if (extensions) {
            List<TimestampRecord> records = new ArrayList<>(packet.timestamps());
            records.sort(Comparator.comparingInt(TimestampRecord::role));
            for (int index = 1; index < records.size(); index++) {
                if (records.get(index).role() == records.get(index - 1).role()) {
                    throw new FormatError("a timestamp role appears twice");
                }
            }
            // u16 length of the TLV records, the records in ascending type order, zero padding to a multiple of 8.
            int timestampsLength = records.isEmpty() ? 0 : 4 + 1 + 9 * records.size();
            int sendTimeLength = packet.sendTimeNs() != null ? 4 + 8 : 0;
            putLe(out, sendTimeLength + timestampsLength, 2);
            if (packet.sendTimeNs() != null) {
                putLe(out, SEND_TIME_EXTENSION, 2);
                putLe(out, 8, 2);
                putLe(out, packet.sendTimeNs(), 8);
            }
            if (!records.isEmpty()) {
                putLe(out, TIMESTAMPS_EXTENSION, 2);
                putLe(out, 1 + 9 * records.size(), 2);
                out.write(records.size());
                for (TimestampRecord record : records) {
                    out.write(record.role());
                    putLe(out, record.nanoseconds(), 8);
                }
            }
            while ((out.size() - DATA_HEADER_BYTES) % 8 != 0) {
                out.write(0);
            }
        }
        out.writeBytes(packet.payload());
        return out.toByteArray();
    }

    /** Validates and decodes; throws FormatError. */
    public static DataPacket decodeDataPacket(byte[] message) {
        if (message.length < DATA_HEADER_BYTES) {
            throw new FormatError("message shorter than the 16-byte header");
        }
        int version = message[0] & 0xFF;
        if (version != DATA_VERSION) {
            throw new FormatError("unsupported data packet version " + version);
        }
        int flags = message[1] & 0xFF;
        if ((flags & ~FLAG_EXTENSIONS) != 0) {
            throw new FormatError("reserved flag bits are set");
        }
        int typeId = (int) getLe(message, 2, 2);
        WireType type = WireType.byId(typeId);
        if (type == null) {
            throw new FormatError("unknown data type " + typeId);
        }
        long alias = getLe(message, 4, 4);
        long sequence = getLe(message, 8, 8);
        List<TimestampRecord> timestamps = new ArrayList<>();
        Long sendTime = null;

        int payloadOffset = DATA_HEADER_BYTES;
        if ((flags & FLAG_EXTENSIONS) != 0) {
            if (message.length < DATA_HEADER_BYTES + 2) {
                throw new FormatError("extension area is truncated");
            }
            int tlvLength = (int) getLe(message, DATA_HEADER_BYTES, 2);
            int area = (2 + tlvLength + 7) / 8 * 8;
            if (DATA_HEADER_BYTES + area > message.length) {
                throw new FormatError("extension area exceeds the message");
            }
            for (int pad = DATA_HEADER_BYTES + 2 + tlvLength; pad < DATA_HEADER_BYTES + area; pad++) {
                if (message[pad] != 0) {
                    throw new FormatError("extension padding is not zero");
                }
            }
            int offset = DATA_HEADER_BYTES + 2;
            int end = offset + tlvLength;
            boolean seenTimestamps = false;
            while (offset < end) {
                if (offset + 4 > end) {
                    throw new FormatError("truncated extension record");
                }
                int extType = (int) getLe(message, offset, 2);
                int extLength = (int) getLe(message, offset + 2, 2);
                offset += 4;
                if (offset + extLength > end) {
                    throw new FormatError("extension record exceeds the extension area");
                }
                if (extType == TIMESTAMPS_EXTENSION) {
                    if (seenTimestamps) {
                        throw new FormatError("TIMESTAMPS extension appears twice");
                    }
                    seenTimestamps = true;
                    if (extLength < 1) {
                        throw new FormatError("TIMESTAMPS extension is empty");
                    }
                    int count = message[offset] & 0xFF;
                    if (extLength != 1 + 9 * count) {
                        throw new FormatError("TIMESTAMPS length does not match its record count");
                    }
                    for (int index = 0; index < count; index++) {
                        int base = offset + 1 + 9 * index;
                        int role = message[base] & 0xFF;
                        if (role < 1 || role > 3) {
                            throw new FormatError("unknown timestamp role " + role);
                        }
                        if (!timestamps.isEmpty() && role <= timestamps.get(timestamps.size() - 1).role()) {
                            throw new FormatError("timestamp roles are not in ascending order");
                        }
                        timestamps.add(new TimestampRecord(role, getLe(message, base + 1, 8)));
                    }
                } else if (extType == SEND_TIME_EXTENSION) {
                    if (sendTime != null) {
                        throw new FormatError("SEND_TIME extension appears twice");
                    }
                    if (extLength != 8) {
                        throw new FormatError("SEND_TIME extension is not 8 bytes");
                    }
                    sendTime = getLe(message, offset, 8);
                } else if ((extType & CRITICAL_EXTENSION_BIT) != 0) {
                    throw new FormatError("unknown critical extension " + extType);
                }
                offset += extLength;
            }
            payloadOffset = DATA_HEADER_BYTES + area;
        }

        byte[] payload = java.util.Arrays.copyOfRange(message, payloadOffset, message.length);
        if (payload.length > MAX_PAYLOAD_BYTES) {
            throw new FormatError("payload exceeds 256 KiB");
        }
        payloadElementCount(type, payload.length);
        if (payload.length == 0) {
            throw new FormatError("payload is empty");
        }
        // An odd final 12-bit value occupies 16 bits whose top 4 bits must be zero.
        if (type.bits == 12 && payload.length % 3 == 2 && (payload[payload.length - 1] & 0xF0) != 0) {
            throw new FormatError("unused bits of a 12-bit value are not zero");
        }
        return new DataPacket(type, alias, sequence, payload, List.copyOf(timestamps), sendTime);
    }

    public static byte[] encodeControlMessage(ControlMessage message) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(CONTROL_VERSION);
        out.write(message.kind());
        putLe(out, 0, 2);
        putLe(out, message.streamAlias(), 4);
        putLe(out, message.nextExpected(), 8);
        out.writeBytes(message.streamId() == null ? new byte[16] : message.streamId());
        return out.toByteArray();
    }

    public static ControlMessage decodeControlMessage(byte[] message) {
        if (message.length != CONTROL_MESSAGE_BYTES) {
            throw new FormatError("stream control message must be 32 bytes");
        }
        if ((message[0] & 0xFF) != CONTROL_VERSION) {
            throw new FormatError("not a stream control message");
        }
        int kind = message[1] & 0xFF;
        if (kind < 1 || kind > 3) {
            throw new FormatError("unknown stream control kind " + kind);
        }
        if (getLe(message, 2, 2) != 0) {
            throw new FormatError("reserved field is not zero");
        }
        return new ControlMessage(kind, getLe(message, 4, 4), getLe(message, 8, 8),
                java.util.Arrays.copyOfRange(message, 16, 32));
    }

    /** A stream control message or a data packet, by the version byte. */
    public static boolean isControlMessage(byte[] message) {
        return message.length > 0 && (message[0] & 0xFF) == CONTROL_VERSION;
    }

    // ---- stream ids ----------------------------------------------------------------------

    public static byte[] parseStreamId(String text) {
        UUID id;
        try {
            if (text.length() != 36) {
                throw new IllegalArgumentException();
            }
            id = UUID.fromString(text);
            if (!id.toString().equalsIgnoreCase(text)) { // UUID.fromString accepts short groups
                throw new IllegalArgumentException();
            }
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException("Invalid stream id (expected a UUID): '" + text + "'.");
        }
        return ByteBuffer.allocate(16).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).array();
    }

    public static String streamIdText(byte[] id) {
        ByteBuffer buffer = ByteBuffer.wrap(id);
        return new UUID(buffer.getLong(), buffer.getLong()).toString();
    }

    /** A version 4 UUID from the platform's CSPRNG (SecureRandom). */
    public static byte[] randomStreamId() {
        UUID id = UUID.randomUUID();
        return ByteBuffer.allocate(16).putLong(id.getMostSignificantBits()).putLong(id.getLeastSignificantBits()).array();
    }

    // ---- little-endian primitives ---------------------------------------------------------

    private static void putLe(ByteArrayOutputStream out, long value, int size) {
        for (int index = 0; index < size; index++) {
            out.write((int) (value >>> (8 * index)) & 0xFF);
        }
    }

    private static void putLe(ByteArrayOutputStream out, BigInteger value, int size) {
        for (int index = 0; index < size; index++) {
            out.write(value.shiftRight(8 * index).intValue() & 0xFF);
        }
    }

    private static long getLe(byte[] bytes, int offset, int size) {
        long value = 0;
        for (int index = size; index-- > 0; ) {
            value = value << 8 | (bytes[offset + index] & 0xFF);
        }
        return value;
    }

    private static BigInteger getLeBig(byte[] bytes, int offset, int size) {
        byte[] big = new byte[size + 1]; // leading zero byte: unsigned
        for (int index = 0; index < size; index++) {
            big[size - index] = bytes[offset + index];
        }
        return new BigInteger(big);
    }
}

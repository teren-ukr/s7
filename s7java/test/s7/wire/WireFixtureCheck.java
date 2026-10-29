// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.wire;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import s7.json.Json;
import s7.stream.StreamDescriptor;
import s7.wire.WireFormat.DataPacket;
import s7.wire.WireFormat.FormatError;
import s7.wire.WireFormat.TimestampRecord;

/**
 * The shared conformance fixtures (s7l2/s7transport/tests/fixtures/wire_v1.json): every valid packet
 * and control message decodes to the fixture's fields and encodes to exactly its bytes, every
 * invalid one is rejected, and stream descriptors read to their canonical form or are refused.
 *
 * <p>Usage: java -cp build s7.wire.WireFixtureCheck [wire_v1.json]
 */
public final class WireFixtureCheck {
    private static final HexFormat HEX = HexFormat.of();
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        Path path = Path.of(args.length > 0 ? args[0] : "../s7l2/s7transport/tests/fixtures/wire_v1.json");
        @SuppressWarnings("unchecked")
        Map<String, Object> fixtures = (Map<String, Object>) Json.parse(Files.readString(path));
        int total = 0;

        for (Map<String, Object> c : cases(fixtures, "data")) {
            total++;
            check(c, () -> {
                byte[] message = HEX.parseHex((String) c.get("hex"));
                DataPacket packet = WireFormat.decodeDataPacket(message);
                List<TimestampRecord> expectedTimes = new ArrayList<>();
                for (Object t : (List<?>) c.get("timestamps")) {
                    Map<?, ?> record = (Map<?, ?>) t;
                    expectedTimes.add(new TimestampRecord(WireFormat.parseRole((String) record.get("role")), (Long) record.get("ns")));
                }
                expectedTimes.sort((a, b) -> Integer.compare(a.role(), b.role()));
                Object sendTime = c.get("send_time_ns");
                Long expectedSendTime = sendTime == Json.NULL ? null : (Long) sendTime;
                if (!packet.type().name().equals(c.get("type")) || packet.streamAlias() != (Long) c.get("stream_alias")
                        || packet.sequence() != (Long) c.get("sequence") || !packet.timestamps().equals(expectedTimes)
                        || !java.util.Objects.equals(packet.sendTimeNs(), expectedSendTime)) {
                    return "decoded " + packet;
                }
                List<Object> decoded = WireFormat.values(packet.type(), WireFormat.decodeElements(packet.type(), packet.payload()));
                if (!same(c.get("values"), decoded)) {
                    return "decoded values " + decoded;
                }
                List<BigInteger[]> elements = WireFormat.fromValues(packet.type(), numbers(packet.type(), (List<?>) c.get("values")));
                byte[] rebuilt = WireFormat.encodeDataPacket(new DataPacket(packet.type(), packet.streamAlias(), packet.sequence(),
                        WireFormat.encodeElements(packet.type(), elements), expectedTimes, expectedSendTime));
                return HEX.formatHex(rebuilt).equals(c.get("hex")) ? null : "encoded " + HEX.formatHex(rebuilt);
            });
        }
        for (Map<String, Object> c : cases(fixtures, "data_ignoring_extensions")) {
            total++;
            check(c, () -> {
                DataPacket packet = WireFormat.decodeDataPacket(HEX.parseHex((String) c.get("hex")));
                List<Object> decoded = WireFormat.values(packet.type(), WireFormat.decodeElements(packet.type(), packet.payload()));
                return packet.type().name().equals(c.get("type")) && same(c.get("values"), decoded) ? null : "decoded " + decoded;
            });
        }
        for (Map<String, Object> c : cases(fixtures, "control")) {
            total++;
            check(c, () -> {
                WireFormat.ControlMessage m = WireFormat.decodeControlMessage(HEX.parseHex((String) c.get("hex")));
                Object id = c.get("stream_id");
                String streamId = m.kind() == WireFormat.ACK ? null : WireFormat.streamIdText(m.streamId());
                boolean fields = m.kind() == (Long) c.get("kind") && m.streamAlias() == (Long) c.get("stream_alias")
                        && m.nextExpected() == (Long) c.get("next_expected") && java.util.Objects.equals(streamId, id == Json.NULL ? null : id);
                String encoded = HEX.formatHex(WireFormat.encodeControlMessage(m));
                return fields && encoded.equals(c.get("hex")) ? null : "decoded " + m + ", encoded " + encoded;
            });
        }
        for (Map<String, Object> c : cases(fixtures, "invalid")) {
            total++;
            byte[] message = HEX.parseHex((String) c.get("hex"));
            try {
                if (WireFormat.isControlMessage(message)) {
                    WireFormat.decodeControlMessage(message);
                } else {
                    DataPacket packet = WireFormat.decodeDataPacket(message);
                    WireFormat.decodeElements(packet.type(), packet.payload());
                }
                failures.add(c.get("name") + ": accepted (" + c.get("reason") + ")");
            } catch (FormatError expected) {
                // rejected, as it must be
            }
        }
        for (Map<String, Object> c : cases(fixtures, "descriptors")) {
            total++;
            check(c, () -> {
                Map<String, Object> canonical = StreamDescriptor.fromJson(c.get("descriptor")).toJson();
                return canonical.equals(c.get("canonical")) ? null : "read as " + Json.write(canonical); // members in any order
            });
        }
        for (Map<String, Object> c : cases(fixtures, "invalid_descriptors")) {
            total++;
            try {
                StreamDescriptor.fromJson(c.get("descriptor"));
                failures.add("descriptor " + c.get("name") + ": accepted (" + c.get("reason") + ")");
            } catch (IllegalArgumentException expected) {
                // refused, as it must be
            }
        }
        for (String failure : failures) {
            System.out.println("FAIL " + failure);
        }
        System.out.println((total - failures.size()) + " of " + total + " fixtures pass");
        System.exit(failures.isEmpty() ? 0 : 1);
    }

    interface Check {
        String run();
    }

    private static void check(Map<String, Object> c, Check check) {
        try {
            String problem = check.run();
            if (problem != null) {
                failures.add(c.get("name") + ": " + problem);
            }
        } catch (RuntimeException ex) {
            failures.add(c.get("name") + ": " + ex);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> cases(Map<String, Object> fixtures, String section) {
        return (List<Map<String, Object>>) fixtures.get(section);
    }

    /** Fixture values: integers beyond 53 bits as decimal strings, complex values as [re, im]. */
    private static List<Object> numbers(WireType t, List<?> values) {
        List<Object> out = new ArrayList<>();
        for (Object v : values) {
            if (t.complex) {
                List<?> pair = (List<?>) v;
                out.add(new Number[]{number(pair.get(0)), number(pair.get(1))});
            } else {
                out.add(number(v));
            }
        }
        return out;
    }

    private static Number number(Object v) {
        if (v instanceof String s) {
            BigInteger b = new BigInteger(s);
            return b.bitLength() < 64 ? (Number) b.longValue() : b;
        }
        return (Number) v;
    }

    /** Integers by value, floating-point values to the bit (the sign of zero included). */
    private static boolean same(Object expected, Object actual) {
        if (expected instanceof List<?> list) {
            Object[] items = actual instanceof List<?> a ? a.toArray() : actual instanceof Object[] a ? a : null;
            if (items == null || items.length != list.size()) {
                return false;
            }
            for (int index = 0; index < items.length; index++) {
                if (!same(list.get(index), items[index])) {
                    return false;
                }
            }
            return true;
        }
        if (expected instanceof String s) {
            return actual instanceof Number n && new BigInteger(s).equals(big(n));
        }
        if (expected instanceof Double || actual instanceof Double) {
            return Double.doubleToRawLongBits(((Number) expected).doubleValue()) == Double.doubleToRawLongBits(((Number) actual).doubleValue());
        }
        return actual instanceof Number n && big((Number) expected).equals(big(n));
    }

    private static BigInteger big(Number n) {
        return n instanceof BigInteger b ? b : BigInteger.valueOf(n.longValue());
    }
}

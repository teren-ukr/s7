// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.stream;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import s7.wire.WireFormat;
import s7.wire.WireType;

/**
 * A stream of a deployed diagram (S7_Network_Wire_Protocol_v1.md section 12.1 item 1), read as
 * s7net's diagram_deployment.cpp parse_streams() reads it.
 */
public final class StreamDescriptor {
    public record End(String nodeUuid, String element, long port) {
    }

    public record TimestampDeclaration(int role, String clockDomain) {
    }

    private static final long UINT32_MAX = 0xFFFFFFFFL;

    public byte[] streamId;
    public End producer;
    public List<End> consumers = new ArrayList<>();
    public WireType dataType;
    public long maxElementsPerPacket = 1024;
    public long maxBatchLatencyMs = 10;
    public long sendLogMaxPackets = 4096;
    public long maxBlockMs = 2000;
    public long maxWaitMs = 2000;
    public long[] sampleRate; // {numerator, denominator}: uniformly sampled; null otherwise
    public List<TimestampDeclaration> timestamps = new ArrayList<>();
    public Long maxLatencyMs;

    public static StreamDescriptor fromJson(Object value) {
        if (!(value instanceof Map<?, ?>)) {
            throw new IllegalArgumentException("streams: an entry must be an object.");
        }
        Map<?, ?> entry = (Map<?, ?>) value;
        StreamDescriptor d = new StreamDescriptor();
        d.streamId = WireFormat.parseStreamId(string(entry, "stream_id", "stream"));
        String what = "stream " + WireFormat.streamIdText(d.streamId);
        d.producer = end(entry.get("producer"), what + " producer");
        if (!(entry.get("consumers") instanceof List<?> consumers) || consumers.isEmpty()) {
            throw new IllegalArgumentException(what + ": 'consumers' must be a non-empty array.");
        }
        for (Object consumer : consumers) {
            d.consumers.add(end(consumer, what + " consumer"));
        }
        try {
            d.dataType = WireType.parse(string(entry, "data_type", what));
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(what + ": " + ex.getMessage());
        }
        d.maxElementsPerPacket = u32(entry, "max_elements_per_packet", d.maxElementsPerPacket);
        d.maxBatchLatencyMs = u32(entry, "max_batch_latency_ms", d.maxBatchLatencyMs);
        if (entry.containsKey("send_log")) {
            if (!(entry.get("send_log") instanceof Map<?, ?> log)) {
                throw new IllegalArgumentException(what + ": 'send_log' must be an object.");
            }
            d.sendLogMaxPackets = u32(log, "max_packets", d.sendLogMaxPackets);
            d.maxBlockMs = u32(log, "max_block_ms", d.maxBlockMs);
        }
        d.maxWaitMs = u32(entry, "max_wait_ms", d.maxWaitMs);
        if (entry.containsKey("max_latency_ms")) {
            d.maxLatencyMs = u32(entry, "max_latency_ms", 0);
        }
        if (entry.containsKey("sample_rate")) {
            if (!(entry.get("sample_rate") instanceof Map<?, ?> rate)) {
                throw new IllegalArgumentException(what + ": 'sample_rate' must be an object.");
            }
            d.sampleRate = new long[]{index(rate, "numerator", what + " sample_rate"), index(rate, "denominator", what + " sample_rate")};
            if (d.sampleRate[0] == 0 || d.sampleRate[1] == 0) {
                throw new IllegalArgumentException(what + ": 'sample_rate' must be positive.");
            }
        }
        if (!(entry.get("timestamps") instanceof List<?> timestamps) || timestamps.isEmpty()) {
            throw new IllegalArgumentException(what + ": 'timestamps' must declare at least one timestamp role.");
        }
        int previous = 0;
        for (Object declaration : timestamps) {
            if (!(declaration instanceof Map<?, ?> t)) {
                throw new IllegalArgumentException(what + ": a timestamp declaration must be an object.");
            }
            int role = WireFormat.parseRole(string(t, "role", what));
            String domain = string(t, "clock_domain", what);
            if (role <= previous) {
                throw new IllegalArgumentException(what + ": timestamp roles must be distinct and in ascending role order.");
            }
            previous = role;
            d.timestamps.add(new TimestampDeclaration(role, domain));
        }
        return d;
    }

    /** Every member at its value or default, in the order diagram_deployment.cpp writes them. */
    public Map<String, Object> toJson() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("stream_id", WireFormat.streamIdText(streamId));
        out.put("producer", endJson(producer));
        List<Object> consumerList = new ArrayList<>();
        for (End consumer : consumers) {
            consumerList.add(endJson(consumer));
        }
        out.put("consumers", consumerList);
        out.put("data_type", dataType.name());
        out.put("max_elements_per_packet", maxElementsPerPacket);
        out.put("max_batch_latency_ms", maxBatchLatencyMs);
        Map<String, Object> log = new LinkedHashMap<>();
        log.put("max_packets", sendLogMaxPackets);
        log.put("max_block_ms", maxBlockMs);
        out.put("send_log", log);
        out.put("max_wait_ms", maxWaitMs);
        if (sampleRate != null) {
            Map<String, Object> rate = new LinkedHashMap<>();
            rate.put("numerator", sampleRate[0]);
            rate.put("denominator", sampleRate[1]);
            out.put("sample_rate", rate);
        }
        List<Object> roles = new ArrayList<>();
        for (TimestampDeclaration t : timestamps) {
            Map<String, Object> declaration = new LinkedHashMap<>();
            declaration.put("role", WireFormat.roleName(t.role()));
            declaration.put("clock_domain", t.clockDomain());
            roles.add(declaration);
        }
        out.put("timestamps", roles);
        if (maxLatencyMs != null) {
            out.put("max_latency_ms", maxLatencyMs);
        }
        return out;
    }

    private static String string(Map<?, ?> entry, String key, String what) {
        if (!(entry.get(key) instanceof String s)) {
            throw new IllegalArgumentException(what + ": '" + key + "' must be a string.");
        }
        return s;
    }

    /** A JSON integer (Long or BigInteger; a Double such as 3.0 is not one), or null. */
    private static BigInteger integer(Object value) {
        if (value instanceof Long l) {
            return BigInteger.valueOf(l);
        }
        return value instanceof BigInteger b ? b : null;
    }

    private static long index(Map<?, ?> entry, String key, String what) {
        BigInteger value = integer(entry.get(key));
        if (value == null || value.signum() < 0 || value.bitLength() > 63) {
            throw new IllegalArgumentException(what + ": '" + key + "' must be a non-negative integer.");
        }
        return value.longValue();
    }

    private static long u32(Map<?, ?> entry, String key, long fallback) {
        if (!entry.containsKey(key)) {
            return fallback;
        }
        BigInteger value = integer(entry.get(key));
        if (value == null || value.signum() <= 0) {
            throw new IllegalArgumentException("stream: '" + key + "' must be a positive integer.");
        }
        return value.min(BigInteger.valueOf(UINT32_MAX)).longValue();
    }

    private static End end(Object value, String what) {
        if (!(value instanceof Map<?, ?> e)) {
            throw new IllegalArgumentException(what + " must be an object.");
        }
        return new End(string(e, "node_uuid", what), string(e, "element", what), index(e, "port", what));
    }

    private static Map<String, Object> endJson(End end) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("node_uuid", end.nodeUuid());
        out.put("element", end.element());
        out.put("port", end.port());
        return out;
    }
}

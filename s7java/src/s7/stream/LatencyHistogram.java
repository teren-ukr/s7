// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.stream;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * End-to-end latency, SEND_TIME to arrival over synchronized UTC clocks (stream_protocol.cpp).
 * Percentiles come from a log2 histogram of microseconds: upper bounds within a factor of two.
 */
public final class LatencyHistogram {
    private static final int BUCKETS = 40; // bucket k: latencies below 2^k microseconds
    private final long[] counts = new long[BUCKETS];
    private long samples, minNs, maxNs, lastNs, late;
    private BigInteger sumNs = BigInteger.ZERO;

    public boolean add(long latencyNs, Long limitMs) {
        long micros = latencyNs <= 0 ? 0 : latencyNs / 1000;
        counts[Math.min(64 - Long.numberOfLeadingZeros(micros), BUCKETS - 1)]++;
        minNs = samples == 0 ? latencyNs : Math.min(minNs, latencyNs);
        maxNs = samples == 0 ? latencyNs : Math.max(maxNs, latencyNs);
        lastNs = latencyNs;
        sumNs = sumNs.add(BigInteger.valueOf(latencyNs));
        samples++;
        boolean isLate = limitMs != null && latencyNs > limitMs * Faults.MS;
        late += isLate ? 1 : 0;
        return isLate;
    }

    private long percentile(double q) {
        long rank = (long) Math.ceil(q * samples);
        long seen = 0;
        for (int bucket = 0; bucket < BUCKETS; bucket++) {
            seen += counts[bucket];
            if (seen >= rank && seen > 0) {
                return Math.min(maxNs, (1L << bucket) * 1000);
            }
        }
        return maxNs;
    }

    public long lastNs() {
        return lastNs;
    }

    /** STREAM_STATUS latency, in the C++ control plane's form. */
    public Map<String, Object> json() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("samples", samples);
        out.put("min_ns", minNs);
        out.put("mean_ns", samples == 0 ? 0L : sumNs.divide(BigInteger.valueOf(samples)).longValue()); // toward zero
        out.put("p50_ns", samples == 0 ? 0L : percentile(0.50));
        out.put("p99_ns", samples == 0 ? 0L : percentile(0.99));
        out.put("max_ns", maxNs);
        out.put("last_ns", lastNs);
        out.put("late", late);
        return out;
    }
}

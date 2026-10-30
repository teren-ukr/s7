// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.stream;

/** Stream fault codes, as STREAM_STATUS reports them (stream_protocol.hpp FaultCode). */
public final class Faults {
    public static final String SEQUENCE_GAP = "SEQUENCE_GAP"; // packets are missing (e.g. producer restart)
    public static final String SEND_LOG_OVERFLOW = "SEND_LOG_OVERFLOW"; // backpressure lasted longer than max_block_ms
    public static final String STREAM_STATE_LOST = "STREAM_STATE_LOST"; // a consumer cannot be resumed from the send log
    public static final String MALFORMED_PACKET = "MALFORMED_PACKET";
    public static final String TYPE_MISMATCH = "TYPE_MISMATCH";
    public static final String UNDERRUN = "UNDERRUN"; // the consumer waited longer than max_wait_ms for data
    // Refused peers: recorded in a stream's recent faults, they do not stop the stream.
    public static final String TIMESTAMP_PROFILE_MISMATCH = "TIMESTAMP_PROFILE_MISMATCH";
    public static final String UNAUTHORIZED_PRODUCER = "UNAUTHORIZED_PRODUCER";
    public static final String UNAUTHORIZED_CONSUMER = "UNAUTHORIZED_CONSUMER";
    public static final String LATE = "LATE";

    public static final long SEQUENCE_RESERVATION = 65536;
    public static final int ACK_EVERY_PACKETS = 64;
    public static final long ACK_INTERVAL_NS = 50_000_000;
    public static final long MS = 1_000_000; // nanoseconds

    private Faults() {
    }

    /** Time of element `index` of a uniformly sampled stream from 0 ns: index / rate, toward zero, saturating. */
    public static long elementTimeNs(long[] rate, long index) {
        java.math.BigInteger ns = java.math.BigInteger.valueOf(index).multiply(java.math.BigInteger.valueOf(1_000_000_000L))
                .multiply(java.math.BigInteger.valueOf(rate[1])).divide(java.math.BigInteger.valueOf(rate[0]));
        return ns.bitLength() >= 64 ? Long.MAX_VALUE : ns.longValue();
    }
}

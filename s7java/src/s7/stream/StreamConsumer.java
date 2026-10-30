// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.stream;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;

import s7.wire.WireFormat;
import s7.wire.WireFormat.ControlMessage;
import s7.wire.WireFormat.DataPacket;
import s7.wire.WireFormat.TimestampRecord;

/**
 * The consumer end of a stream (stream_protocol.cpp StreamConsumer): delivers each sequence exactly
 * once and in order, discards duplicates, faults on a gap, and acknowledges what its graph consumed.
 * Times are monotonic nanoseconds. Not thread-safe: the stream table guards it.
 */
public final class StreamConsumer {
    private static final class Buffered {
        final long sequence;
        final List<BigInteger[]> values;
        final List<TimestampRecord> timestamps;
        int consumed;

        Buffered(long sequence, List<BigInteger[]> values, List<TimestampRecord> timestamps) {
            this.sequence = sequence;
            this.values = values;
            this.timestamps = timestamps;
        }
    }

    public final StreamConfig config;
    public final long alias;
    private long nextExpected; // next sequence to accept
    private long consumedUpTo; // every packet before this was fully taken by the graph
    private long ackedUpTo;
    private final ArrayDeque<Buffered> buffer = new ArrayDeque<>();
    private long bufferedElements;
    private int consumedSinceAck;
    private Long lastAckNs;
    private String fault;
    private boolean restartAtNext;
    private boolean elementCountKnown = true; // false after a recovered fault
    public final LatencyHistogram latency = new LatencyHistogram();
    private long packets, elements, duplicates, malformed;

    public StreamConsumer(StreamConfig config, long alias) {
        this.config = config;
        this.alias = alias;
    }

    /** Sent after every (re)connect. */
    public ControlMessage resumeMessage() {
        return new ControlMessage(WireFormat.RESUME, alias, nextExpected, config.streamId);
    }

    /** Delivered in order, duplicate discarded, or a gap / mismatch, which faults the stream. Returns whether it was late. */
    public boolean onPacket(DataPacket packet, long nowNs, Long receivedUtcNs) {
        if (fault != null) {
            return false;
        }
        if (packet.type() != config.type) {
            fault(Faults.TYPE_MISMATCH);
            return false;
        }
        List<Integer> roles = packet.timestamps().stream().map(TimestampRecord::role).toList();
        if (config.explicitTimestamps() ? !roles.equals(config.timestampRoles) : !roles.isEmpty()) {
            fault(Faults.TIMESTAMP_PROFILE_MISMATCH);
            return false;
        }
        if (restartAtNext) {
            restartAtNext = false;
            nextExpected = packet.sequence();
            consumedUpTo = Math.max(consumedUpTo, packet.sequence());
            ackedUpTo = Math.max(ackedUpTo, packet.sequence());
        }
        if (packet.sequence() < nextExpected) {
            duplicates++;
            return false;
        }
        if (packet.sequence() > nextExpected) {
            fault(Faults.SEQUENCE_GAP);
            return false;
        }
        List<BigInteger[]> values = WireFormat.decodeElements(config.type, packet.payload());
        buffer.addLast(new Buffered(packet.sequence(), values, packet.timestamps()));
        bufferedElements += values.size();
        nextExpected++;
        packets++;
        if (lastAckNs == null) {
            lastAckNs = nowNs;
        }
        if (packet.sendTimeNs() != null) {
            long arrival = receivedUtcNs != null ? receivedUtcNs : StreamProducer.utcNowNs();
            return latency.add(arrival - packet.sendTimeNs(), config.maxLatencyMs);
        }
        return false;
    }

    public void onMalformed() {
        malformed++;
        fault(Faults.MALFORMED_PACKET);
    }

    public long available() {
        return bufferedElements;
    }

    /** Elements for the graph; firstTimes, if given, receives the times of the first element taken. */
    public List<BigInteger[]> take(int maxCount, List<TimestampRecord> firstTimes) {
        if (firstTimes != null) {
            firstTimes.clear();
            if (maxCount > 0 && !buffer.isEmpty()) {
                Buffered front = buffer.peekFirst();
                if (config.sampleRate != null) {
                    if (elementCountKnown) {
                        long ns = Faults.elementTimeNs(config.sampleRate, elements);
                        for (int role : config.timestampRoles) {
                            firstTimes.add(new TimestampRecord(role, ns));
                        }
                    }
                } else if (front.consumed == 0) {
                    firstTimes.addAll(front.timestamps);
                }
            }
        }
        List<BigInteger[]> out = new ArrayList<>();
        while (out.size() < maxCount && !buffer.isEmpty()) {
            Buffered front = buffer.peekFirst();
            int chunk = Math.min(maxCount - out.size(), front.values.size() - front.consumed);
            out.addAll(front.values.subList(front.consumed, front.consumed + chunk));
            front.consumed += chunk;
            bufferedElements -= chunk;
            elements += chunk;
            if (front.consumed == front.values.size()) {
                consumedUpTo = front.sequence + 1;
                consumedSinceAck++;
                buffer.pollFirst();
            }
        }
        return out;
    }

    /** An ACK when 64 packets were consumed or 50 ms passed since the last one while something new was consumed. */
    public ControlMessage ackDue(long nowNs) {
        if (consumedUpTo <= ackedUpTo) {
            return null;
        }
        long last = lastAckNs != null ? lastAckNs : 0;
        if (consumedSinceAck < Faults.ACK_EVERY_PACKETS && nowNs - last < Faults.ACK_INTERVAL_NS) {
            return null;
        }
        ackedUpTo = consumedUpTo;
        consumedSinceAck = 0;
        lastAckNs = nowNs;
        return new ControlMessage(WireFormat.ACK, alias, ackedUpTo, new byte[16]);
    }

    public void fault(String code) {
        if (fault == null) {
            fault = code;
        }
    }

    /** RECOVER_STREAM: clears the fault and accepts the next packet received as the new start. */
    public void recover() {
        if (fault == null) {
            return; // a repeated RECOVER_STREAM changes nothing
        }
        fault = null;
        restartAtNext = true;
        elementCountKnown = false; // the elements lost in the fault are not counted
    }

    public String faultCode() {
        return fault;
    }

    public long nextExpected() {
        return nextExpected;
    }

    public long packets() {
        return packets;
    }

    public long elements() {
        return elements;
    }

    public long duplicates() {
        return duplicates;
    }

    public long malformed() {
        return malformed;
    }
}

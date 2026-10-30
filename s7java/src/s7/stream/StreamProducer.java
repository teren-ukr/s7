// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.stream;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import s7.wire.WireFormat;
import s7.wire.WireFormat.DataPacket;
import s7.wire.WireFormat.TimestampRecord;

/**
 * The producer end of a stream (stream_protocol.cpp StreamProducer): packs elements into packets
 * (batching), numbers them, keeps them in a bounded send log until every attached consumer
 * acknowledged them, and replays from a consumer's RESUME position. A full log is backpressure.
 * Times are monotonic nanoseconds. Not thread-safe: the stream table guards it.
 */
public final class StreamProducer {
    private record Logged(long sequence, Long sendTimeNs, List<TimestampRecord> timestamps, byte[] payload) {
    }

    private static final class Consumer {
        long alias;
        long nextToSend;
        long acknowledged;
        boolean attached;
    }

    public final StreamConfig config;
    private final SequenceStore sequences;
    private long nextSequence;
    private long reservedEnd;
    private final ArrayDeque<Logged> log = new ArrayDeque<>(); // contiguous sequences
    private final List<Logged> index = new ArrayList<>(); // the same packets, for replay by position
    private final Map<String, Consumer> consumers = new HashMap<>();
    private List<BigInteger[]> pending = new ArrayList<>();
    private List<TimestampRecord> pendingTimes = List.of();
    private long pendingSince;
    public boolean stampSendTime = true; // only while this node's clock is synchronized
    private String fault;
    private long packets, elements, replayed, lostResumes;
    public long blockedTotalMs;

    public StreamProducer(StreamConfig config, SequenceStore sequences) {
        if (config.maxElementsPerPacket == 0 || config.sendLogMaxPackets == 0) {
            throw new IllegalArgumentException("Stream limits must be positive.");
        }
        if (config.sampleRate != null && (config.sampleRate[0] == 0 || config.sampleRate[1] == 0)) {
            throw new IllegalArgumentException("A stream's sample rate must be positive.");
        }
        for (int i = 1; i < config.timestampRoles.size(); i++) {
            if (config.timestampRoles.get(i) <= config.timestampRoles.get(i - 1)) {
                throw new IllegalArgumentException("A stream's timestamp roles must be distinct and in ascending role order.");
            }
        }
        if (WireFormat.payloadBytes(config.type, (int) Math.min(config.maxElementsPerPacket, Integer.MAX_VALUE / 64)) > WireFormat.MAX_PAYLOAD_BYTES) {
            throw new IllegalArgumentException("max_elements_per_packet exceeds the 256 KiB payload limit for " + config.type + ".");
        }
        this.config = config;
        this.sequences = sequences;
        // Continue beyond the previous reservation: after a restart the consumer sees a gap, never a reused number.
        this.reservedEnd = sequences.reservedEnd(config.streamId);
        this.nextSequence = reservedEnd;
    }

    public boolean logFull() {
        return log.size() >= config.sendLogMaxPackets;
    }

    /**
     * Takes elements; returns how many: fewer when the send log is full (backpressure). A stream with
     * explicit timestamps takes one element at a time with exactly its declared roles.
     */
    public int append(List<BigInteger[]> items, long nowNs, List<TimestampRecord> times) {
        if (config.explicitTimestamps()) {
            List<Integer> roles = times.stream().map(TimestampRecord::role).toList();
            if (items.size() > 1 || (items.size() == 1 && !roles.equals(config.timestampRoles))) {
                throw new IllegalArgumentException("Stream " + WireFormat.streamIdText(config.streamId)
                        + " has explicit timestamps: publish one element at a time with its declared roles.");
            }
        } else if (!times.isEmpty()) {
            throw new IllegalArgumentException("Stream " + WireFormat.streamIdText(config.streamId) + " takes no per-element timestamps.");
        }
        if (fault != null) {
            return items.size(); // a faulted stream sends nothing; the graph is not held back
        }
        if (config.explicitTimestamps()) {
            if (items.isEmpty() || logFull()) {
                return 0;
            }
            pending = new ArrayList<>();
            pending.add(items.get(0));
            pendingSince = nowNs;
            pendingTimes = List.copyOf(times);
            seal();
            return 1;
        }
        int limit = (int) config.maxElementsPerPacket;
        int taken = 0;
        while (taken < items.size()) {
            if (pending.size() == limit) {
                if (logFull()) {
                    break;
                }
                seal();
            }
            if (pending.isEmpty() && logFull()) {
                break;
            }
            int chunk = Math.min(items.size() - taken, limit - pending.size());
            if (pending.isEmpty()) {
                pendingSince = nowNs;
            }
            pending.addAll(items.subList(taken, taken + chunk));
            taken += chunk;
        }
        if (pending.size() == limit && !logFull()) {
            seal();
        }
        return taken;
    }

    /** Seals the partial packet if its oldest element waited max_batch_latency (or with force). */
    public boolean flush(long nowNs, boolean force) {
        if (pending.isEmpty() || logFull() || fault != null) {
            return false;
        }
        if (!force && nowNs - pendingSince < config.maxBatchLatencyMs * Faults.MS) {
            return false;
        }
        seal();
        return true;
    }

    private void seal() {
        if (nextSequence >= reservedEnd) {
            reservedEnd = nextSequence + Faults.SEQUENCE_RESERVATION;
            sequences.reserve(config.streamId, reservedEnd);
        }
        Logged packet = new Logged(nextSequence, stampSendTime ? utcNowNs() : null, pendingTimes,
                WireFormat.encodeElements(config.type, pending));
        log.addLast(packet);
        index.add(packet);
        nextSequence++;
        packets++;
        elements += pending.size();
        pending = new ArrayList<>();
        pendingTimes = List.of();
    }

    static long utcNowNs() {
        java.time.Instant now = java.time.Instant.now();
        return now.getEpochSecond() * 1_000_000_000L + now.getNano();
    }

    /**
     * RESUME from a consumer: start transmitting at nextExpected. A position older than the log starts at
     * the oldest logged packet (the consumer faults on the gap); one beyond nextSequence faults the stream.
     */
    public void resume(String consumer, long alias, long nextExpected) {
        long oldest = log.isEmpty() ? nextSequence : log.peekFirst().sequence();
        long start = nextExpected;
        if (nextExpected < oldest) {
            lostResumes++;
            start = oldest;
        } else if (nextExpected > nextSequence) {
            lostResumes++;
            fault(Faults.STREAM_STATE_LOST);
            start = nextSequence;
        }
        Consumer entry = consumers.computeIfAbsent(consumer, k -> new Consumer());
        entry.alias = alias;
        entry.nextToSend = start;
        entry.acknowledged = Math.max(entry.acknowledged, start);
        entry.attached = true;
        replayed += nextSequence - start;
        trim();
    }

    public void detach(String consumer) {
        Consumer entry = consumers.get(consumer);
        if (entry != null) {
            entry.attached = false; // keeps its retention position
        }
    }

    public void acknowledge(String consumer, long nextExpected) {
        Consumer entry = consumers.get(consumer);
        if (entry == null || nextExpected > entry.nextToSend) {
            return; // cannot acknowledge what was not sent
        }
        entry.acknowledged = Math.max(entry.acknowledged, nextExpected);
        trim();
    }

    private void trim() {
        if (consumers.isEmpty()) {
            return; // nobody has the data yet
        }
        long lowest = Long.MAX_VALUE;
        for (Consumer c : consumers.values()) {
            lowest = Math.min(lowest, c.acknowledged);
        }
        int dropped = 0;
        while (!log.isEmpty() && log.peekFirst().sequence() < lowest) {
            log.pollFirst();
            dropped++;
        }
        if (dropped > 0) {
            index.subList(0, dropped).clear();
        }
    }

    /** The next encoded packet for the consumer, or null if it is up to date. */
    public byte[] nextMessage(String consumer) {
        Consumer entry = consumers.get(consumer);
        if (fault != null || entry == null || !entry.attached || entry.nextToSend >= nextSequence || log.isEmpty()) {
            return null;
        }
        long position = entry.nextToSend - log.peekFirst().sequence();
        if (position >= index.size()) {
            return null;
        }
        Logged logged = index.get((int) position);
        entry.nextToSend++;
        return WireFormat.encodeDataPacket(new DataPacket(config.type, entry.alias, logged.sequence(), logged.payload(),
                logged.timestamps(), logged.sendTimeNs()));
    }

    public void fault(String code) {
        if (fault == null) {
            fault = code;
        }
    }

    /** RECOVER_STREAM: clears the fault; sending resumes. */
    public void recover() {
        fault = null;
    }

    public String faultCode() {
        return fault;
    }

    public long nextSequence() {
        return nextSequence;
    }

    public long packets() {
        return packets;
    }

    public long elements() {
        return elements;
    }

    public long replayed() {
        return replayed;
    }

    public long lostResumes() {
        return lostResumes;
    }

    public int sendLogDepth() {
        return log.size();
    }
}

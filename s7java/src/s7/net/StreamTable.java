// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.net;

import java.math.BigInteger;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import s7.stream.Faults;
import s7.stream.SequenceStore;
import s7.stream.StreamConfig;
import s7.stream.StreamConsumer;
import s7.stream.StreamProducer;
import s7.wire.WireFormat;
import s7.wire.WireFormat.TimestampRecord;

/**
 * Every stream of the node and the blocking graph-side API (s7transport transport.cpp StreamTable):
 * publish waits for room in a full send log up to max_block_ms, receive waits for data up to
 * max_wait_ms. This object's monitor guards every producer and consumer, as the C++ mutex does.
 */
public final class StreamTable {
    public static final String PRODUCER = "producer", CONSUMER = "consumer";
    private static final int MAX_RECENT_FAULTS = 16;

    public static final class Entry {
        public final long handle;
        public final String role;
        public final StreamConfig config;
        public final StreamProducer producer;
        public final StreamConsumer consumer;
        boolean open = true;
        long unauthorized;
        final ArrayDeque<Map<String, Object>> recentFaults = new ArrayDeque<>();
        String noted;
        long lateNotedNs = Long.MIN_VALUE;

        Entry(long handle, String role, StreamConfig config, StreamProducer producer, StreamConsumer consumer) {
            this.handle = handle;
            this.role = role;
            this.config = config;
            this.producer = producer;
            this.consumer = consumer;
        }

        String faultCode() {
            return producer != null ? producer.faultCode() : consumer.faultCode();
        }

        void note(String code, String detail) {
            if (recentFaults.size() == MAX_RECENT_FAULTS) {
                recentFaults.pollFirst();
            }
            Map<String, Object> fault = new LinkedHashMap<>();
            fault.put("code", code);
            fault.put("detail", detail);
            fault.put("at", Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS).toString());
            recentFaults.addLast(fault);
        }

        void noteFault() {
            String code = faultCode();
            if (code != null && !code.equals(noted)) {
                note(code, "");
            }
            noted = code;
        }

        void noteLate() {
            long now = System.nanoTime();
            if (now - lateNotedNs < 1_000_000_000L) {
                return;
            }
            lateNotedNs = now;
            note(Faults.LATE, "latency_ms=" + consumer.latency.lastNs() / 1_000_000 + " max_latency_ms="
                    + (config.maxLatencyMs != null ? config.maxLatencyMs : 0));
        }
    }

    public record Received(List<BigInteger[]> elements, String fault, List<TimestampRecord> times) {
    }

    private final SequenceStore sequences;
    final Map<Long, Entry> entries = new LinkedHashMap<>();
    private final Map<String, Long> producers = new HashMap<>();
    private final Map<String, Long> consumers = new HashMap<>();
    private long nextHandle = 1;
    private boolean clockUsable = true;
    // Called with the monitor held after producer data or consumer streams changed; they only schedule work.
    Consumer<Entry> onProducerData = entry -> { };
    Consumer<Entry> onConsumerOpened = entry -> { };

    public StreamTable(SequenceStore sequences) {
        this.sequences = sequences;
    }

    private static String key(byte[] id) {
        return Arrays.toString(id);
    }

    /** Reopening a closed stream of the same type continues it; another type starts anew. */
    public synchronized long open(StreamConfig config, String role) {
        Map<String, Long> index = role.equals(PRODUCER) ? producers : consumers;
        Long existingHandle = index.get(key(config.streamId));
        if (existingHandle != null) {
            Entry existing = entries.get(existingHandle);
            if (existing.open) {
                throw new IllegalArgumentException("Stream " + WireFormat.streamIdText(config.streamId) + " is already open as " + role + ".");
            }
            if (existing.config.type == config.type) {
                existing.open = true;
                existing.config.maxBlockMs = config.maxBlockMs;
                existing.config.maxWaitMs = config.maxWaitMs;
                existing.config.producerNode = config.producerNode;
                existing.config.consumerNodes = config.consumerNodes;
                existing.config.maxLatencyMs = config.maxLatencyMs;
                notifyAll();
                return existingHandle;
            }
            entries.remove(existingHandle);
            index.remove(key(config.streamId));
        }
        long handle = nextHandle++;
        Entry entry;
        if (role.equals(PRODUCER)) {
            StreamProducer producer = new StreamProducer(config, sequences);
            producer.stampSendTime = clockUsable;
            entry = new Entry(handle, role, config, producer, null);
        } else {
            entry = new Entry(handle, role, config, null, new StreamConsumer(config, handle)); // the alias is the handle
        }
        entries.put(handle, entry);
        index.put(key(config.streamId), handle);
        if (role.equals(CONSUMER)) {
            onConsumerOpened.accept(entry);
        } else {
            onProducerData.accept(entry); // apply RESUMEs that arrived before the producer opened
        }
        return handle;
    }

    public synchronized void close(long handle) {
        Entry entry = entries.get(handle);
        if (entry != null) {
            entry.open = false;
            notifyAll();
        }
    }

    /** The stream's fault, if any; blocks on a full send log up to max_block_ms (then SEND_LOG_OVERFLOW). */
    public synchronized String publish(long handle, List<BigInteger[]> items, List<TimestampRecord> times) throws InterruptedException {
        Entry entry = require(handle, PRODUCER);
        StreamProducer producer = entry.producer;
        int done = 0;
        long deadline = Long.MIN_VALUE;
        while (done < items.size()) {
            if (producer.faultCode() != null) {
                return producer.faultCode();
            }
            long now = System.nanoTime();
            done += producer.append(items.subList(done, items.size()), now, times);
            onProducerData.accept(entry);
            if (done == items.size()) {
                break;
            }
            if (deadline == Long.MIN_VALUE) {
                deadline = now + entry.config.maxBlockMs * Faults.MS;
            }
            long waitStart = System.nanoTime();
            while (entries.containsKey(handle) && producer.logFull() && producer.faultCode() == null) {
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    break;
                }
                wait(Math.max(1, left / 1_000_000));
            }
            if (!entries.containsKey(handle)) {
                return null;
            }
            producer.blockedTotalMs += (System.nanoTime() - waitStart) / Faults.MS;
            if (producer.logFull() && producer.faultCode() == null) {
                producer.fault(Faults.SEND_LOG_OVERFLOW);
                return Faults.SEND_LOG_OVERFLOW;
            }
        }
        return null;
    }

    /** Waits for data up to max_wait_ms (then UNDERRUN). */
    public synchronized Received receive(long handle, int count) throws InterruptedException {
        Entry entry = require(handle, CONSUMER);
        StreamConsumer consumer = entry.consumer;
        List<BigInteger[]> taken = new ArrayList<>();
        List<TimestampRecord> firstTimes = new ArrayList<>();
        long deadline = System.nanoTime() + entry.config.maxWaitMs * Faults.MS;
        while (true) {
            taken.addAll(consumer.take(count - taken.size(), taken.isEmpty() ? firstTimes : null));
            if (taken.size() == count || consumer.faultCode() != null) {
                break;
            }
            while (entries.containsKey(handle) && consumer.available() == 0 && consumer.faultCode() == null) {
                long left = deadline - System.nanoTime();
                if (left <= 0) {
                    break;
                }
                wait(Math.max(1, left / 1_000_000));
            }
            if (!entries.containsKey(handle)) {
                return new Received(taken, null, firstTimes);
            }
            if (consumer.available() == 0 && consumer.faultCode() == null) {
                consumer.fault(Faults.UNDERRUN);
                break;
            }
        }
        return new Received(taken, consumer.faultCode(), firstTimes);
    }

    /** GET_STREAM_STATUS entries, in the C++ control plane's form. */
    public synchronized List<Map<String, Object>> statuses() {
        List<Map<String, Object>> result = new ArrayList<>();
        for (Entry entry : entries.values()) {
            entry.noteFault();
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("stream_id", WireFormat.streamIdText(entry.config.streamId));
            s.put("role", entry.role);
            s.put("data_type", entry.config.type.name());
            String fault = entry.faultCode();
            Map<String, Object> latency;
            if (entry.producer != null) {
                StreamProducer p = entry.producer;
                s.put("state", fault != null ? "faulted" : !entry.open ? "closed" : p.logFull() ? "blocked" : "active");
                s.put("fault", fault != null ? fault : "NONE");
                s.put("next_sequence", p.nextSequence());
                s.put("packets", p.packets());
                s.put("elements", p.elements());
                s.put("replayed", p.replayed());
                s.put("lost_resumes", p.lostResumes());
                s.put("duplicates_discarded", 0L);
                s.put("malformed", 0L);
                s.put("unauthorized", entry.unauthorized);
                s.put("send_log_depth", (long) p.sendLogDepth());
                s.put("buffered_elements", 0L);
                s.put("blocked_ms_total", p.blockedTotalMs);
                latency = new s7.stream.LatencyHistogram().json();
            } else {
                StreamConsumer c = entry.consumer;
                s.put("state", fault != null ? "faulted" : entry.open ? "active" : "closed");
                s.put("fault", fault != null ? fault : "NONE");
                s.put("next_sequence", c.nextExpected());
                s.put("packets", c.packets());
                s.put("elements", c.elements());
                s.put("replayed", 0L);
                s.put("lost_resumes", 0L);
                s.put("duplicates_discarded", c.duplicates());
                s.put("malformed", c.malformed());
                s.put("unauthorized", entry.unauthorized);
                s.put("send_log_depth", 0L);
                s.put("buffered_elements", c.available());
                s.put("blocked_ms_total", 0L);
                latency = c.latency.json();
            }
            s.put("recent_faults", new ArrayList<>(entry.recentFaults));
            s.put("latency", latency);
            result.add(s);
        }
        return result;
    }

    public synchronized boolean recover(byte[] streamId) {
        boolean found = false;
        for (Map<String, Long> index : List.of(producers, consumers)) {
            Long handle = index.get(key(streamId));
            if (handle != null) {
                Entry entry = entries.get(handle);
                entry.noteFault();
                if (entry.producer != null) {
                    entry.producer.recover();
                    onProducerData.accept(entry);
                } else {
                    entry.consumer.recover();
                }
                found = true;
            }
        }
        notifyAll();
        return found;
    }

    private Entry require(long handle, String role) {
        Entry entry = entries.get(handle);
        if (entry == null || !entry.role.equals(role)) {
            throw new IllegalArgumentException("Not an open " + role + " stream.");
        }
        return entry;
    }

    // The monitor held by the caller.
    Entry findProducer(byte[] streamId) {
        Long handle = producers.get(key(streamId));
        return handle == null ? null : entries.get(handle);
    }

    Entry findConsumerByAlias(long alias) {
        Entry entry = entries.get(alias);
        return entry != null && entry.role.equals(CONSUMER) ? entry : null;
    }
}

// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.stream;

import java.util.ArrayList;
import java.util.List;

import s7.wire.WireType;

/** A stream's settings (s7transport stream_protocol.hpp StreamConfig). */
public final class StreamConfig {
    public byte[] streamId;
    public WireType type = WireType.F64;
    public long maxElementsPerPacket = 1024;
    public long maxBatchLatencyMs = 10;
    public long sendLogMaxPackets = 4096;
    public long maxBlockMs = 2000;
    public long maxWaitMs = 2000; // consumer side: how long a step may wait for data
    // The nodes allowed at the other end (node UUIDs; empty: not checked).
    public String producerNode = "";
    public List<String> consumerNodes = new ArrayList<>();
    // With a sample rate the stream is uniformly sampled and packets carry no timestamps; without
    // one, every packet carries exactly the declared roles (ascending) for its single element.
    public long[] sampleRate; // {numerator, denominator} or null
    public List<Integer> timestampRoles = new ArrayList<>();
    public Long maxLatencyMs; // consumer: packets later than this are counted late

    public boolean explicitTimestamps() {
        return sampleRate == null && !timestampRoles.isEmpty();
    }

    public static StreamConfig fromDescriptor(StreamDescriptor d) {
        StreamConfig c = new StreamConfig();
        c.streamId = d.streamId;
        c.type = d.dataType;
        c.maxElementsPerPacket = d.maxElementsPerPacket;
        c.maxBatchLatencyMs = d.maxBatchLatencyMs;
        c.sendLogMaxPackets = d.sendLogMaxPackets;
        c.maxBlockMs = d.maxBlockMs;
        c.maxWaitMs = d.maxWaitMs;
        c.producerNode = d.producer.nodeUuid();
        for (StreamDescriptor.End consumer : d.consumers) {
            c.consumerNodes.add(consumer.nodeUuid());
        }
        c.sampleRate = d.sampleRate;
        for (StreamDescriptor.TimestampDeclaration t : d.timestamps) {
            c.timestampRoles.add(t.role());
        }
        c.maxLatencyMs = d.maxLatencyMs;
        return c;
    }
}

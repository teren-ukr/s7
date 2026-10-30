// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.node;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import s7.net.DataEndpoint.DataPeer;
import s7.stream.StreamDescriptor;
import s7.wire.WireFormat;

/**
 * A node's part of a deployed diagram, as s7net's diagram_deployment.cpp extract_node_schema() and
 * producer_endpoints() derive it: its elements, the connections between them, a NetSink for each
 * stream it produces and a NetSource for each it consumes, and the producer nodes it connects to.
 */
public final class NodePart {
    public final Map<String, Object> schema = new LinkedHashMap<>();
    public final List<DataPeer> dataPeers = new ArrayList<>();
    public final Long stepNs; // the diagram's model-time step

    private static Map<String, Object> connection(Object from, Object fromPort, Object to, Object toPort) {
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("from_element", from);
        c.put("from_port", fromPort);
        c.put("to_element", to);
        c.put("to_port", toPort);
        return c;
    }

    @SuppressWarnings("unchecked")
    public NodePart(Map<String, Object> diagram, String node) {
        Map<String, Object> source = (Map<String, Object>) diagram.getOrDefault("schema", diagram);
        Map<String, String> placement = new LinkedHashMap<>();
        List<Object> elements = new ArrayList<>();
        for (Object item : (List<Object>) source.get("elements")) {
            Map<String, Object> e = (Map<String, Object>) item;
            placement.put((String) e.get("id"), e.get("node") instanceof String s ? s : "");
            if (node.equals(placement.get(e.get("id")))) {
                Map<String, Object> copy = new LinkedHashMap<>(e);
                copy.remove("node");
                elements.add(copy);
            }
        }
        List<Object> connections = new ArrayList<>();
        List<String> produced = new ArrayList<>();
        List<String> consumed = new ArrayList<>();
        for (Object item : (List<Object>) diagram.getOrDefault("streams", List.of())) {
            StreamDescriptor d = StreamDescriptor.fromJson(item);
            String id = WireFormat.streamIdText(d.streamId);
            List<Object> roles = new ArrayList<>();
            d.timestamps.forEach(t -> roles.add(WireFormat.roleName(t.role())));
            if (d.producer.nodeUuid().equals(node)) {
                produced.add(d.producer.element() + ":" + d.producer.port());
                List<Object> consumerNodes = new ArrayList<>();
                d.consumers.forEach(c -> {
                    if (!consumerNodes.contains(c.nodeUuid())) {
                        consumerNodes.add(c.nodeUuid());
                    }
                });
                Map<String, Object> params = new LinkedHashMap<>();
                params.put("stream_id", id);
                params.put("type", d.dataType.name());
                params.put("max_elements_per_packet", d.maxElementsPerPacket);
                params.put("max_batch_latency_ms", d.maxBatchLatencyMs);
                params.put("send_log_max_packets", d.sendLogMaxPackets);
                params.put("max_block_ms", d.maxBlockMs);
                params.put("consumer_nodes", consumerNodes);
                params.put("timestamps", roles);
                if (d.sampleRate != null) {
                    params.put("sample_rate", List.of(d.sampleRate[0], d.sampleRate[1]));
                }
                elements.add(Map.of("id", "__stream_" + id + "_out", "type", "NetSink", "params", params));
                connections.add(connection(d.producer.element(), d.producer.port(), "__stream_" + id + "_out", 0L));
            }
            boolean consumes = false;
            for (StreamDescriptor.End c : d.consumers) {
                if (c.nodeUuid().equals(node)) {
                    consumed.add(d.producer.element() + ":" + d.producer.port() + "->" + c.element() + ":" + c.port());
                    connections.add(connection("__stream_" + id + "_in", 0L, c.element(), c.port()));
                    consumes = true;
                }
            }
            if (consumes) {
                Map<String, Object> params = new LinkedHashMap<>();
                params.put("stream_id", id);
                params.put("type", d.dataType.name());
                params.put("max_wait_ms", d.maxWaitMs);
                params.put("producer_node", d.producer.nodeUuid());
                params.put("timestamps", roles);
                if (d.sampleRate != null) {
                    params.put("sample_rate", List.of(d.sampleRate[0], d.sampleRate[1]));
                }
                if (d.maxLatencyMs != null) {
                    params.put("max_latency_ms", d.maxLatencyMs);
                }
                elements.add(Map.of("id", "__stream_" + id + "_in", "type", "NetSource", "params", params));
                if (!d.producer.nodeUuid().equals(node)) {
                    DataPeer peer = peerOf(diagram, d.producer.nodeUuid(), id);
                    if (!dataPeers.contains(peer)) {
                        dataPeers.add(peer);
                    }
                }
            }
        }
        for (Object item : (List<Object>) source.getOrDefault("connections", List.of())) {
            Map<String, Object> c = (Map<String, Object>) item;
            boolean fromHere = node.equals(placement.get(c.get("from_element")));
            boolean toHere = node.equals(placement.get(c.get("to_element")));
            String link = c.get("from_element") + ":" + c.get("from_port") + "->" + c.get("to_element") + ":" + c.get("to_port");
            if (fromHere && toHere) {
                connections.add(new LinkedHashMap<>(c));
            } else if (fromHere && !produced.contains(c.get("from_element") + ":" + c.get("from_port"))) {
                throw new IllegalArgumentException("Connection " + link + " leaves this node without a stream.");
            } else if (toHere && !consumed.contains(link)) {
                throw new IllegalArgumentException("Connection " + link + " enters this node without a stream.");
            }
        }
        schema.put("name", source.getOrDefault("name", "diagram") + "@" + node);
        schema.put("elements", elements);
        schema.put("connections", connections);
        stepNs = diagram.get("dt") instanceof Number dt ? Math.round(dt.doubleValue() * 1e9) : null;
    }

    @SuppressWarnings("unchecked")
    private static DataPeer peerOf(Map<String, Object> diagram, String producerNode, String streamId) {
        for (Object item : (List<Object>) diagram.getOrDefault("runtime_nodes", List.of())) {
            Map<String, Object> n = (Map<String, Object>) item;
            if (producerNode.equals(n.get("node_uuid"))) {
                Object url = n.containsKey("data_endpoint") ? n.get("data_endpoint") : n.get("endpoint");
                if (url instanceof String s && !s.isEmpty()) {
                    return new DataPeer(s, producerNode);
                }
            }
        }
        throw new IllegalArgumentException("Stream " + streamId + ": producer node " + producerNode + " has no endpoint in 'runtime_nodes'.");
    }
}

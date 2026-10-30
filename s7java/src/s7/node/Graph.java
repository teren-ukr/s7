// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.node;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import s7.net.StreamTable;
import s7.stream.StreamConfig;
import s7.wire.WireFormat;
import s7.wire.WireType;

/**
 * A node's part of a diagram, compiled and stepped with the S7 causal semantics (doc/S7_Formal_Model.md):
 * elements with direct feedthrough run in causal order; causal memory (Delay) publishes at the start of the
 * next step what it computed in this one, so a cycle must pass through it. F64 signals; the elements the
 * transport experiments need: Constant, Gain, Adder, Accumulator, Delay / PreviousValue, Comparator,
 * NetSink and NetSource.
 */
public final class Graph {
    abstract static class Element {
        final String id;
        int inputs;
        double output;
        boolean memory;
        double staged;

        Element(String id) {
            this.id = id;
        }

        abstract void step(double[] in) throws InterruptedException;
    }

    private final Map<String, Element> elements = new LinkedHashMap<>();
    private final Map<String, Object[][]> drivers = new HashMap<>(); // element -> per input {driver element}
    private final List<Element> causalOrder = new ArrayList<>();
    private final List<Element> memory = new ArrayList<>();
    private boolean stagedReady;
    public long steps;
    private final StreamTable table;

    @SuppressWarnings("unchecked")
    public Graph(Map<String, Object> schema, StreamTable table) {
        this.table = table;
        for (Object item : (List<Object>) schema.get("elements")) {
            Map<String, Object> e = (Map<String, Object>) item;
            Map<String, Object> params = (Map<String, Object>) e.getOrDefault("params", Map.of());
            elements.put((String) e.get("id"), create((String) e.get("id"), (String) e.get("type"), params));
        }
        for (Element element : elements.values()) {
            drivers.put(element.id, new Object[element.inputs][]);
        }
        for (Object item : (List<Object>) schema.get("connections")) {
            Map<String, Object> c = (Map<String, Object>) item;
            Element from = elements.get(c.get("from_element"));
            Element to = elements.get(c.get("to_element"));
            if (from == null || to == null) {
                throw new IllegalArgumentException("connection " + c.get("from_element") + " -> " + c.get("to_element") + ": unknown element");
            }
            int port = ((Long) c.getOrDefault("to_port", 0L)).intValue();
            Object[][] ports = drivers.get(to.id);
            if (port >= ports.length || ports[port] != null) {
                throw new IllegalArgumentException("input '" + to.id + "':" + port + " missing or driven twice");
            }
            ports[port] = new Object[]{from};
        }
        drivers.forEach((id, ports) -> {
            for (int port = 0; port < ports.length; port++) {
                if (ports[port] == null) {
                    throw new IllegalArgumentException("input '" + id + "':" + port + " is not connected");
                }
            }
        });
        Map<String, Integer> state = new HashMap<>();
        for (Element element : elements.values()) {
            if (!element.memory) {
                visit(element, state);
            } else {
                memory.add(element);
            }
        }
    }

    private void visit(Element element, Map<String, Integer> state) {
        Integer s = state.get(element.id);
        if (s != null && s == 2) {
            return;
        }
        if (s != null) {
            throw new IllegalArgumentException("cycle without causal memory through '" + element.id + "'");
        }
        state.put(element.id, 1);
        for (Object[] driver : drivers.get(element.id)) {
            Element from = (Element) driver[0];
            if (!from.memory) {
                visit(from, state);
            }
        }
        state.put(element.id, 2);
        causalOrder.add(element);
    }

    private double[] inputs(Element element) {
        Object[][] ports = drivers.get(element.id);
        double[] in = new double[ports.length];
        for (int i = 0; i < ports.length; i++) {
            in[i] = ((Element) ports[i][0]).output;
        }
        return in;
    }

    /** One step: publish causal memory, evaluate the rest in causal order, stage causal memory. */
    public void step() throws InterruptedException {
        if (stagedReady) {
            for (Element m : memory) {
                m.output = m.staged;
            }
        }
        for (Element element : causalOrder) {
            element.step(inputs(element));
        }
        for (Element m : memory) {
            double current = m.output;
            m.step(inputs(m));
            m.staged = m.output;
            m.output = current;
        }
        stagedReady = true;
        steps++;
    }

    public Double sample(String id) {
        Element element = elements.get(id);
        return element == null ? null : element.output;
    }

    public void close() {
        for (Element element : elements.values()) {
            if (element instanceof NetEnd end && end.handle != 0) {
                table.close(end.handle);
            }
        }
    }

    private static double number(Map<String, Object> params, String name, double fallback) {
        Object value = params.getOrDefault(name, fallback);
        if (!(value instanceof Number n) || value instanceof Boolean) {
            throw new IllegalArgumentException("parameter '" + name + "' must be a number");
        }
        return n.doubleValue();
    }

    @SuppressWarnings("unchecked")
    private Element create(String id, String type, Map<String, Object> params) {
        switch (type) {
            case "Constant": {
                double value = number(params, "value", 0);
                return new Element(id) {
                    { output = value; }

                    void step(double[] in) {
                    }
                };
            }
            case "Gain": {
                double factor = number(params, "factor", 1);
                Element e = new Element(id) {
                    void step(double[] in) {
                        output = in[0] * factor;
                    }
                };
                e.inputs = 1;
                return e;
            }
            case "Adder": {
                List<Object> raw = (List<Object>) params.getOrDefault("weights", List.of(1L, 1L));
                double[] weights = raw.stream().mapToDouble(w -> ((Number) w).doubleValue()).toArray();
                Element e = new Element(id) {
                    void step(double[] in) {
                        double total = 0.0; // in input order, as AdderT: the same value to the last bit
                        for (int i = 0; i < in.length; i++) {
                            total += in[i] * weights[i];
                        }
                        output = total;
                    }
                };
                e.inputs = weights.length;
                return e;
            }
            case "Accumulator": {
                double initial = number(params, "initial_value", 0);
                Element e = new Element(id) {
                    { output = initial; }

                    void step(double[] in) {
                        output += in[0];
                    }
                };
                e.inputs = 1;
                return e;
            }
            case "Delay":
            case "PreviousValue": {
                double initial = number(params, "initial_value", 0);
                Element e = new Element(id) {
                    { output = initial; }

                    void step(double[] in) {
                        output = in[0];
                    }
                };
                e.inputs = 1;
                e.memory = true;
                return e;
            }
            case "Comparator": {
                String operation = (String) params.getOrDefault("operation", "lt");
                Element e = new Element(id) {
                    void step(double[] in) {
                        boolean result = switch (operation) {
                            case "lt" -> in[0] < in[1];
                            case "le" -> in[0] <= in[1];
                            case "gt" -> in[0] > in[1];
                            case "ge" -> in[0] >= in[1];
                            case "eq" -> in[0] == in[1];
                            case "ne" -> in[0] != in[1];
                            default -> throw new IllegalArgumentException("Comparator operation must be one of lt, le, gt, ge, eq, ne.");
                        };
                        output = result ? 1.0 : 0.0;
                    }
                };
                e.inputs = 2;
                return e;
            }
            case "NetSink":
                return new NetEnd(id, params, true);
            case "NetSource":
                return new NetEnd(id, params, false);
            default:
                throw new IllegalArgumentException("element '" + id + "': unknown element type '" + type + "'");
        }
    }

    /** A stream end: NetSink publishes its input, NetSource outputs the next received value (waiting for it). */
    final class NetEnd extends Element {
        final boolean sink;
        final StreamConfig config = new StreamConfig();
        long handle;

        @SuppressWarnings("unchecked")
        NetEnd(String id, Map<String, Object> params, boolean sink) {
            super(id);
            this.sink = sink;
            this.inputs = sink ? 1 : 0;
            config.streamId = WireFormat.parseStreamId((String) params.get("stream_id"));
            if (!"F64".equals(params.getOrDefault("type", "F64"))) {
                throw new IllegalArgumentException("s7java graphs carry F64 streams only");
            }
            config.type = WireType.F64;
            for (String name : new String[]{"max_elements_per_packet", "max_batch_latency_ms", "send_log_max_packets", "max_block_ms", "max_wait_ms"}) {
                if (params.containsKey(name)) {
                    long value = ((Number) params.get(name)).longValue();
                    switch (name) {
                        case "max_elements_per_packet" -> config.maxElementsPerPacket = value;
                        case "max_batch_latency_ms" -> config.maxBatchLatencyMs = value;
                        case "send_log_max_packets" -> config.sendLogMaxPackets = value;
                        case "max_block_ms" -> config.maxBlockMs = value;
                        default -> config.maxWaitMs = value;
                    }
                }
            }
            config.producerNode = (String) params.getOrDefault("producer_node", "");
            config.consumerNodes = new ArrayList<>((List<String>) params.getOrDefault("consumer_nodes", List.of()));
            if (params.get("sample_rate") instanceof List<?> rate) {
                config.sampleRate = new long[]{((Number) rate.get(0)).longValue(), ((Number) rate.get(1)).longValue()};
            }
            for (Object role : (List<Object>) params.getOrDefault("timestamps", List.of())) {
                config.timestampRoles.add(WireFormat.parseRole((String) role));
            }
            config.timestampRoles.sort(null);
            if (params.get("max_latency_ms") instanceof Number latency) {
                config.maxLatencyMs = latency.longValue();
            }
            if (sink && config.explicitTimestamps() && config.timestampRoles.stream().anyMatch(r -> r != WireFormat.PROCESSING_TIME)) {
                throw new IllegalArgumentException("a NetSink without a sample_rate stamps PROCESSING_TIME only");
            }
        }

        @Override
        void step(double[] in) throws InterruptedException {
            if (handle == 0) {
                handle = table.open(config, sink ? StreamTable.PRODUCER : StreamTable.CONSUMER);
            }
            String fault;
            if (sink) {
                BigInteger bits = new BigInteger(Long.toUnsignedString(Double.doubleToRawLongBits(in[0])));
                List<WireFormat.TimestampRecord> times = new ArrayList<>();
                if (config.explicitTimestamps()) {
                    java.time.Instant now = java.time.Instant.now();
                    for (int role : config.timestampRoles) {
                        times.add(new WireFormat.TimestampRecord(role, now.getEpochSecond() * 1_000_000_000L + now.getNano()));
                    }
                }
                List<BigInteger[]> one = new ArrayList<>();
                one.add(new BigInteger[]{bits});
                fault = table.publish(handle, one, times);
            } else {
                StreamTable.Received received = table.receive(handle, 1);
                if (!received.elements().isEmpty()) {
                    output = Double.longBitsToDouble(received.elements().get(0)[0].longValue());
                }
                fault = received.fault();
            }
            if (fault != null) {
                throw new IllegalStateException((sink ? "NetSink" : "NetSource") + " stream " + WireFormat.streamIdText(config.streamId)
                        + " faulted: " + fault + ".");
            }
        }
    }
}

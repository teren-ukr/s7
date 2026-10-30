// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.node;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import s7.json.Json;
import s7.net.DataEndpoint;
import s7.net.StreamTable;
import s7.net.Tls;
import s7.stream.SequenceStore;

/**
 * A minimal S7 node in Java for the data plane: it runs its part of a deployed diagram (the file a
 * deployment wrote, for example by s7ctl deploy --write) and exchanges its streams with the other
 * nodes over mTLS /data connections. It has no control plane: it takes its part from the file
 * instead of PREPARE / COMMIT, and reports its streams' status (in the GET_STREAM_STATUS form) to a file.
 *
 * <p>Usage: java -cp build s7.node.DataNode --diagram FILE --cert PEM --key PEM --ca PEM --port N
 * [--state-dir DIR] [--watch ELEMENT]... [--status-file FILE] [--serve-seconds S] [--activate-at-ns UTC_NS]
 *
 * <p>The graph steps on the UTC grid activate-at + n * dt (default: from start), as a committed
 * deployment with activate_at_ns does on the other nodes.
 */
public final class DataNode {
    private static void log(String message) {
        System.out.println(message);
        System.out.flush();
    }

    private static long utcNowNs() {
        Instant now = Instant.now();
        return now.getEpochSecond() * 1_000_000_000L + now.getNano();
    }

    @SuppressWarnings("unchecked")
    public static void main(String[] args) throws Exception {
        Map<String, String> options = new LinkedHashMap<>();
        List<String> watches = new ArrayList<>();
        for (int i = 0; i + 1 < args.length; i += 2) {
            if (args[i].equals("--watch")) {
                watches.add(args[i + 1]);
            } else {
                options.put(args[i], args[i + 1]);
            }
        }
        for (String required : new String[]{"--diagram", "--cert", "--key", "--ca", "--port"}) {
            if (!options.containsKey(required)) {
                System.err.println("error: " + required + " is required");
                System.exit(2);
            }
        }
        Path cert = Path.of(options.get("--cert"));
        String node = Tls.nodeUuidOfFile(cert);
        if (node.isEmpty()) {
            System.err.println("error: the certificate must carry exactly one SAN URI spiffe://s7/node/<node_uuid>");
            System.exit(1);
        }
        SSLContext tls = Tls.context(cert, Path.of(options.get("--key")), Path.of(options.get("--ca")));
        Map<String, Object> diagram = (Map<String, Object>) Json.parse(Files.readString(Path.of(options.get("--diagram"))));
        NodePart part = new NodePart(diagram, node);
        Path state = Path.of(options.getOrDefault("--state-dir", System.getProperty("java.io.tmpdir") + "/s7java-" + node));
        StreamTable table = new StreamTable(new SequenceStore.FileStore(state.resolve("streams")));
        Graph graph = new Graph(part.schema, table);
        DataEndpoint endpoint = new DataEndpoint(table, node, tls, DataNode::log);
        int port = endpoint.listen("127.0.0.1", Integer.parseInt(options.get("--port")));
        log("runtime.node_uuid=" + node);
        log("runtime.data_listen_url=wss://127.0.0.1:" + port + "/data");
        log("runtime.graph.active name=" + part.schema.get("name") + " elements=" + ((List<Object>) part.schema.get("elements")).size()
                + " pacing=" + (part.stepNs != null ? "grid period_ns=" + part.stepNs : "none"));
        endpoint.setDataPeers(part.dataPeers);

        Path statusFile = options.containsKey("--status-file") ? Path.of(options.get("--status-file")) : null;
        long serveUntil = options.containsKey("--serve-seconds")
                ? System.nanoTime() + (long) (Double.parseDouble(options.get("--serve-seconds")) * 1e9) : Long.MAX_VALUE;
        long origin = options.containsKey("--activate-at-ns") ? Long.parseLong(options.get("--activate-at-ns")) : utcNowNs();
        Thread stepping = new Thread(() -> step(graph, part.stepNs, watches, origin));
        stepping.setDaemon(true);
        stepping.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> writeStatus(statusFile, table, graph)));
        while (System.nanoTime() < serveUntil) {
            Thread.sleep(500);
            writeStatus(statusFile, table, graph);
        }
        writeStatus(statusFile, table, graph);
        endpoint.close();
        System.exit(0);
    }

    /** Steps on the UTC grid origin + n * dt (catching up when behind), until a step fails (a stream fault). */
    private static void step(Graph graph, Long stepNs, List<String> watches, long origin) {
        long period = stepNs != null ? stepNs : 1_000_000_000L;
        long lastWatch = 0;
        try {
            while (true) {
                long due = origin + graph.steps * period;
                long wait = due - utcNowNs();
                if (wait > 0) {
                    Thread.sleep(wait / 1_000_000, (int) (wait % 1_000_000));
                    continue;
                }
                graph.step();
                long now = System.nanoTime();
                if (!watches.isEmpty() && now - lastWatch >= 1_000_000_000L) {
                    lastWatch = now;
                    StringBuilder line = new StringBuilder("watch step=" + graph.steps);
                    for (String id : watches) {
                        Double value = graph.sample(id);
                        if (value != null) {
                            line.append(' ').append(id).append('=').append(value % 1 == 0 && Math.abs(value) < 1e15
                                    ? Long.toString(value.longValue()) : value.toString());
                        }
                    }
                    log(line.toString());
                }
            }
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
        } catch (RuntimeException ex) {
            log("runtime.execution.stopped=error step=" + graph.steps + " error=" + ex.getMessage());
        }
    }

    private static synchronized void writeStatus(Path file, StreamTable table, Graph graph) {
        if (file == null) {
            return;
        }
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("type", "STREAM_STATUS");
        status.put("steps", graph.steps);
        status.put("streams", table.statuses());
        try {
            Path temporary = file.resolveSibling(file.getFileName() + ".tmp");
            Files.writeString(temporary, Json.write(status));
            Files.move(temporary, file, java.nio.file.StandardCopyOption.REPLACE_EXISTING, java.nio.file.StandardCopyOption.ATOMIC_MOVE);
        } catch (java.io.IOException ex) {
            log("runtime.status.error=" + ex.getMessage());
        }
    }
}

// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.net;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

import s7.stream.Faults;
import s7.stream.StreamConfig;
import s7.wire.WireFormat;
import s7.wire.WireFormat.ControlMessage;
import s7.wire.WireFormat.DataPacket;

/**
 * The /data connections of a node (s7transport transport.cpp BeastRuntimeNetEndpoint). A consumer
 * node connects to the /data endpoint of each producer node of its streams and RESUMEs every stream
 * it consumes from that node after each (re)connect; the producer replays from its send log and
 * continues. Each side announces its node UUID in the handshake (S7-Node). A connection's peer node
 * is the node of its verified certificate over TLS, otherwise the announced (or configured) one.
 * Blocking sockets: a reader thread per connection, a writer thread with a bounded queue, a 1 ms tick.
 */
public final class DataEndpoint implements AutoCloseable {
    public static final String NODE_HEADER = "S7-Node";
    private static final int MAX_QUEUED_WRITES = 64;
    private static final long RECONNECT_MS = 1000;
    private static final int MAX_DATA_MESSAGE_BYTES = WireFormat.MAX_PAYLOAD_BYTES + 4096;

    public record DataPeer(String url, String nodeUuid) {
    }

    final class Connection {
        final WebSocket ws;
        final boolean outbound;
        final DataPeer link;
        String peerNode = "";
        String consumerKey = "anonymous";
        final Set<Long> resumed = new HashSet<>();
        final Map<Long, Long> producing = new HashMap<>(); // their alias -> local handle
        final Map<Long, Long> producingAlias = new HashMap<>(); // local handle -> their alias
        final Map<String, ControlMessage> pendingResumes = new HashMap<>();
        final LinkedBlockingQueue<byte[]> writes = new LinkedBlockingQueue<>();
        volatile boolean closed;

        Connection(WebSocket ws, boolean outbound, DataPeer link) {
            this.ws = ws;
            this.outbound = outbound;
            this.link = link;
        }
    }

    private final StreamTable table;
    private final String nodeUuid;
    private final SSLContext tls; // null: plain WebSocket
    private final Consumer<String> log;
    private final Set<Connection> connections = ConcurrentHashMap.newKeySet();
    private final Map<String, DataPeer> links = new ConcurrentHashMap<>();
    private final Map<Long, Connection> consumerSources = new HashMap<>(); // consumer handle -> its data source (table monitor)
    private final Map<String, Connection> routes = new HashMap<>(); // producer handle + consumer key -> connection (table monitor)
    private final ScheduledExecutorService timers = Executors.newScheduledThreadPool(1, daemon("s7-data-timer"));
    public final ArrayDeque<String> errors = new ArrayDeque<>();
    private ServerSocket server;
    private volatile boolean stopping;

    public DataEndpoint(StreamTable table, String nodeUuid, SSLContext tls, Consumer<String> log) {
        this.table = table;
        this.nodeUuid = nodeUuid;
        this.tls = tls;
        this.log = log;
        table.onProducerData = entry -> timers.execute(this::pumpAll);
        table.onConsumerOpened = entry -> {
            ControlMessage resume = entry.consumer.resumeMessage();
            String producerNode = entry.config.producerNode;
            for (Connection connection : connections) {
                if (!connection.closed && mayProduce(connection, producerNode)) {
                    connection.resumed.add(resume.streamAlias());
                    send(connection, WireFormat.encodeControlMessage(resume));
                }
            }
        };
        timers.scheduleAtFixedRate(this::tick, 1, 1, TimeUnit.MILLISECONDS);
    }

    private static java.util.concurrent.ThreadFactory daemon(String name) {
        return runnable -> {
            Thread thread = new Thread(runnable, name);
            thread.setDaemon(true);
            return thread;
        };
    }

    private static void start(String name, Runnable body) {
        Thread thread = new Thread(body, name);
        thread.setDaemon(true);
        thread.start();
    }

    private synchronized void recordError(String error) {
        if (errors.size() == 32) {
            errors.pollFirst();
        }
        errors.addLast(error);
        log.accept("runtime.transport.error=" + error);
    }

    static boolean mayProduce(Connection connection, String producerNode) {
        return producerNode.isEmpty() || connection.peerNode.equals(producerNode);
    }

    static boolean mayConsume(Connection connection, StreamConfig config) {
        return config.consumerNodes.isEmpty() || config.consumerNodes.contains(connection.peerNode);
    }

    static String describe(Connection connection) {
        return connection.peerNode.isEmpty() ? "an unidentified peer" : "node " + connection.peerNode;
    }

    // ---- server ------------------------------------------------------------------------------

    /** Accepts /data connections on the port (0: any); returns the port. */
    public int listen(String bindAddress, int port) throws IOException {
        if (tls != null) {
            SSLServerSocket socket = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket();
            socket.setNeedClientAuth(true); // every data peer is a node with its certificate
            server = socket;
        } else {
            server = new ServerSocket();
        }
        server.bind(new InetSocketAddress(bindAddress, port));
        start("s7-data-accept", () -> {
            while (!stopping) {
                try {
                    Socket socket = server.accept();
                    socket.setTcpNoDelay(true);
                    start("s7-data-inbound", () -> serveInbound(socket));
                } catch (IOException ex) {
                    if (!stopping) {
                        recordError("accept failed: " + ex.getMessage());
                    }
                }
            }
        });
        return server.getLocalPort();
    }

    private void serveInbound(Socket socket) {
        try {
            socket.setSoTimeout(10_000);
            WebSocket ws = WebSocket.accept(socket, new String[]{"/data"}, MAX_DATA_MESSAGE_BYTES, Map.of(NODE_HEADER, nodeUuid));
            if (ws == null) {
                return;
            }
            socket.setSoTimeout(0);
            run(new Connection(ws, false, null), ws.headers.getOrDefault(NODE_HEADER.toLowerCase(), ""));
        } catch (IOException ex) {
            try {
                socket.close();
            } catch (IOException ignored) {
                // gone
            }
        }
    }

    // ---- connections -------------------------------------------------------------------------

    private void run(Connection connection, String claimedNode) {
        X509Certificate certificate = connection.ws.socket instanceof SSLSocket s ? Tls.peer(s.getSession()) : null;
        if (connection.ws.socket instanceof SSLSocket) {
            connection.peerNode = certificate != null ? Tls.nodeUuid(certificate) : "";
        } else {
            connection.peerNode = !claimedNode.isEmpty() ? claimedNode : connection.link != null ? connection.link.nodeUuid() : "";
        }
        if (certificate != null) {
            connection.consumerKey = Tls.fingerprint(certificate);
        } else if (!connection.peerNode.isEmpty()) {
            connection.consumerKey = "node:" + connection.peerNode;
        }
        connections.add(connection);
        start("s7-data-writer", () -> writer(connection));
        onDataConnection(connection);
        Object message;
        while ((message = connection.ws.receive()) != null) {
            if (message instanceof byte[] bytes) {
                onMessage(connection, bytes);
            }
            if (connection.closed) {
                break;
            }
        }
        close(connection);
    }

    /** Resumes every local consumer stream on a new data connection. */
    private void onDataConnection(Connection connection) {
        List<byte[]> resumes = new ArrayList<>();
        synchronized (table) {
            for (StreamTable.Entry entry : table.entries.values()) {
                if (entry.consumer != null && mayProduce(connection, entry.config.producerNode)) {
                    ControlMessage resume = entry.consumer.resumeMessage();
                    connection.resumed.add(resume.streamAlias());
                    resumes.add(WireFormat.encodeControlMessage(resume));
                }
            }
        }
        resumes.forEach(message -> send(connection, message));
    }

    private void send(Connection connection, byte[] message) {
        if (!connection.closed) {
            connection.writes.add(message);
        }
    }

    private void writer(Connection connection) {
        try {
            while (!connection.closed) {
                byte[] message = connection.writes.poll(100, TimeUnit.MILLISECONDS);
                if (message == null) {
                    continue;
                }
                connection.ws.send(message);
                if (connection.writes.size() < MAX_QUEUED_WRITES / 2) {
                    pumpConnection(connection);
                }
            }
        } catch (IOException | InterruptedException ex) {
            close(connection);
        }
    }

    private void close(Connection connection) {
        synchronized (table) {
            if (connection.closed && !connections.contains(connection)) {
                return;
            }
            connection.closed = true;
            for (long handle : connection.producingAlias.keySet()) {
                String key = handle + "|" + connection.consumerKey;
                if (routes.get(key) == connection) {
                    routes.remove(key);
                    StreamTable.Entry entry = table.entries.get(handle);
                    if (entry != null && entry.producer != null) {
                        entry.producer.detach(connection.consumerKey);
                    }
                }
            }
            connections.remove(connection);
        }
        connection.ws.abort();
        if (connection.outbound && connection.link != null) {
            scheduleReconnect(connection.link);
        }
    }

    private void onMessage(Connection connection, byte[] message) {
        try {
            if (WireFormat.isControlMessage(message)) {
                onStreamControl(connection, WireFormat.decodeControlMessage(message));
            } else {
                onDataPacket(connection, WireFormat.decodeDataPacket(message));
            }
        } catch (WireFormat.FormatError ex) {
            recordError("malformed message from peer: " + ex.getMessage());
            close(connection); // the peer reconnects and resumes
        }
    }

    private void onStreamControl(Connection connection, ControlMessage message) {
        synchronized (table) {
            if (message.kind() == WireFormat.ACK) {
                Long handle = connection.producing.get(message.streamAlias());
                StreamTable.Entry entry = handle != null ? table.entries.get(handle) : null;
                if (entry != null && entry.producer != null) {
                    entry.producer.acknowledge(connection.consumerKey, message.nextExpected());
                    table.notifyAll();
                }
            } else {
                long next = message.kind() == WireFormat.RESUME_NO_STATE ? 0 : message.nextExpected();
                StreamTable.Entry entry = table.findProducer(message.streamId());
                if (entry == null) {
                    // Not produced here (yet): remember it in case the producer opens later.
                    connection.pendingResumes.put(Arrays.toString(message.streamId()),
                            new ControlMessage(message.kind(), message.streamAlias(), next, message.streamId()));
                    return;
                }
                if (!attach(connection, entry, message.streamAlias(), next)) {
                    return;
                }
            }
        }
        pumpConnection(connection);
    }

    /** Monitor held. The latest RESUME wins; a peer that is not a configured consumer is refused. */
    private boolean attach(Connection connection, StreamTable.Entry entry, long alias, long next) {
        if (!mayConsume(connection, entry.config)) {
            entry.unauthorized++;
            entry.note(Faults.UNAUTHORIZED_CONSUMER, describe(connection));
            recordError("refused RESUME of stream " + WireFormat.streamIdText(entry.config.streamId) + " from "
                    + describe(connection) + ": not a configured consumer");
            return false;
        }
        String key = entry.handle + "|" + connection.consumerKey;
        Connection previous = routes.get(key);
        if (previous != null && previous != connection) {
            Long theirAlias = previous.producingAlias.remove(entry.handle);
            if (theirAlias != null) {
                previous.producing.remove(theirAlias);
            }
        }
        routes.put(key, connection);
        entry.producer.resume(connection.consumerKey, alias, next);
        connection.producing.put(alias, entry.handle);
        connection.producingAlias.put(entry.handle, alias);
        table.notifyAll();
        return true;
    }

    private void onDataPacket(Connection connection, DataPacket packet) {
        String refused = null;
        synchronized (table) {
            StreamTable.Entry entry = table.findConsumerByAlias(packet.streamAlias());
            if (entry == null) {
                return; // a stream closed meanwhile
            }
            if (!connection.resumed.contains(packet.streamAlias())) {
                // Not RESUMEd here: this peer is not the stream's producer.
                entry.unauthorized++;
                entry.note(Faults.UNAUTHORIZED_PRODUCER, describe(connection));
                refused = WireFormat.streamIdText(entry.config.streamId);
            } else {
                if (entry.consumer.onPacket(packet, System.nanoTime(), null)) {
                    entry.noteLate();
                }
                consumerSources.put(entry.handle, connection);
                table.notifyAll();
            }
        }
        if (refused != null) {
            recordError("refused packets of stream " + refused + " from " + describe(connection) + ": not the configured producer");
            close(connection);
        }
    }

    private void pumpAll() {
        for (Connection connection : connections) {
            if (!connection.closed) {
                applyPendingResumes(connection);
                pumpConnection(connection);
            }
        }
    }

    private void applyPendingResumes(Connection connection) {
        synchronized (table) {
            for (String id : new ArrayList<>(connection.pendingResumes.keySet())) {
                ControlMessage message = connection.pendingResumes.get(id);
                StreamTable.Entry entry = table.findProducer(message.streamId());
                if (entry != null) {
                    connection.pendingResumes.remove(id);
                    attach(connection, entry, message.streamAlias(), message.nextExpected());
                }
            }
        }
    }

    /** Sends the producer streams' next packets, bounded by the write queue. */
    private void pumpConnection(Connection connection) {
        if (connection.closed) {
            return;
        }
        synchronized (table) {
            boolean progress = true;
            while (progress && connection.writes.size() < MAX_QUEUED_WRITES) {
                progress = false;
                for (long handle : new ArrayList<>(connection.producingAlias.keySet())) {
                    StreamTable.Entry entry = table.entries.get(handle);
                    if (entry == null) {
                        continue;
                    }
                    byte[] message = entry.producer.nextMessage(connection.consumerKey);
                    if (message != null) {
                        send(connection, message);
                        progress = true;
                    }
                }
            }
        }
    }

    /** Every millisecond: flush due batches and send due acknowledgements. */
    private void tick() {
        try {
            long now = System.nanoTime();
            boolean flushed = false;
            List<Map.Entry<Connection, byte[]>> acks = new ArrayList<>();
            synchronized (table) {
                for (StreamTable.Entry entry : table.entries.values()) {
                    if (entry.producer != null) {
                        flushed |= entry.producer.flush(now, false);
                    } else {
                        ControlMessage ack = entry.consumer.ackDue(now);
                        Connection source = consumerSources.get(entry.handle);
                        if (ack != null && source != null) {
                            acks.add(Map.entry(source, WireFormat.encodeControlMessage(ack)));
                        }
                    }
                }
                if (flushed) {
                    table.notifyAll();
                }
            }
            acks.forEach(ack -> send(ack.getKey(), ack.getValue()));
            if (flushed) {
                connections.forEach(this::pumpConnection);
            }
        } catch (RuntimeException ex) {
            recordError("tick: " + ex);
        }
    }

    // ---- data peers (consumer side) ---------------------------------------------------------------

    /** Connects to every producer node of this node's consumer streams. */
    public void setDataPeers(List<DataPeer> peers) {
        for (DataPeer peer : peers) {
            String key = peer.url() + "#" + peer.nodeUuid();
            if (links.putIfAbsent(key, peer) == null) {
                timers.execute(() -> connect(peer));
            }
        }
    }

    private final Set<DataPeer> reconnecting = ConcurrentHashMap.newKeySet();

    private void scheduleReconnect(DataPeer peer) {
        if (!stopping && reconnecting.add(peer)) {
            timers.schedule(() -> {
                reconnecting.remove(peer);
                connect(peer);
            }, RECONNECT_MS, TimeUnit.MILLISECONDS);
        }
    }

    private void connect(DataPeer peer) {
        start("s7-data-outbound", () -> {
            URI url = URI.create(peer.url());
            boolean secure = url.getScheme().equals("wss");
            String host = url.getHost().startsWith("[") ? url.getHost().substring(1, url.getHost().length() - 1) : url.getHost();
            String path = url.getRawPath() == null || url.getRawPath().isEmpty() ? "/" : url.getRawPath();
            for (String suffix : new String[]{"/control", "/data"}) {
                if (path.endsWith(suffix)) {
                    path = path.substring(0, path.length() - suffix.length());
                    break;
                }
            }
            path = (path.endsWith("/") ? path.substring(0, path.length() - 1) : path) + "/data";
            try {
                if (secure && tls == null) {
                    throw new IOException("data peer " + peer.url() + " needs TLS, but this node has no TLS credentials");
                }
                if (secure && !Boolean.getBoolean("s7.tls.resume")) {
                    // A fresh full handshake on every (re)connect: the C++ node's TLS server verifies client
                    // certificates without a session id context, so it answers a resumption with internal_error.
                    javax.net.ssl.SSLSessionContext sessions = tls.getClientSessionContext();
                    for (java.util.Enumeration<byte[]> ids = sessions.getIds(); ids.hasMoreElements(); ) {
                        javax.net.ssl.SSLSession cached = sessions.getSession(ids.nextElement());
                        if (cached != null) {
                            cached.invalidate();
                        }
                    }
                }
                Socket socket = secure ? tls.getSocketFactory().createSocket() : new Socket();
                socket.setTcpNoDelay(true);
                socket.connect(new InetSocketAddress(host, url.getPort()), 10_000);
                socket.setSoTimeout(10_000);
                if (socket instanceof SSLSocket s) {
                    s.startHandshake();
                }
                WebSocket ws = WebSocket.connect(socket, host, url.getPort(), path, MAX_DATA_MESSAGE_BYTES, Map.of(NODE_HEADER, nodeUuid));
                socket.setSoTimeout(0);
                String claimed = ws.headers.getOrDefault(NODE_HEADER.toLowerCase(), "");
                String expected = peer.nodeUuid();
                if (socket instanceof SSLSocket s) {
                    X509Certificate certificate = Tls.peer(s.getSession());
                    if (!expected.isEmpty() && (certificate == null || !Tls.nodeUuid(certificate).equals(expected))) {
                        recordError("data peer " + host + ":" + url.getPort() + " is not node " + expected + " (certificate identity mismatch)");
                        ws.abort();
                        scheduleReconnect(peer);
                        return;
                    }
                } else if (!expected.isEmpty() && !claimed.isEmpty() && !claimed.equals(expected)) {
                    recordError("data peer " + host + ":" + url.getPort() + " is node " + claimed + ", not node " + expected + " (identity mismatch)");
                    ws.abort();
                    scheduleReconnect(peer);
                    return;
                }
                run(new Connection(ws, true, peer), claimed);
            } catch (IOException ex) {
                log.accept("runtime.transport.connect_failed url=" + peer.url() + " error=" + ex.getMessage());
                scheduleReconnect(peer);
            }
        });
    }

    @Override
    public void close() {
        stopping = true;
        timers.shutdownNow();
        for (Connection connection : connections) {
            connection.ws.abort();
        }
        if (server != null) {
            try {
                server.close();
            } catch (IOException ignored) {
                // closing
            }
        }
    }
}

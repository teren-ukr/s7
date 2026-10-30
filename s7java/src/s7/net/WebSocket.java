// SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
// SPDX-License-Identifier: GPL-3.0-or-later

package s7.net;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Minimal RFC 6455 WebSocket over a blocking socket (server and client): binary and text messages,
 * fragmentation, ping/pong and the closing handshake; no extensions. Enough for /data.
 */
public final class WebSocket implements AutoCloseable {
    private static final String GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    private static final int OP_CONTINUATION = 0x0, OP_TEXT = 0x1, OP_BINARY = 0x2, OP_CLOSE = 0x8, OP_PING = 0x9, OP_PONG = 0xA;
    private static final SecureRandom RANDOM = new SecureRandom();

    public final Socket socket;
    private final DataInputStream in;
    private final OutputStream out;
    private final boolean client;
    private final int maxMessageBytes;
    public final String path;
    /** The peer's handshake headers, lower-case names. */
    public final Map<String, String> headers;
    private volatile boolean closed;

    private WebSocket(Socket socket, InputStream in, boolean client, int maxMessageBytes, String path, Map<String, String> headers)
            throws IOException {
        this.socket = socket;
        this.in = new DataInputStream(in);
        this.out = socket.getOutputStream();
        this.client = client;
        this.maxMessageBytes = maxMessageBytes;
        this.path = path;
        this.headers = headers;
    }

    private static String acceptKey(String key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-1").digest((key + GUID).getBytes(StandardCharsets.US_ASCII));
            return Base64.getEncoder().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    /** The HTTP head up to the blank line: the request or status line, then lower-case headers. */
    private static String[] readHead(InputStream in, Map<String, String> headers) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int last4 = 0; // the last four bytes read, oldest in the top byte
        while (last4 != 0x0D0A0D0A) { // "\r\n\r\n"
            int b = in.read();
            if (b < 0) {
                throw new EOFException("connection closed during the handshake");
            }
            head.write(b);
            if (head.size() > 16 * 1024) {
                throw new IOException("HTTP header too large");
            }
            last4 = last4 << 8 | b;
        }
        String[] lines = head.toString(StandardCharsets.ISO_8859_1).split("\r\n");
        for (int i = 1; i < lines.length; i++) {
            int colon = lines[i].indexOf(':');
            if (colon > 0) {
                headers.put(lines[i].substring(0, colon).strip().toLowerCase(Locale.ROOT), lines[i].substring(colon + 1).strip());
            }
        }
        return lines;
    }

    private static String headerLines(Map<String, String> headers) {
        StringBuilder out = new StringBuilder();
        headers.forEach((name, value) -> out.append(name).append(": ").append(value).append("\r\n"));
        return out.toString();
    }

    /** Server side of the opening handshake; null (after an HTTP error) if refused. */
    public static WebSocket accept(Socket socket, String[] paths, int maxMessageBytes, Map<String, String> responseHeaders) throws IOException {
        InputStream in = socket.getInputStream();
        Map<String, String> headers = new LinkedHashMap<>();
        String[] request = readHead(in, headers)[0].split(" ");
        OutputStream out = socket.getOutputStream();
        String path = request.length > 1 ? request[1].split("\\?", 2)[0] : "";
        boolean upgrade = request[0].equals("GET") && headers.getOrDefault("upgrade", "").toLowerCase(Locale.ROOT).contains("websocket")
                && headers.containsKey("sec-websocket-key") && "13".equals(headers.get("sec-websocket-version"));
        if (!upgrade || !java.util.Arrays.asList(paths).contains(path)) {
            out.write(((upgrade ? "HTTP/1.1 404 Not Found" : "HTTP/1.1 400 Bad Request") + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            socket.close();
            return null;
        }
        out.write(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
                + acceptKey(headers.get("sec-websocket-key")) + "\r\n" + headerLines(responseHeaders) + "\r\n").getBytes(StandardCharsets.US_ASCII));
        out.flush();
        return new WebSocket(socket, in, false, maxMessageBytes, path, headers);
    }

    /** Client side: performs the handshake on a connected socket, sending headers with the request. */
    public static WebSocket connect(Socket socket, String host, int port, String path, int maxMessageBytes, Map<String, String> requestHeaders)
            throws IOException {
        byte[] nonce = new byte[16];
        RANDOM.nextBytes(nonce);
        String key = Base64.getEncoder().encodeToString(nonce);
        OutputStream out = socket.getOutputStream();
        out.write(("GET " + path + " HTTP/1.1\r\nHost: " + host + ":" + port + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                + "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n" + headerLines(requestHeaders) + "\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        InputStream in = socket.getInputStream();
        Map<String, String> headers = new LinkedHashMap<>();
        String status = readHead(in, headers)[0];
        if (!(status + " ").contains(" 101 ") || !acceptKey(key).equals(headers.get("sec-websocket-accept"))) {
            socket.close();
            throw new IOException("handshake refused: " + status);
        }
        return new WebSocket(socket, in, true, maxMessageBytes, path, headers);
    }

    private synchronized void sendFrame(int opcode, byte[] payload) throws IOException {
        ByteArrayOutputStream frame = new ByteArrayOutputStream(payload.length + 14);
        frame.write(0x80 | opcode);
        int mask = client ? 0x80 : 0;
        if (payload.length < 126) {
            frame.write(mask | payload.length);
        } else if (payload.length < 1 << 16) {
            frame.write(mask | 126);
            frame.write(payload.length >>> 8);
            frame.write(payload.length & 0xFF);
        } else {
            frame.write(mask | 127);
            for (int shift = 56; shift >= 0; shift -= 8) {
                frame.write((int) ((long) payload.length >>> shift) & 0xFF);
            }
        }
        if (client) {
            byte[] key = new byte[4];
            RANDOM.nextBytes(key);
            frame.writeBytes(key);
            byte[] masked = new byte[payload.length];
            for (int i = 0; i < payload.length; i++) {
                masked[i] = (byte) (payload[i] ^ key[i & 3]);
            }
            frame.writeBytes(masked);
        } else {
            frame.writeBytes(payload);
        }
        out.write(frame.toByteArray());
        out.flush();
    }

    public void send(byte[] message) throws IOException {
        if (closed) {
            throw new IOException("connection is closed");
        }
        sendFrame(OP_BINARY, message);
    }

    /** The next message (byte[] binary, String text), or null once the connection has closed. */
    public Object receive() {
        ByteArrayOutputStream message = new ByteArrayOutputStream();
        int opcode = -1;
        try {
            while (true) {
                int first = in.readUnsignedByte();
                int second = in.readUnsignedByte();
                boolean fin = (first & 0x80) != 0;
                int frameOpcode = first & 0x0F;
                if ((first & 0x70) != 0) {
                    throw new IOException("reserved bits set");
                }
                boolean masked = (second & 0x80) != 0;
                if (masked == client) {
                    throw new IOException("frames from a client must be masked, from a server unmasked");
                }
                long length = second & 0x7F;
                if (length == 126) {
                    length = in.readUnsignedShort();
                } else if (length == 127) {
                    length = in.readLong();
                }
                if (length < 0 || length > maxMessageBytes || message.size() + length > maxMessageBytes) {
                    throw new IOException("message too large");
                }
                byte[] key = new byte[4];
                if (masked) {
                    in.readFully(key);
                }
                byte[] payload = new byte[(int) length];
                in.readFully(payload);
                if (masked) {
                    for (int i = 0; i < payload.length; i++) {
                        payload[i] ^= key[i & 3];
                    }
                }
                if (frameOpcode == OP_PING) {
                    sendFrame(OP_PONG, payload);
                    continue;
                }
                if (frameOpcode == OP_PONG) {
                    continue;
                }
                if (frameOpcode == OP_CLOSE) {
                    close();
                    return null;
                }
                if (frameOpcode != OP_CONTINUATION) {
                    if (opcode != -1) {
                        throw new IOException("new message before the previous one ended");
                    }
                    opcode = frameOpcode;
                } else if (opcode == -1) {
                    throw new IOException("continuation without a message");
                }
                message.writeBytes(payload);
                if (fin) {
                    return opcode == OP_TEXT ? message.toString(StandardCharsets.UTF_8) : message.toByteArray();
                }
            }
        } catch (IOException ex) {
            abort();
            return null;
        }
    }

    @Override
    public void close() {
        if (!closed) {
            closed = true;
            try {
                sendFrame(OP_CLOSE, new byte[]{0x03, (byte) 0xE8});
            } catch (IOException ignored) {
                // already gone
            }
        }
        abort();
    }

    /** Closes the socket at once. */
    public void abort() {
        closed = true;
        try {
            socket.close();
        } catch (IOException ignored) {
            // nothing left to release
        }
    }

    public boolean isClosed() {
        return closed;
    }
}

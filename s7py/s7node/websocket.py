# SPDX-FileCopyrightText: Oleksiy Lukin and S7 contributors
# SPDX-License-Identifier: GPL-3.0-or-later

"""Minimal RFC 6455 WebSocket over asyncio streams (server and client).

Enough for the S7 control protocol: text and binary messages, fragmentation,
ping/pong and the closing handshake. No extensions (no permessage-deflate).
"""
import asyncio
import base64
import hashlib
import os
import struct

_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_MAX_HEADER_BYTES = 16 * 1024

OP_CONTINUATION, OP_TEXT, OP_BINARY, OP_CLOSE, OP_PING, OP_PONG = 0x0, 0x1, 0x2, 0x8, 0x9, 0xA


class WebSocketError(Exception):
    pass


def _apply_mask(payload: bytes, mask: bytes) -> bytes:
    size = len(payload)
    key = (mask * (size // 4 + 1))[:size]
    return (int.from_bytes(payload, "little") ^ int.from_bytes(key, "little")).to_bytes(size, "little")


def _accept_key(key: str) -> str:
    return base64.b64encode(hashlib.sha1(key.encode("ascii") + _GUID).digest()).decode("ascii")


async def _read_http_head(reader: asyncio.StreamReader) -> list[str]:
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError as error:
        raise WebSocketError("HTTP header too large") from error
    except asyncio.IncompleteReadError as error:
        raise WebSocketError("connection closed during the handshake") from error
    if len(head) > _MAX_HEADER_BYTES:
        raise WebSocketError("HTTP header too large")
    return head.decode("latin-1").split("\r\n")[:-2]


def _headers(lines: list[str]) -> dict[str, str]:
    headers = {}
    for line in lines:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return headers


class WebSocket:
    def __init__(self, reader, writer, *, is_client: bool, max_message_bytes: int, path: str = "/",
                 headers: dict[str, str] | None = None):
        self.headers = headers or {}  # the peer's handshake headers, lower-case names
        self.reader = reader
        self.writer = writer
        self.is_client = is_client
        self.max_message_bytes = max_message_bytes
        self.path = path
        self.closed = False
        self._send_lock = asyncio.Lock()

    @property
    def ssl_object(self):
        return self.writer.get_extra_info("ssl_object")

    async def _send_frame(self, opcode: int, payload: bytes) -> None:
        header = bytearray([0x80 | opcode])
        mask_bit = 0x80 if self.is_client else 0
        length = len(payload)
        if length < 126:
            header.append(mask_bit | length)
        elif length < 1 << 16:
            header.append(mask_bit | 126)
            header += struct.pack("!H", length)
        else:
            header.append(mask_bit | 127)
            header += struct.pack("!Q", length)
        if self.is_client:
            mask = os.urandom(4)
            header += mask
            payload = _apply_mask(payload, mask)
        async with self._send_lock:
            self.writer.write(bytes(header) + payload)
            await self.writer.drain()

    async def send(self, message: str | bytes) -> None:
        if self.closed:
            raise WebSocketError("connection is closed")
        if isinstance(message, str):
            await self._send_frame(OP_TEXT, message.encode("utf-8"))
        else:
            await self._send_frame(OP_BINARY, message)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if not self.closed:
            self.closed = True
            try:
                await self._send_frame(OP_CLOSE, struct.pack("!H", code) + reason.encode("utf-8")[:120])
            except (ConnectionError, OSError):
                pass
        self.writer.close()

    async def _read_frame(self):
        first, second = await self.reader.readexactly(2)
        fin, opcode = bool(first & 0x80), first & 0x0F
        if first & 0x70:
            raise WebSocketError("reserved bits set (no extension was negotiated)")
        masked, length = bool(second & 0x80), second & 0x7F
        if masked == self.is_client:
            raise WebSocketError("frames from a client must be masked, from a server unmasked")
        if length == 126:
            (length,) = struct.unpack("!H", await self.reader.readexactly(2))
        elif length == 127:
            (length,) = struct.unpack("!Q", await self.reader.readexactly(8))
        if opcode >= OP_CLOSE and (length > 125 or not fin):
            raise WebSocketError("invalid control frame")
        if length > self.max_message_bytes:
            raise WebSocketError("message too large")
        mask = await self.reader.readexactly(4) if masked else None
        payload = await self.reader.readexactly(length)
        if mask:
            payload = _apply_mask(payload, mask)
        return fin, opcode, payload

    async def recv(self) -> str | bytes | None:
        """The next message, or None once the connection has closed."""
        opcode, parts, size = None, [], 0
        try:
            while True:
                fin, frame_opcode, payload = await self._read_frame()
                if frame_opcode == OP_PING:
                    await self._send_frame(OP_PONG, payload)
                    continue
                if frame_opcode == OP_PONG:
                    continue
                if frame_opcode == OP_CLOSE:
                    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1000
                    await self.close(code if code in (1000, 1001) else 1000)
                    return None
                if frame_opcode == OP_CONTINUATION:
                    if opcode is None:
                        raise WebSocketError("continuation without a message")
                elif opcode is not None:
                    raise WebSocketError("new message before the previous one ended")
                else:
                    opcode = frame_opcode
                size += len(payload)
                if size > self.max_message_bytes:
                    raise WebSocketError("message too large")
                parts.append(payload)
                if fin:
                    data = b"".join(parts)
                    return data.decode("utf-8") if opcode == OP_TEXT else data
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            self.closed = True
            self.writer.close()
            return None
        except (WebSocketError, UnicodeDecodeError):
            await self.close(1002)
            return None


def _header_lines(headers: dict[str, str] | None) -> str:
    return "".join(f"{name}: {value}\r\n" for name, value in (headers or {}).items())


async def accept(reader, writer, *, paths: tuple[str, ...], max_message_bytes: int,
                 response_headers: dict[str, str] | None = None) -> WebSocket | None:
    """Server side of the opening handshake; None (after an HTTP error) if refused. response_headers
    are added to the response; the request's headers are on the returned WebSocket."""

    async def refuse(status: str) -> None:
        writer.write(f"HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode("ascii"))
        await writer.drain()
        writer.close()

    lines = await _read_http_head(reader)
    method, target, _ = (lines[0].split(" ") + ["", "", ""])[:3]
    headers = _headers(lines[1:])
    if method != "GET" or "websocket" not in headers.get("upgrade", "").lower() or "sec-websocket-key" not in headers:
        await refuse("400 Bad Request")
        return None
    if headers.get("sec-websocket-version") != "13":
        await refuse("426 Upgrade Required\r\nSec-WebSocket-Version: 13")
        return None
    path = target.split("?", 1)[0]
    if path not in paths:
        await refuse("404 Not Found")
        return None
    writer.write(
        (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {_accept_key(headers['sec-websocket-key'])}\r\n"
            f"{_header_lines(response_headers)}\r\n"
        ).encode("ascii")
    )
    await writer.drain()
    return WebSocket(reader, writer, is_client=False, max_message_bytes=max_message_bytes, path=path, headers=headers)


async def connect(host: str, port: int, path: str, *, ssl=None, max_message_bytes: int = 4 * 1024 * 1024,
                  headers: dict[str, str] | None = None) -> WebSocket:
    """Client side: opens a connection and performs the handshake, sending headers with the request."""
    reader, writer = await asyncio.open_connection(host, port, ssl=ssl, limit=_MAX_HEADER_BYTES * 2)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    writer.write(
        (
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{_header_lines(headers)}\r\n"
        ).encode("ascii")
    )
    await writer.drain()
    lines = await _read_http_head(reader)
    received = _headers(lines[1:])
    if " 101 " not in lines[0] + " " or received.get("sec-websocket-accept") != _accept_key(key):
        writer.close()
        raise WebSocketError(f"handshake refused: {lines[0]}")
    return WebSocket(reader, writer, is_client=True, max_message_bytes=max_message_bytes, path=path, headers=received)

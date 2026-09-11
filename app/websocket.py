"""
RFC 6455, by hand, on top of http.server.

Written rather than installed for the same reason the rest of this app is
standard library only: a terminal is the tool you reach for when a machine is
in a bad way, and "pip install first" is the wrong answer at that moment.
Server-side framing is a couple of hundred lines and every one of them is here.

What it supports, which is exactly what a terminal needs:

  * the opening handshake (Sec-WebSocket-Accept)
  * text and binary frames, including continuation fragments
  * close, with the status code echoed back
  * ping/pong -- and this is the interesting one. A terminal that is being
    watched and not typed into sends nothing for minutes at a time, which is
    long enough for a proxy, a corporate middlebox or a laptop's power manager
    to decide the connection is idle and drop it. A server ping every
    PING_INTERVAL seconds is what keeps it open, and a client that stops
    answering is a client that has already gone away.

What it does not support, because nothing here needs it: extensions
(permessage-deflate), subprotocol negotiation, and client-side framing.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time

# The one constant in the spec, concatenated with the client key and hashed.
# Verified against RFC 6455's own worked example rather than typed from memory
# (see the self-check at the bottom of this file) -- get one character of this
# wrong and the handshake still looks like a 101 to a lenient client while every
# real browser silently drops the connection.
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

# RFC 6455 section 1.3: this key must produce this accept value.
_RFC_EXAMPLE = ("dGhlIHNhbXBsZSBub25jZQ==", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

OP_CONT, OP_TEXT, OP_BINARY = 0x0, 0x1, 0x2
OP_CLOSE, OP_PING, OP_PONG = 0x8, 0x9, 0xA

# How often to ping, and how long to wait for the pong before giving up. The
# interval is short enough to beat the common 60-second idle timeouts and long
# enough that it is invisible in a packet capture of a busy session.
PING_INTERVAL = 20.0
PONG_TIMEOUT = 45.0

# A single frame larger than this is refused. Terminal input is keystrokes; a
# paste is the big case and megabytes of it is a bug or an attack, not a paste.
MAX_FRAME = 4 * 1024 * 1024


class WebSocketError(Exception):
    pass


class WebSocketClosed(WebSocketError):
    """The peer went away. Expected, and not worth a traceback."""


def is_upgrade(headers) -> bool:
    return (headers.get("Upgrade", "").lower() == "websocket"
            and "upgrade" in headers.get("Connection", "").lower())


def accept_key(client_key: str) -> str:
    digest = hashlib.sha1((client_key + GUID).encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


class WebSocket:
    """One upgraded connection. Reads on the calling thread, writes from any.

    Writes are serialised with a lock because two threads legitimately write
    here: the pump carrying terminal output, and the pinger. Interleaving two
    frames on one socket produces a protocol error and an instant disconnect,
    which is a horrible way to learn about a missing lock.
    """

    def __init__(self, conn: socket.socket, rfile, wfile):
        self.conn = conn
        self.rfile = rfile
        self.wfile = wfile
        self.closed = False
        self.last_pong = time.monotonic()
        self._wlock = threading.Lock()
        self._pinger = None

    # ------------------------------------------------------------- handshake

    @classmethod
    def upgrade(cls, handler) -> "WebSocket":
        """Complete the handshake on a BaseHTTPRequestHandler. Raises on refusal."""
        key = handler.headers.get("Sec-WebSocket-Key")
        version = handler.headers.get("Sec-WebSocket-Version", "")
        if not key:
            raise WebSocketError("no Sec-WebSocket-Key")
        if version.strip() != "13":
            raise WebSocketError(f"unsupported websocket version {version!r}")

        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_key(key)}\r\n"
            "\r\n"
        )
        handler.wfile.write(response.encode("ascii"))
        handler.wfile.flush()

        # The socket is ours now; http.server must not try to speak HTTP on it
        # again or write its own error page over our frames.
        handler.close_connection = True
        return cls(handler.connection, handler.rfile, handler.wfile)

    # ----------------------------------------------------------------- writes

    def _send_frame(self, opcode: int, payload: bytes) -> None:
        if self.closed:
            raise WebSocketClosed("socket already closed")
        header = bytearray()
        header.append(0x80 | opcode)          # FIN + opcode; we never fragment
        n = len(payload)
        if n < 126:
            header.append(n)                  # server frames are never masked
        elif n < 65536:
            header.append(126)
            header += struct.pack(">H", n)
        else:
            header.append(127)
            header += struct.pack(">Q", n)
        try:
            with self._wlock:
                self.wfile.write(bytes(header) + payload)
                self.wfile.flush()
        except (OSError, ValueError) as e:
            self.closed = True
            raise WebSocketClosed(str(e)) from e

    def send_text(self, text: str) -> None:
        self._send_frame(OP_TEXT, text.encode("utf-8"))

    def send_json(self, obj) -> None:
        self.send_text(json.dumps(obj, separators=(",", ":")))

    def send_ping(self, payload: bytes = b"") -> None:
        self._send_frame(OP_PING, payload)

    def send_pong(self, payload: bytes = b"") -> None:
        self._send_frame(OP_PONG, payload)

    def close(self, code: int = 1000, reason: str = "") -> None:
        if self.closed:
            return
        try:
            self._send_frame(OP_CLOSE, struct.pack(">H", code) + reason.encode("utf-8")[:120])
        except (WebSocketClosed, OSError):
            pass
        self.closed = True
        try:
            self.conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    # ------------------------------------------------------------------ reads

    def _read_exact(self, n: int) -> bytes:
        chunks, got = [], 0
        while got < n:
            chunk = self.rfile.read(n - got)
            if not chunk:
                raise WebSocketClosed("peer hung up")
            chunks.append(chunk)
            got += len(chunk)
        return b"".join(chunks)

    def recv(self):
        """Next application message as str, or None when the peer closed.

        Control frames are handled here and never returned: a pong updates the
        liveness clock, a ping is answered immediately, a close ends the loop.
        """
        buffer = bytearray()
        buffer_op = None
        while True:
            try:
                b0, b1 = self._read_exact(2)
            except WebSocketClosed:
                return None
            except (OSError, ValueError):
                return None

            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F

            if length == 126:
                length, = struct.unpack(">H", self._read_exact(2))
            elif length == 127:
                length, = struct.unpack(">Q", self._read_exact(8))
            if length > MAX_FRAME:
                self.close(1009, "frame too large")
                return None

            mask = self._read_exact(4) if masked else None
            payload = self._read_exact(length) if length else b""
            if mask:
                # The spec requires client frames to be masked; unmasking is a
                # four-byte rotating XOR and nothing more.
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))

            if opcode == OP_CLOSE:
                code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 1005
                self.close(1000 if code == 1005 else code)
                return None
            if opcode == OP_PING:
                try:
                    self.send_pong(payload)
                except WebSocketClosed:
                    return None
                continue
            if opcode == OP_PONG:
                self.last_pong = time.monotonic()
                continue

            if opcode in (OP_TEXT, OP_BINARY):
                buffer_op = opcode
                buffer = bytearray(payload)
            elif opcode == OP_CONT:
                buffer += payload
            else:
                self.close(1002, "unknown opcode")
                return None

            if fin:
                if buffer_op == OP_TEXT:
                    try:
                        return buffer.decode("utf-8")
                    except UnicodeDecodeError:
                        self.close(1007, "invalid utf-8")
                        return None
                return bytes(buffer)

    # ------------------------------------------------------------- keep-alive

    def start_keepalive(self, on_dead=None) -> None:
        """Ping forever, and notice when the answers stop.

        This is the whole anti-disconnection story for the browser link: an
        idle terminal is indistinguishable from a dead one to anything in the
        middle, and a ping every PING_INTERVAL is what tells the middle
        otherwise. If PONG_TIMEOUT passes with no pong the peer is gone --
        keeping the session is the session registry's job, not this socket's.
        """
        def _run():
            while not self.closed:
                time.sleep(PING_INTERVAL)
                if self.closed:
                    return
                if time.monotonic() - self.last_pong > PONG_TIMEOUT:
                    self.close(1001, "no pong")
                    if on_dead:
                        on_dead()
                    return
                try:
                    self.send_ping(b"apex")
                except WebSocketClosed:
                    return
        self._pinger = threading.Thread(target=_run, name="ws-keepalive", daemon=True)
        self._pinger.start()


# A wrong GUID produces a handshake that passes any client lenient enough to
# check only the status line, and that no browser will accept. Asserting the
# spec's own example at import time makes that failure impossible to ship.
assert accept_key(_RFC_EXAMPLE[0]) == _RFC_EXAMPLE[1], (
    "websocket accept key is wrong; check GUID against RFC 6455")

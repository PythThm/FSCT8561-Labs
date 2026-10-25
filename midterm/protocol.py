"""
Notes to self:
Purpose of this script is to fix the problem with recv(1024), where a message 
can be malformed upon arrival. The fix is to send every message as a 4-byte big
endian length followed by the payload of UTF-8 text, so the receiver knows where
a message ends.
"""

import socket
import struct

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 5050

HEADER_SIZE = 4
MAX_FRAME = 65536      # largest frame either side will accept (server replies)
MAX_REQUEST = 1024     # largest frame the server accepts from a client


class ProtocolError(Exception):
    """The peer sent something that breaks the framing rules."""

    def __init__(self, message, event="MALFORMED_FRAME"):
        super().__init__(message)
        self.event = event  # name used in the security log


class IdleTimeout(Exception):
    """No data arrived within the idle timeout."""


class ConnectionClosed(Exception):
    """The peer closed the connection."""


def _recv_exact(sock, size):
    """Read exactly `size` bytes or raise ConnectionClosed."""
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionClosed()
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock, text):
    """Encode `text` and send it as one length-prefixed frame."""
    data = text.encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ProtocolError("Message too large to send", "FRAME_TOO_LARGE")
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock, idle_timeout, frame_timeout=10.0, max_size=MAX_FRAME):
    """
    Receive one frame and return its payload as bytes.

    idle_timeout:  how long to wait for the first byte of a new frame.
    frame_timeout: how long the rest of the frame may take once it has started
                   (stops a client from holding a thread open with half a frame).
    max_size:      largest payload accepted; bigger length headers are rejected
                   before any memory is allocated for them.
    """
    sock.settimeout(idle_timeout)
    try:
        first = _recv_exact(sock, 1)
    except socket.timeout:
        raise IdleTimeout()

    sock.settimeout(frame_timeout)
    try:
        header = first + _recv_exact(sock, HEADER_SIZE - 1)
        (length,) = struct.unpack(">I", header)
        # Text probes (for example nmap -sV sending "GET / HTTP/1.0") parse as a
        # huge number here and are rejected without reading further.
        if length == 0 or length > max_size:
            raise ProtocolError("Invalid frame length", "MALFORMED_FRAME")
        return _recv_exact(sock, length)
    except socket.timeout:
        raise ProtocolError("Frame not completed in time", "INCOMPLETE_FRAME")
    except ConnectionClosed:
        raise ProtocolError("Connection dropped mid-frame", "INCOMPLETE_FRAME")
"""
protocol.py
-----------
Wire-protocol encoder / decoder for the Intelligent-NIDS private
communication network.

Every byte that travels over the TCP connection is wrapped in a
self-describing frame so that:
  • The receiver always knows where one message ends and the next begins.
  • Every message carries its type, sender identity, and timestamp.
  • Binary payloads (file chunks) are safely embedded via base64.

Frame format
------------
    NIDS::<json_header>\n<raw_payload_bytes>

Where <json_header> is a UTF-8 JSON object with the fields:

    {
        "msg_type"    : str,        # MsgType enum value
        "sender"      : str,        # alias of the originating party
        "timestamp"   : float,      # Unix epoch (time.time())
        "payload_len" : int,        # length of raw payload in bytes
        "extra"       : dict        # optional metadata (file name, etc.)
    }

And <raw_payload_bytes> is exactly payload_len bytes that follow the
newline delimiter.

Design rationale
----------------
•  Length-prefixed binary payload avoids the ambiguity of text-only
   delimiters (newlines inside chat messages would break framing).
•  The NIDS:: magic prefix lets the packet-capture module quickly
   identify proprietary frames vs. background LAN traffic.
•  JSON headers are human-readable – invaluable during debugging.
•  base64 encoding is used only for FILE_CHUNK messages so that binary
   data never corrupts the JSON header layer.
"""

import base64
import json
import time
from typing import Any, Optional

from communication.constants import (
    BUFFER_SIZE,
    ENCODING,
    HEADER_DELIM,
    HEADER_PREFIX,
    MsgType,
)
from communication.logger import get_logger

log = get_logger("protocol")


# ---------------------------------------------------------------------------
# Public data-class style container
# ---------------------------------------------------------------------------
class Frame:
    """
    Represents one fully-decoded NIDS protocol message.

    Attributes
    ----------
    msg_type  : MsgType   – what kind of message this is
    sender    : str       – alias of the sender
    timestamp : float     – Unix epoch when the frame was created
    payload   : bytes     – raw payload bytes (may be empty)
    extra     : dict      – optional key-value metadata
    text      : str       – convenience property; payload decoded as UTF-8
    """

    __slots__ = ("msg_type", "sender", "timestamp", "payload", "extra")

    def __init__(
        self,
        msg_type: MsgType,
        sender: str,
        timestamp: float,
        payload: bytes,
        extra: Optional[dict] = None,
    ) -> None:
        self.msg_type: MsgType = msg_type
        self.sender: str       = sender
        self.timestamp: float  = timestamp
        self.payload: bytes    = payload
        self.extra: dict       = extra or {}

    @property
    def text(self) -> str:
        """Return payload decoded as UTF-8 (convenience for chat messages)."""
        return self.payload.decode(ENCODING, errors="replace")

    def __repr__(self) -> str:
        return (
            f"Frame(type={self.msg_type.value!r}, "
            f"sender={self.sender!r}, "
            f"payload_len={len(self.payload)})"
        )


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------
def build_frame(
    msg_type: MsgType,
    sender: str,
    payload: bytes = b"",
    extra: Optional[dict] = None,
) -> bytes:
    """
    Encode a message into a wire-ready byte string.

    Parameters
    ----------
    msg_type : MsgType
        The type of message being sent.
    sender : str
        The alias / identifier of the sending party.
    payload : bytes
        Raw payload bytes.  For text messages, encode the string first:
        ``payload=message.encode(ENCODING)``.
    extra : dict, optional
        Arbitrary metadata to embed in the header (e.g. file name, chunk
        index).

    Returns
    -------
    bytes
        The complete frame ready to be written to a socket.
    """
    header: dict[str, Any] = {
        "msg_type"    : msg_type.value,
        "sender"      : sender,
        "timestamp"   : time.time(),
        "payload_len" : len(payload),
        "extra"       : extra or {},
    }
    header_bytes: bytes = (
        HEADER_PREFIX + json.dumps(header) + HEADER_DELIM
    ).encode(ENCODING)
    return header_bytes + payload


def build_text_frame(
    msg_type: MsgType,
    sender: str,
    text: str,
    extra: Optional[dict] = None,
) -> bytes:
    """Convenience wrapper for text-only messages."""
    return build_frame(msg_type, sender, text.encode(ENCODING), extra)


def build_file_chunk_frame(
    sender: str,
    chunk_data: bytes,
    file_name: str,
    chunk_index: int,
    total_chunks: int,
) -> bytes:
    """
    Encode a file chunk as a FILE_CHUNK frame.

    The chunk bytes are base64-encoded so they can be safely embedded
    inside the length-prefixed payload without any corruption risk.
    """
    encoded = base64.b64encode(chunk_data)
    extra = {
        "file_name"   : file_name,
        "chunk_index" : chunk_index,
        "total_chunks": total_chunks,
    }
    return build_frame(MsgType.FILE_CHUNK, sender, encoded, extra)


# ---------------------------------------------------------------------------
# Decoding helpers
# ---------------------------------------------------------------------------
def _recv_exactly(sock, n: int) -> bytes:
    """
    Read exactly *n* bytes from *sock*.

    Raises
    ------
    ConnectionError
        If the connection is closed before *n* bytes are received.
    """
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(buf)))
        if not chunk:
            raise ConnectionError(
                f"Connection closed while reading payload "
                f"(got {len(buf)}/{n} bytes)"
            )
        buf += chunk
    return buf


def recv_frame(sock) -> Optional[Frame]:
    """
    Block until one complete frame is read from *sock* and return a
    :class:`Frame`.

    The function reads the header line first (looking for HEADER_DELIM),
    then reads exactly ``payload_len`` bytes.

    Returns
    -------
    Frame | None
        ``None`` is returned only when the connection has been closed
        cleanly (zero-byte read at the start).

    Raises
    ------
    ValueError
        If the header is malformed or the magic prefix is missing.
    ConnectionError
        If the connection drops mid-frame.
    """
    # ── Step 1: accumulate bytes until we see the header delimiter ──────
    raw_header = b""
    while True:
        byte = sock.recv(1)
        if not byte:
            # Clean shutdown from the remote side
            return None
        raw_header += byte
        if raw_header.endswith(HEADER_DELIM.encode(ENCODING)):
            break

    raw_header_str = raw_header.decode(ENCODING, errors="replace").rstrip(
        HEADER_DELIM
    )

    # ── Step 2: validate magic prefix ───────────────────────────────────
    if not raw_header_str.startswith(HEADER_PREFIX):
        raise ValueError(
            f"Invalid frame header (missing magic prefix): "
            f"{raw_header_str[:80]!r}"
        )

    json_part = raw_header_str[len(HEADER_PREFIX):]

    # ── Step 3: parse JSON header ────────────────────────────────────────
    try:
        header: dict = json.loads(json_part)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Malformed JSON header: {exc}") from exc

    msg_type_str: str = header.get("msg_type", "")
    sender: str       = header.get("sender", "unknown")
    timestamp: float  = header.get("timestamp", time.time())
    payload_len: int  = header.get("payload_len", 0)
    extra: dict       = header.get("extra", {})

    try:
        msg_type = MsgType(msg_type_str)
    except ValueError:
        raise ValueError(f"Unknown msg_type: {msg_type_str!r}")

    # ── Step 4: read payload ─────────────────────────────────────────────
    payload: bytes = _recv_exactly(sock, payload_len) if payload_len else b""

    # ── Step 5: decode base64 for file chunks ────────────────────────────
    if msg_type == MsgType.FILE_CHUNK:
        payload = base64.b64decode(payload)

    return Frame(
        msg_type=msg_type,
        sender=sender,
        timestamp=timestamp,
        payload=payload,
        extra=extra,
    )


def decode_frame_bytes(data: bytes) -> Optional[Frame]:
    """
    Decode a complete frame from an in-memory byte string.

    Unlike ``recv_frame()`` which reads from a socket, this function
    parses a byte string that already contains a complete frame.  It is
    used by ``BrowserSession.send()`` to inspect frames that the server
    is about to broadcast, so the WebSocket bridge can forward them to
    browser clients in JSON form.

    Parameters
    ----------
    data : bytes
        Complete encoded frame (output of ``build_frame``).

    Returns
    -------
    Frame | None
        ``None`` if the data is malformed or the prefix is missing.
    """
    try:
        prefix_bytes = HEADER_PREFIX.encode(ENCODING)
        delim_bytes  = HEADER_DELIM.encode(ENCODING)

        if not data.startswith(prefix_bytes):
            return None

        delim_pos = data.index(delim_bytes)
        json_part = data[len(prefix_bytes):delim_pos].decode(ENCODING)
        header: dict = json.loads(json_part)

        payload_start = delim_pos + len(delim_bytes)
        payload: bytes = data[payload_start:]

        msg_type = MsgType(header.get("msg_type", ""))
        if msg_type == MsgType.FILE_CHUNK:
            payload = base64.b64decode(payload)

        return Frame(
            msg_type  = msg_type,
            sender    = header.get("sender", "unknown"),
            timestamp = header.get("timestamp", time.time()),
            payload   = payload,
            extra     = header.get("extra", {}),
        )
    except Exception:
        return None


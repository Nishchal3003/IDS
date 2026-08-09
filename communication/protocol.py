"""NIDS wire-protocol encoder/decoder.

Frame format:  NIDS::<json_header>\n<raw_payload_bytes>
"""

import base64
import json
import time
from typing import Any, Optional

from communication.constants import BUFFER_SIZE, ENCODING, HEADER_DELIM, HEADER_PREFIX, MsgType
from communication.logger import get_logger

log = get_logger("protocol")


class Frame:
    """One fully-decoded NIDS protocol message."""
    __slots__ = ("msg_type", "sender", "timestamp", "payload", "extra")

    def __init__(self, msg_type: MsgType, sender: str, timestamp: float,
                 payload: bytes, extra: Optional[dict] = None) -> None:
        self.msg_type  = msg_type
        self.sender    = sender
        self.timestamp = timestamp
        self.payload   = payload
        self.extra     = extra or {}

    @property
    def text(self) -> str:
        return self.payload.decode(ENCODING, errors="replace")

    def __repr__(self) -> str:
        return f"Frame(type={self.msg_type.value!r}, sender={self.sender!r}, len={len(self.payload)})"


# ── Encoding ──────────────────────────────────────────────────────────────────

def build_frame(msg_type: MsgType, sender: str, payload: bytes = b"",
                extra: Optional[dict] = None) -> bytes:
    """Encode a message into a wire-ready byte string."""
    header: dict[str, Any] = {
        "msg_type"   : msg_type.value,
        "sender"     : sender,
        "timestamp"  : time.time(),
        "payload_len": len(payload),
        "extra"      : extra or {},
    }
    return (HEADER_PREFIX + json.dumps(header) + HEADER_DELIM).encode(ENCODING) + payload


def build_text_frame(msg_type: MsgType, sender: str, text: str,
                     extra: Optional[dict] = None) -> bytes:
    """Convenience wrapper: encode text as UTF-8 payload."""
    return build_frame(msg_type, sender, text.encode(ENCODING), extra)


def build_file_chunk_frame(sender: str, chunk_data: bytes, file_name: str,
                           chunk_index: int, total_chunks: int) -> bytes:
    """Encode a file chunk (base64) as a FILE_CHUNK frame."""
    return build_frame(
        MsgType.FILE_CHUNK, sender, base64.b64encode(chunk_data),
        {"file_name": file_name, "chunk_index": chunk_index, "total_chunks": total_chunks},
    )


# ── Decoding ──────────────────────────────────────────────────────────────────

def _recv_exactly(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(BUFFER_SIZE, n - len(buf)))
        if not chunk:
            raise ConnectionError(f"Connection closed mid-payload ({len(buf)}/{n} bytes)")
        buf += chunk
    return buf


def recv_frame(sock) -> Optional[Frame]:
    """Block until one complete frame arrives; return None on clean disconnect."""
    raw = b""
    delim = HEADER_DELIM.encode(ENCODING)
    while not raw.endswith(delim):
        byte = sock.recv(1)
        if not byte:
            return None
        raw += byte

    hdr_str = raw.decode(ENCODING, errors="replace").rstrip(HEADER_DELIM)
    if not hdr_str.startswith(HEADER_PREFIX):
        raise ValueError(f"Missing magic prefix: {hdr_str[:80]!r}")

    try:
        h = json.loads(hdr_str[len(HEADER_PREFIX):])
    except json.JSONDecodeError as e:
        raise ValueError(f"Malformed JSON header: {e}") from e

    msg_type = MsgType(h.get("msg_type", ""))
    payload  = _recv_exactly(sock, h.get("payload_len", 0)) if h.get("payload_len") else b""
    if msg_type == MsgType.FILE_CHUNK:
        payload = base64.b64decode(payload)

    return Frame(msg_type, h.get("sender", "unknown"),
                 h.get("timestamp", time.time()), payload, h.get("extra", {}))


def decode_frame_bytes(data: bytes) -> Optional[Frame]:
    """Decode a complete frame from an in-memory byte string (used by WS bridge)."""
    try:
        pfx = HEADER_PREFIX.encode(ENCODING)
        dlm = HEADER_DELIM.encode(ENCODING)
        if not data.startswith(pfx):
            return None
        pos = data.index(dlm)
        h   = json.loads(data[len(pfx):pos].decode(ENCODING))
        payload = data[pos + len(dlm):]
        msg_type = MsgType(h.get("msg_type", ""))
        if msg_type == MsgType.FILE_CHUNK:
            payload = base64.b64decode(payload)
        return Frame(msg_type, h.get("sender", "unknown"),
                     h.get("timestamp", time.time()), payload, h.get("extra", {}))
    except Exception:
        return None

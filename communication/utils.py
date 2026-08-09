"""Shared utility helpers for the Intelligent-NIDS communication module."""

import ipaddress
import socket
import time
from pathlib import Path
from typing import Generator, Optional

from communication.constants import ENCODING, FILE_CHUNK_SIZE, MAX_FILE_SIZE, MsgType
from communication.logger import get_logger

log = get_logger("utils")

# ── Network ──────────────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Return the primary LAN IPv4 address via a dummy UDP connect."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def is_lan_peer(client_ip: str, server_ip: Optional[str] = None) -> bool:
    """Return True if client_ip is loopback or on the same /24 LAN as server_ip."""
    if client_ip.startswith("::ffff:"):
        client_ip = client_ip[7:]
    try:
        c = ipaddress.ip_address(client_ip)
        if c.is_loopback:
            return True
        if server_ip and server_ip != "127.0.0.1":
            return c in ipaddress.ip_network(f"{server_ip}/24", strict=False)
        return c.is_private
    except ValueError:
        return False


def is_valid_ip(ip: str) -> bool:
    """Return True if ip is a valid IPv4 address string."""
    try:
        socket.inet_aton(ip); return True
    except socket.error:
        return False


def is_port_in_use(port: int, host: str = "0.0.0.0") -> bool:
    """Return True if port is already bound on host."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port)); return False
        except OSError:
            return True

# ── Formatting ───────────────────────────────────────────────────────────────

def format_size(n: int) -> str:
    """Convert bytes to a human-readable string (B / KB / MB / GB / TB)."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n} B" if unit == "B" else f"{n:.2f} {unit}"
        n //= 1024
    return f"{n:.2f} TB"


def format_duration(seconds: float) -> str:
    """Convert elapsed seconds to h/m/s string."""
    h, rem = divmod(int(seconds), 3600)
    m, s   = divmod(rem, 60)
    if h: return f"{h}h {m}m {s}s"
    if m: return f"{m}m {s}s"
    return f"{s}s"


def timestamp_to_str(epoch: float, fmt: str = "%H:%M:%S") -> str:
    """Format a Unix epoch float as a time string."""
    return time.strftime(fmt, time.localtime(epoch))

# ── Alias validation ──────────────────────────────────────────────────────────

_ALLOWED = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")

def sanitise_alias(alias: str) -> str:
    """Validate and clean a device alias (2-20 chars, alphanumeric/hyphen/underscore)."""
    alias = alias.strip()
    if len(alias) < 2:
        raise ValueError(f"Alias too short ({len(alias)}); min 2.")
    if len(alias) > 20:
        raise ValueError(f"Alias too long ({len(alias)}); max 20.")
    bad = [c for c in alias if c not in _ALLOWED]
    if bad:
        raise ValueError(f"Invalid chars {bad!r}. Use letters, digits, - or _.")
    return alias

# ── Socket / file helpers ─────────────────────────────────────────────────────

def safe_send(sock: socket.socket, data: bytes) -> bool:
    """Send data to sock; return True on success, False on error."""
    try:
        sock.sendall(data); return True
    except OSError as exc:
        log.error("safe_send failed: %s", exc); return False


def validate_file_for_transfer(path: str) -> Path:
    """Strip quotes, resolve path, check it exists and is within MAX_FILE_SIZE."""
    path = path.strip().strip('"').strip("'").strip()
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    if p.is_dir():
        raise IsADirectoryError(f"Path is a directory: {p}")
    if p.stat().st_size > MAX_FILE_SIZE:
        raise ValueError(f"File too large ({format_size(p.stat().st_size)}); limit {format_size(MAX_FILE_SIZE)}")
    return p


def get_file_chunks(path: Path) -> Generator[bytes, None, None]:
    """Yield FILE_CHUNK_SIZE byte chunks from path."""
    with path.open("rb") as fh:
        while chunk := fh.read(FILE_CHUNK_SIZE):
            yield chunk

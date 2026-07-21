"""
utils.py
--------
Shared utility helpers for the Intelligent-NIDS communication module.

All helpers are pure functions (no side-effects, no global state) so
they are safe to import from both server and client without creating
circular dependencies.

Contents
--------
•  get_local_ip()       – discover the machine's LAN IP address
•  format_size()        – human-readable byte sizes  (e.g. "1.23 MB")
•  format_duration()    – human-readable elapsed time
•  sanitise_alias()     – validate and clean a user-chosen device alias
•  timestamp_to_str()   – Unix epoch → readable string
•  safe_send()          – send a pre-built frame with error handling
•  get_file_chunks()    – generator that yields FILE_CHUNK_SIZE slices
"""

import os
import socket
import time
from pathlib import Path
from typing import Generator, Optional

from communication.constants import (
    ENCODING,
    FILE_CHUNK_SIZE,
    MAX_FILE_SIZE,
    MsgType,
)
from communication.logger import get_logger

log = get_logger("utils")


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------
def get_local_ip() -> str:
    """
    Return the primary LAN IPv4 address of this machine.

    Uses a dummy UDP connection to 8.8.8.8 (no data is actually sent)
    to let the OS choose the outgoing interface.  Falls back to
    ``127.0.0.1`` if that fails.

    Returns
    -------
    str
        e.g. ``"192.168.1.42"``
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except OSError:
        log.warning("Could not determine LAN IP; falling back to 127.0.0.1")
        return "127.0.0.1"


def is_valid_ip(ip: str) -> bool:
    """Return True if *ip* is a syntactically valid IPv4 address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


def is_port_in_use(port: int, host: str = "0.0.0.0") -> bool:
    """
    Check whether *port* is already bound on *host*.

    Useful for giving the user a clear error before attempting to start
    the server on a taken port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------
def format_size(num_bytes: int) -> str:
    """
    Convert a byte count to a human-readable string.

    Examples
    --------
    >>> format_size(1023)
    '1023 B'
    >>> format_size(1024)
    '1.00 KB'
    >>> format_size(1048576)
    '1.00 MB'
    """
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024:
            return f"{num_bytes:.2f} {unit}" if unit != "B" else f"{num_bytes} B"
        num_bytes //= 1024
    return f"{num_bytes:.2f} TB"


def format_duration(seconds: float) -> str:
    """
    Convert elapsed seconds to a human-readable string.

    Examples
    --------
    >>> format_duration(61.5)
    '1m 1s'
    >>> format_duration(3661.0)
    '1h 1m 1s'
    """
    secs = int(seconds)
    h, rem = divmod(secs, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


def timestamp_to_str(epoch: float, fmt: str = "%H:%M:%S") -> str:
    """
    Convert a Unix epoch float to a formatted time string.

    Parameters
    ----------
    epoch : float
        Output of ``time.time()``.
    fmt : str
        ``strftime``-compatible format string.  Defaults to ``%H:%M:%S``.

    Returns
    -------
    str
    """
    return time.strftime(fmt, time.localtime(epoch))


# ---------------------------------------------------------------------------
# Alias validation
# ---------------------------------------------------------------------------
_MAX_ALIAS_LEN: int = 20
_MIN_ALIAS_LEN: int = 2
_ALLOWED_CHARS: frozenset = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789-_"
)


def sanitise_alias(alias: str) -> str:
    """
    Validate and clean a user-supplied device alias.

    Rules:
      • 2–20 characters long.
      • Only alphanumeric, hyphen, or underscore.
      • Leading/trailing whitespace is stripped.

    Returns
    -------
    str
        The sanitised alias.

    Raises
    ------
    ValueError
        If the alias violates any rule.
    """
    alias = alias.strip()
    if len(alias) < _MIN_ALIAS_LEN:
        raise ValueError(
            f"Alias too short ({len(alias)} chars); minimum is {_MIN_ALIAS_LEN}."
        )
    if len(alias) > _MAX_ALIAS_LEN:
        raise ValueError(
            f"Alias too long ({len(alias)} chars); maximum is {_MAX_ALIAS_LEN}."
        )
    invalid = [c for c in alias if c not in _ALLOWED_CHARS]
    if invalid:
        raise ValueError(
            f"Alias contains invalid characters: {invalid!r}. "
            "Use only letters, digits, hyphens, and underscores."
        )
    return alias


# ---------------------------------------------------------------------------
# Socket send helper
# ---------------------------------------------------------------------------
def safe_send(sock: socket.socket, data: bytes) -> bool:
    """
    Send *data* to *sock*, catching and logging any socket errors.

    Parameters
    ----------
    sock : socket.socket
        The connected socket to write to.
    data : bytes
        Fully encoded frame bytes (output of ``build_frame``).

    Returns
    -------
    bool
        ``True`` if the send succeeded, ``False`` otherwise.
    """
    try:
        sock.sendall(data)
        return True
    except OSError as exc:
        log.error("safe_send failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------
def validate_file_for_transfer(path: str) -> Path:
    """
    Validate that *path* exists, is a file, and is within the size limit.

    Surrounding whitespace and quotation marks are stripped automatically,
    so paths pasted from Windows Explorer (which wraps them in double-quotes)
    are handled correctly without the user having to remove the quotes.

    Parameters
    ----------
    path : str
        Absolute or relative path to the file.  Surrounding ``"`` or ``'``
        characters are stripped before resolution.

    Returns
    -------
    pathlib.Path
        Resolved ``Path`` object.

    Raises
    ------
    FileNotFoundError
        If the path does not exist.
    IsADirectoryError
        If the path is a directory.
    ValueError
        If the file exceeds ``MAX_FILE_SIZE``.
    """
    # Strip surrounding whitespace and quotation marks that Windows
    # sometimes adds when a user copies a path from Explorer or a prompt.
    path = path.strip().strip('"').strip("'").strip()

    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    if p.is_dir():
        raise IsADirectoryError(f"Path is a directory, not a file: {p}")
    size = p.stat().st_size
    if size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large: {format_size(size)} "
            f"(limit is {format_size(MAX_FILE_SIZE)})"
        )
    return p


def get_file_chunks(path: Path) -> Generator[bytes, None, None]:
    """
    Yield ``FILE_CHUNK_SIZE`` byte chunks from *path*.

    Parameters
    ----------
    path : pathlib.Path
        Validated path to a readable file.

    Yields
    ------
    bytes
        Successive chunks of up to ``FILE_CHUNK_SIZE`` bytes.
    """
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(FILE_CHUNK_SIZE)
            if not chunk:
                break
            yield chunk

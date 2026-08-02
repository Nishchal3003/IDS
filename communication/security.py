"""
communication/security.py
--------------------------
Centralised security utilities for the NIDS private network.

Three concerns handled here
----------------------------
1. AUTH TOKEN  – HMAC-SHA256(PSK, "NIDS-AUTH:<alias>")
   Clients include this in their HELLO frame.  The server verifies it
   before allowing the session.  An empty PSK disables auth entirely
   (open network, backward compatible with Phase 1 behaviour).

2. FRAME MAC   – HMAC-SHA256(PSK, "<msg_type>:<sender>:<text>:<ts>")
   Appended as a "mac" field inside every frame's JSON header.
   The receiver verifies before processing.  Detects message tampering
   or injection even if an attacker somehow bypasses TLS.

3. CERT PATHS  – single place that all modules import from so there is
   never a path mismatch between the HTTP server and the WS server.

Usage
-----
    from communication.security import (
        compute_auth_token, verify_auth_token,
        compute_frame_mac, verify_frame_mac,
        CERT_FILE, KEY_FILE,
        server_ssl_context, client_ssl_context,
    )
"""

import hashlib
import hmac as _hmac
import ssl
from pathlib import Path

# ---------------------------------------------------------------------------
# Certificate paths
# ---------------------------------------------------------------------------
_ROOT      = Path(__file__).resolve().parent.parent
CERT_FILE  = _ROOT / "certs" / "server.crt"
KEY_FILE   = _ROOT / "certs" / "server.key"


def certs_exist() -> bool:
    return CERT_FILE.exists() and KEY_FILE.exists()


# ---------------------------------------------------------------------------
# SSL context factories
# ---------------------------------------------------------------------------

def server_ssl_context() -> ssl.SSLContext:
    """
    Return an SSL context for the server side (TLS, TCP + HTTPS + WSS).
    Raises ``FileNotFoundError`` if certs are missing.
    """
    if not certs_exist():
        raise FileNotFoundError(
            f"TLS certs not found.\n"
            f"  Run:  python -m communication.generate_certs"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def client_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """
    Return an SSL context for the client side (Python TCP client).

    Parameters
    ----------
    verify : bool
        If True (default), the server cert is verified against CERT_FILE.
        Set False only if the cert file is missing (graceful degradation).
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify and CERT_FILE.exists():
        ctx.load_verify_locations(str(CERT_FILE))
    else:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


# ---------------------------------------------------------------------------
# Auth token  (included in HELLO)
# ---------------------------------------------------------------------------

def compute_auth_token(psk: str, alias: str) -> str:
    """
    Compute the HMAC-SHA256 auth token a client sends in its HELLO frame.

    Parameters
    ----------
    psk   : pre-shared key (from NETWORK_PSK in config)
    alias : client's chosen alias (e.g. "Alice")

    Returns
    -------
    Hex-encoded HMAC string, or "" if PSK is empty (auth disabled).
    """
    if not psk:
        return ""
    msg = f"NIDS-AUTH:{alias}".encode("utf-8")
    return _hmac.new(psk.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_auth_token(psk: str, alias: str, token: str) -> bool:
    """
    Verify the auth token received in a client HELLO.

    Returns True if:
    - PSK is empty (auth disabled), OR
    - the supplied token matches the expected HMAC.

    Always returns False if PSK is set but token is missing / wrong.
    """
    if not psk:
        return True   # open network
    expected = compute_auth_token(psk, alias)
    # constant-time comparison to prevent timing attacks
    return _hmac.compare_digest(expected, token or "")


# ---------------------------------------------------------------------------
# Frame MAC  (included in every frame's JSON header)
# ---------------------------------------------------------------------------

def compute_frame_mac(psk: str, msg_type: str, sender: str,
                      text: str, timestamp: str) -> str:
    """
    Compute the HMAC-SHA256 MAC for one protocol frame.

    Returns "" if PSK is empty (MACs disabled).
    """
    if not psk:
        return ""
    payload = f"{msg_type}:{sender}:{text}:{timestamp}"
    return _hmac.new(
        psk.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_frame_mac(psk: str, msg_type: str, sender: str,
                     text: str, timestamp: str, mac: str) -> bool:
    """
    Verify a frame MAC received from a peer.

    Returns True if:
    - PSK is empty (MACs disabled), OR
    - the supplied MAC matches the expected HMAC.
    """
    if not psk:
        return True
    expected = compute_frame_mac(psk, msg_type, sender, text, timestamp)
    return _hmac.compare_digest(expected, mac or "")

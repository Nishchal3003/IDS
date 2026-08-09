"""Security utilities: TLS contexts, HMAC auth tokens, and frame MACs."""

import hashlib
import hmac as _hmac
import ssl
from pathlib import Path

_ROOT     = Path(__file__).resolve().parent.parent
CERT_FILE = _ROOT / "certs" / "server.crt"
KEY_FILE  = _ROOT / "certs" / "server.key"


def certs_exist() -> bool:
    return CERT_FILE.exists() and KEY_FILE.exists()


def server_ssl_context() -> ssl.SSLContext:
    """TLS context for server (TCP + HTTPS + WSS)."""
    if not certs_exist():
        raise FileNotFoundError("TLS certs not found. Run: python -m communication.generate_certs")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def client_ssl_context(verify: bool = True) -> ssl.SSLContext:
    """TLS context for Python TCP client."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if verify and CERT_FILE.exists():
        ctx.load_verify_locations(str(CERT_FILE))
    else:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _hmac_hex(psk: str, msg: str) -> str:
    return _hmac.new(psk.encode(), msg.encode(), hashlib.sha256).hexdigest()


def compute_auth_token(psk: str, alias: str) -> str:
    """Return HMAC-SHA256 auth token for HELLO frame; empty string if no PSK."""
    return _hmac_hex(psk, f"NIDS-AUTH:{alias}") if psk else ""


def verify_auth_token(psk: str, alias: str, token: str) -> bool:
    """Return True if token is valid or PSK is empty (open network)."""
    return True if not psk else _hmac.compare_digest(compute_auth_token(psk, alias), token or "")


def compute_frame_mac(psk: str, msg_type: str, sender: str, text: str, ts: str) -> str:
    """Return frame MAC; empty string if PSK is empty."""
    return _hmac_hex(psk, f"{msg_type}:{sender}:{text}:{ts}") if psk else ""


def verify_frame_mac(psk: str, msg_type: str, sender: str,
                     text: str, ts: str, mac: str) -> bool:
    """Return True if MAC is valid or PSK is empty."""
    return True if not psk else _hmac.compare_digest(compute_frame_mac(psk, msg_type, sender, text, ts), mac or "")

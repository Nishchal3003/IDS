"""
tls.py
------
SSL context factory for the Intelligent-NIDS communication module.

Provides two context builders:
  • ``server_ssl_context()`` — for the TCP server (holds cert + key)
  • ``client_ssl_context()`` — for the TCP client (loads cert to verify server)

Design rationale
----------------
Centralising SSL context creation here means:
  • server_core.py and client_core.py never touch ssl directly.
  • The certs directory path is computed once.
  • If we later switch to a CA-signed cert or mutual TLS, only this file changes.

TLS is only applied to the raw TCP sockets (Python clients).
Browser WebSocket clients connect over plain ws:// — this is acceptable
for an internal LAN where the primary threat model is passive interception
between systems, not browser MITM attacks.
"""

import ssl
import sys
from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).resolve().parent.parent
CERTS_DIR: Path    = PROJECT_ROOT / "certs"
CERT_FILE: Path    = CERTS_DIR / "server.crt"
KEY_FILE: Path     = CERTS_DIR / "server.key"


def certs_exist() -> bool:
    """Return True if both the certificate and key file are present."""
    return CERT_FILE.exists() and KEY_FILE.exists()


def server_ssl_context() -> ssl.SSLContext:
    """
    Build an SSL context for the TCP server.

    The server presents its certificate to connecting clients.
    Client certificate verification is not required (one-way TLS).

    Returns
    -------
    ssl.SSLContext

    Raises
    ------
    FileNotFoundError
        If ``certs/server.crt`` or ``certs/server.key`` are missing.
        Run ``python -m communication.generate_certs`` first.
    """
    if not certs_exist():
        raise FileNotFoundError(
            "TLS certificates not found.\n"
            "Run:  python -m communication.generate_certs\n"
            f"Expected:  {CERT_FILE}\n"
            f"           {KEY_FILE}"
        )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    # Disable weak protocols and ciphers
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5")
    return ctx


def client_ssl_context(verify_cert: bool = True) -> ssl.SSLContext:
    """
    Build an SSL context for the TCP client.

    Parameters
    ----------
    verify_cert : bool
        If ``True`` (default), the client validates the server certificate
        against ``certs/server.crt``.  The connection will be refused if
        the cert does not match.

        If ``False``, the connection is still TLS-encrypted but the server
        identity is not verified.  Useful for quick testing.

    Returns
    -------
    ssl.SSLContext
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    if verify_cert and CERT_FILE.exists():
        ctx.load_verify_locations(cafile=str(CERT_FILE))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = False  # self-signed cert has no hostname to check
    else:
        # Encrypt traffic but skip cert verification
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    return ctx

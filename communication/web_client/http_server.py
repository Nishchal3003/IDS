"""
http_server.py
--------------
HTTPS server that serves the browser client UI (index.html).

Any device on the LAN opens a browser and goes to:

    https://<server-ip>:8443

and instantly accesses the full NIDS private network client — no Python,
no installation, no files required on the client device.

Security
--------
The server uses the same TLS certificate as the TCP server (certs/server.crt).
Browser will show a "Not secure" warning on first visit because the cert is
self-signed (not issued by a public CA). Click "Advanced → Proceed" once —
the encryption is identical to a CA-signed cert.

The server also listens on plain HTTP (port 8080) and immediately redirects
to the HTTPS URL so that users who type http:// are automatically upgraded.

The server runs in a daemon thread so it does not block the main process.
"""

import http.server
import ssl
import threading
from pathlib import Path

from communication.logger import get_logger
from communication.security import server_ssl_context, certs_exist

log = get_logger("http_server")

WEB_CLIENT_DIR: Path = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------

class _NIDSHandler(http.server.BaseHTTPRequestHandler):
    """
    Serves index.html for any GET request, adds security headers.
    """

    # Injected by start_https_server() so the handler knows the HTTPS port
    https_port: int = 8443

    def do_GET(self) -> None:  # noqa: N802
        index_path = WEB_CLIENT_DIR / "index.html"
        if not index_path.exists():
            self.send_error(404, "index.html not found")
            return
        content = index_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type",  "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control",  "no-cache")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, fmt, *args) -> None:  # noqa: N802
        log.debug("HTTPS: %s", fmt % args)


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    """Redirects HTTP → HTTPS."""
    https_port: int = 8443
    https_host: str = "localhost"

    def do_GET(self) -> None:  # noqa: N802
        target = f"https://{self.https_host}:{self.https_port}{self.path}"
        self.send_response(301)
        self.send_header("Location", target)
        self.end_headers()

    def log_message(self, fmt, *args) -> None:  # noqa: N802
        log.debug("HTTP-redirect: %s", fmt % args)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def start_https_server(host: str, https_port: int,
                       redirect_port: int = 8080) -> None:
    """
    Start the HTTPS server (and an HTTP→HTTPS redirect) in daemon threads.

    Parameters
    ----------
    host          : bind interface (e.g. ``"0.0.0.0"``).
    https_port    : TLS port (e.g. 8443).
    redirect_port : plain HTTP port that redirects to HTTPS (e.g. 8080).
    """
    if not certs_exist():
        log.warning(
            "TLS certs missing — falling back to plain HTTP on port %d. "
            "Run: python -m communication.generate_certs",
            redirect_port,
        )
        _start_plain_http(host, redirect_port)
        return

    # ── HTTPS server ──────────────────────────────────────────────────────
    try:
        ctx = server_ssl_context()
    except Exception as exc:
        log.error("Cannot load TLS certs for HTTPS: %s", exc)
        _start_plain_http(host, redirect_port)
        return

    # Patch the handler class with the port (class variable, not instance)
    _NIDSHandler.https_port = https_port

    https_srv = http.server.HTTPServer((host, https_port), _NIDSHandler)
    https_srv.socket = ctx.wrap_socket(https_srv.socket, server_side=True)

    def _run_https():
        log.info("HTTPS server started on %s:%d", host, https_port)
        https_srv.serve_forever()

    threading.Thread(target=_run_https, daemon=True, name="https-server").start()
    log.info("HTTPS server thread started (port %d)", https_port)

    # ── HTTP → HTTPS redirect ─────────────────────────────────────────────
    # Determine a sensible redirect hostname (use first non-0.0.0.0 address)
    try:
        from communication.utils import get_local_ip
        redir_host = get_local_ip() if host == "0.0.0.0" else host
    except Exception:
        redir_host = "localhost"

    _RedirectHandler.https_port = https_port
    _RedirectHandler.https_host = redir_host

    redirect_srv = http.server.HTTPServer((host, redirect_port), _RedirectHandler)

    def _run_redirect():
        log.info("HTTP→HTTPS redirect on %s:%d → %d", host, redirect_port, https_port)
        redirect_srv.serve_forever()

    threading.Thread(target=_run_redirect, daemon=True, name="http-redirect").start()


def _start_plain_http(host: str, port: int) -> None:
    """Fallback: plain HTTP (Phase 1 behaviour)."""
    _NIDSHandler.https_port = port
    srv = http.server.HTTPServer((host, port), _NIDSHandler)

    def _run():
        log.info("HTTP server (plain) started on %s:%d", host, port)
        srv.serve_forever()

    threading.Thread(target=_run, daemon=True, name="http-plain").start()


# ---------------------------------------------------------------------------
# Backward-compatible shim (called by older server.py versions)
# ---------------------------------------------------------------------------
def start_http_server(host: str, port: int) -> None:
    """Shim: called by server.py; upgrades to HTTPS automatically."""
    start_https_server(host, https_port=8443, redirect_port=port)

"""HTTPS server serving the browser UI, plus HTTP→HTTPS redirect."""

import http.server
import threading
from pathlib import Path

from communication.logger import get_logger
from communication.security import certs_exist, server_ssl_context
from communication.utils import get_local_ip

log = get_logger("http_server")
WEB_CLIENT_DIR = Path(__file__).resolve().parent


class _NIDSHandler(http.server.BaseHTTPRequestHandler):
    https_port: int = 8443

    def do_GET(self) -> None:
        p = WEB_CLIENT_DIR / "index.html"
        if not p.exists():
            self.send_error(404, "index.html not found"); return
        data = p.read_bytes()
        self.send_response(200)
        for k, v in [("Content-Type", "text/html; charset=utf-8"),
                     ("Content-Length", str(len(data))), ("Cache-Control", "no-cache"),
                     ("X-Frame-Options", "DENY"), ("X-Content-Type-Options", "nosniff")]:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args) -> None:
        log.debug("HTTPS: %s", fmt % args)


class _RedirectHandler(http.server.BaseHTTPRequestHandler):
    https_port: int = 8443
    https_host: str = "localhost"

    def do_GET(self) -> None:
        self.send_response(301)
        self.send_header("Location", f"https://{self.https_host}:{self.https_port}{self.path}")
        self.end_headers()

    def log_message(self, fmt, *args) -> None:
        log.debug("HTTP-redirect: %s", fmt % args)


def start_https_server(host: str, https_port: int, redirect_port: int = 8080) -> None:
    """Start HTTPS + HTTP-redirect servers in daemon threads."""
    if not certs_exist():
        log.warning("TLS certs missing — plain HTTP on %d. Run: python -m communication.generate_certs", redirect_port)
        _start_plain_http(host, redirect_port); return
    try:
        ctx = server_ssl_context()
    except Exception as e:
        log.error("Cannot load TLS for HTTPS: %s", e); _start_plain_http(host, redirect_port); return

    _NIDSHandler.https_port = https_port
    srv = http.server.HTTPServer((host, https_port), _NIDSHandler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True, name="https-server").start()
    log.info("HTTPS on %s:%d", host, https_port)

    redir_host = (get_local_ip() if host == "0.0.0.0" else host)
    _RedirectHandler.https_port = https_port
    _RedirectHandler.https_host = redir_host
    redir_srv = http.server.HTTPServer((host, redirect_port), _RedirectHandler)
    threading.Thread(target=redir_srv.serve_forever, daemon=True, name="http-redirect").start()
    log.info("HTTP→HTTPS redirect %d→%d", redirect_port, https_port)


def _start_plain_http(host: str, port: int) -> None:
    _NIDSHandler.https_port = port
    srv = http.server.HTTPServer((host, port), _NIDSHandler)
    threading.Thread(target=srv.serve_forever, daemon=True, name="http-plain").start()
    log.info("Plain HTTP on %s:%d", host, port)


def start_http_server(host: str, port: int) -> None:
    """Backward-compat shim."""
    start_https_server(host, https_port=8443, redirect_port=port)

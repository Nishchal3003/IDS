"""
http_server.py
--------------
Lightweight HTTP server that serves the browser client UI (index.html).

Any device on the LAN can open a browser and go to:

    http://<server-ip>:8080

and instantly access the full NIDS private network client — no Python,
no installation, no files required on the client device.

The server runs in a daemon thread so it does not block the main process.
"""

import http.server
import os
import threading
from pathlib import Path

from communication.logger import get_logger

log = get_logger("http_server")

WEB_CLIENT_DIR: Path = Path(__file__).resolve().parent


class _SingleFileHandler(http.server.BaseHTTPRequestHandler):
    """
    Serves index.html for any GET request.

    All paths (``/``, ``/anything``) return the same ``index.html`` so
    that browser refreshes and direct URL access always work.
    """

    def do_GET(self) -> None:  # noqa: N802
        index_path = WEB_CLIENT_DIR / "index.html"
        if not index_path.exists():
            self.send_error(404, "index.html not found")
            return
        content = index_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, fmt, *args) -> None:  # noqa: N802
        """Redirect HTTP access logs to the project logger."""
        log.debug("HTTP: %s", fmt % args)


def start_http_server(host: str, port: int) -> None:
    """
    Start the HTTP server in a background daemon thread.

    Parameters
    ----------
    host : str
        Interface to bind (e.g. ``"0.0.0.0"``).
    port : int
        HTTP port (e.g. ``8080``).
    """
    server = http.server.HTTPServer((host, port), _SingleFileHandler)

    def _run():
        log.info("HTTP server started on %s:%d", host, port)
        server.serve_forever()

    thread = threading.Thread(target=_run, daemon=True, name="http-server")
    thread.start()
    log.info("HTTP server thread started (port %d)", port)

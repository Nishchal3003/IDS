"""
server.py
---------
Entry point for the NIDS private network server.

Run this on the machine that will act as the hub:

    python main.py server

The server starts THREE services:
  1. TCP server (port 5000, TLS encrypted) — for Python clients
  2. HTTP server (port 8080)              — serves the browser client UI
  3. WebSocket server (port 8081)         — real-time browser communication

Any device on the LAN can then open:
    http://<this-machine-ip>:8080
and join the network instantly — no installation required.
"""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from communication.logger import get_logger
from communication.server_core import NIDSServer
from communication.utils import get_local_ip, is_port_in_use

try:
    from config.network_config import HOST, PORT, WEB_PORT, WS_PORT
except ImportError:
    HOST     = "0.0.0.0"
    PORT     = 5000
    WEB_PORT = 8080
    WS_PORT  = 8081

log = get_logger("server")


def main() -> None:
    """Start the NIDS server with HTTP and WebSocket services."""
    local_ip = get_local_ip()
    log.info("Local IP detected as: %s", local_ip)

    # ── Port checks ──────────────────────────────────────────────────────
    for port, label in [(PORT, "TCP"), (WEB_PORT, "HTTP"), (WS_PORT, "WebSocket")]:
        if is_port_in_use(port, HOST):
            log.error(
                "[%s] Port %d is already in use. Free it or change it in config/network_config.py",
                label, port,
            )
            sys.exit(1)

    # ── Create server ────────────────────────────────────────────────────
    server = NIDSServer(host=HOST, port=PORT)

    # ── Start HTTP server (daemon thread) ────────────────────────────────
    try:
        from communication.web_client.http_server import start_http_server
        start_http_server(HOST, WEB_PORT)
        log.info("HTTP server started on port %d", WEB_PORT)
    except Exception as exc:
        log.warning("Could not start HTTP server: %s", exc)

    # ── Start WebSocket server (daemon thread) ───────────────────────────
    try:
        from communication.web_client.ws_bridge import start_ws_server
        start_ws_server(server, HOST, WS_PORT)
        log.info("WebSocket server started on port %d", WS_PORT)
    except Exception as exc:
        log.warning("Could not start WebSocket server: %s", exc)

    # ── Print banner ─────────────────────────────────────────────────────
    tls_status = "ON" if server._ssl_ctx else "OFF (run generate_certs.py to enable)"
    print(f"\n{'='*64}")
    print(f"  NIDS Private Network Server")
    print(f"{'='*64}")
    print(f"  TCP  (Python clients) : {local_ip}:{PORT}  | TLS: {tls_status}")
    print(f"  Web  (Browser clients): http://{local_ip}:{WEB_PORT}")
    print(f"  WS   (Real-time)      : ws://{local_ip}:{WS_PORT}")
    print(f"{'='*64}")
    print(f"  Open any browser on the LAN and go to:")
    print(f"      http://{local_ip}:{WEB_PORT}")
    print(f"{'='*64}")
    print(f"  Press Ctrl+C to stop\n")

    # ── Start TCP server (blocks main thread) ────────────────────────────
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\nCtrl+C received — shutting down gracefully...")
        server.stop()
        log.info("Server shutdown complete.")
        sys.exit(0)


if __name__ == "__main__":
    main()
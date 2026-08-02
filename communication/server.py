"""
server.py
---------
Entry point for the NIDS private network server.

Run this on the machine that will act as the hub:

    python main.py server

The server starts THREE services:
  1. TCP server  (port 5000, TLS encrypted)   — for Python clients
  2. HTTPS server (port 8443, TLS encrypted)  — serves the browser client UI
  3. WSS server   (port 8444, TLS encrypted)  — real-time browser communication
  4. HTTP  server (port 8080, redirect only)  — redirects http:// → https://

Any device on the LAN can then open:
    https://<this-machine-ip>:8443
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
    from config.network_config import (
        HOST, PORT, WEB_PORT, WS_PORT,
        HTTPS_PORT, WSS_PORT, NETWORK_PSK,
    )
except ImportError:
    HOST       = "0.0.0.0"
    PORT       = 5000
    WEB_PORT   = 8080
    WS_PORT    = 8081
    HTTPS_PORT = 8443
    WSS_PORT   = 8444
    NETWORK_PSK = ""

log = get_logger("server")


def main() -> None:
    """Start the NIDS server with HTTP and WebSocket services."""
    local_ip = get_local_ip()
    log.info("Local IP detected as: %s", local_ip)

    # ── Port checks ──────────────────────────────────────────────────────
    for port, label in [
        (PORT,       "TCP"),
        (HTTPS_PORT, "HTTPS"),
        (WSS_PORT,   "WSS"),
        (WEB_PORT,   "HTTP-redirect"),
    ]:
        if is_port_in_use(port, HOST):
            log.error(
                "[%s] Port %d is already in use. Free it or change it in config/network_config.py",
                label, port,
            )
            sys.exit(1)

    # ── Create server ────────────────────────────────────────────────────
    server = NIDSServer(host=HOST, port=PORT)

    # ── Start HTTPS server (daemon thread) ───────────────────────────────────
    try:
        from communication.web_client.http_server import start_https_server
        start_https_server(HOST, https_port=HTTPS_PORT, redirect_port=WEB_PORT)
        log.info("HTTPS server started on port %d (redirect on %d)", HTTPS_PORT, WEB_PORT)
    except Exception as exc:
        log.warning("Could not start HTTPS server: %s", exc)

    # ── Start WSS server (daemon thread) ──────────────────────────────────────
    try:
        from communication.web_client.ws_bridge import start_ws_server
        start_ws_server(server, HOST, WSS_PORT)
        log.info("WSS server started on port %d", WSS_PORT)
    except Exception as exc:
        log.warning("Could not start WSS server: %s", exc)

    # ── Print banner ─────────────────────────────────────────────────────
    tls_status  = "ON" if server._ssl_ctx else "OFF (run generate_certs.py to enable)"
    auth_status = f"ON  (PSK set)" if NETWORK_PSK else "OFF (open network)"
    print(f"\n{'='*64}")
    print(f"  NIDS Private Network Server  —  SECURE MODE")
    print(f"{'='*64}")
    print(f"  TCP   (Python clients): {local_ip}:{PORT}  | TLS: {tls_status}")
    print(f"  HTTPS (Browser UI)    : https://{local_ip}:{HTTPS_PORT}")
    print(f"  WSS   (Real-time)     : wss://{local_ip}:{WSS_PORT}")
    print(f"  HTTP  (auto-redirect) : http://{local_ip}:{WEB_PORT}  -> HTTPS")
    print(f"  Auth  (PSK)           : {auth_status}")
    print(f"{'='*64}")
    print(f"  Open any browser on the LAN and go to:")
    print(f"      https://{local_ip}:{HTTPS_PORT}")
    print(f"  (Accept the self-signed cert warning once)")
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
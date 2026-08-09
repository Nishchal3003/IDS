"""Entry point for the NIDS server — starts TCP, HTTPS, and WSS services."""

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from communication.logger import get_logger
from communication.server_core import NIDSServer
from communication.utils import get_local_ip, is_port_in_use

try:
    from config.network_config import HOST, PORT, WEB_PORT, WS_PORT, HTTPS_PORT, WSS_PORT, NETWORK_PSK
except ImportError:
    HOST, PORT, WEB_PORT, WS_PORT, HTTPS_PORT, WSS_PORT, NETWORK_PSK = \
        "0.0.0.0", 5000, 8080, 8081, 8443, 8444, ""

log = get_logger("server")


def main() -> None:
    local = get_local_ip()
    for port, label in [(PORT, "TCP"), (HTTPS_PORT, "HTTPS"), (WSS_PORT, "WSS"), (WEB_PORT, "HTTP")]:
        if is_port_in_use(port, HOST):
            log.error("[%s] Port %d already in use. Change in config/network_config.py", label, port)
            sys.exit(1)

    server = NIDSServer(host=HOST, port=PORT)

    try:
        from communication.web_client.http_server import start_https_server
        start_https_server(HOST, https_port=HTTPS_PORT, redirect_port=WEB_PORT)
    except Exception as e:
        log.warning("HTTPS server failed: %s", e)

    try:
        from communication.web_client.ws_bridge import start_ws_server
        start_ws_server(server, HOST, WSS_PORT)
    except Exception as e:
        log.warning("WSS server failed: %s", e)

    tls  = "ON" if server._ssl_ctx else "OFF"
    auth = "ON (PSK set)" if NETWORK_PSK else "OFF (open)"
    print(f"\n{'='*56}")
    print(f"  NIDS Server  |  TLS: {tls}  |  Auth: {auth}")
    print(f"  TCP  : {local}:{PORT}")
    print(f"  HTTPS: https://{local}:{HTTPS_PORT}")
    print(f"  WSS  : wss://{local}:{WSS_PORT}")
    print(f"  HTTP : http://{local}:{WEB_PORT} → HTTPS")
    print(f"  Browser: https://{local}:{HTTPS_PORT}")
    print(f"{'='*56}\n")

    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        server.stop()


if __name__ == "__main__":
    main()
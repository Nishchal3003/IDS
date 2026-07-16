"""
server.py
---------
Entry point for the NIDS private network server.

Run this on the machine that will act as the hub:

    python -m communication.server
    OR
    python communication/server.py

The server will:
  1. Read host/port from config/network_config.py.
  2. Instantiate NIDSServer.
  3. Enter the accept loop (blocks until Ctrl+C).
"""

import sys
from pathlib import Path

# Ensure the project root is on sys.path when run directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from communication.logger import get_logger
from communication.server_core import NIDSServer
from communication.utils import get_local_ip, is_port_in_use

# Import config values (falls back gracefully if not set)
try:
    from config.network_config import HOST, PORT
except ImportError:
    HOST = "0.0.0.0"
    PORT = 5000

log = get_logger("server")


def main() -> None:
    """Start the NIDS server."""
    local_ip = get_local_ip()
    log.info("Local IP detected as: %s", local_ip)

    if is_port_in_use(PORT, HOST):
        log.error(
            "Port %d is already in use on %s. "
            "Change PORT in config/network_config.py or free the port.",
            PORT, HOST,
        )
        sys.exit(1)

    server = NIDSServer(host=HOST, port=PORT)

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n\nCtrl+C received – shutting down server gracefully...")
        server.stop()
        log.info("Server shutdown complete.")
        sys.exit(0)


if __name__ == "__main__":
    main()
"""
main.py
-------
Intelligent-NIDS – top-level entry point.

Usage
-----
Run the server:
    python main.py server

Run the client:
    python main.py client

In future phases, additional sub-commands will be added here:
    python main.py capture     # packet capture daemon
    python main.py dashboard   # Streamlit dashboard
    python main.py train       # ML model training
"""

import sys


def print_usage() -> None:
    print("""
Intelligent Network Intrusion Detection System
===============================================

Usage:
  python main.py server                    – Start the NIDS communication server
  python main.py client                    – Start an interactive client terminal
  python main.py capture                   – Start packet capture (Phase 2)
  python main.py capture --list            – List available network interfaces
  python main.py capture -i WiFi -d 60     – Capture on WiFi for 60 seconds
  python main.py capture --help            – All capture options

Phase 1: Communication Network  [DONE]
Phase 2: Packet Capture         [DONE]
Phase 3: ML Pipeline            (coming next)
Phase 4: Dashboard              (coming next)
""")


def main() -> None:
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "server":
        from communication.server import main as server_main
        server_main()

    elif command == "client":
        from communication.client import main as client_main
        client_main()

    elif command == "capture":
        from capture.capture_daemon import main as capture_main
        capture_main(sys.argv[2:])   # forward remaining args (--interface etc.)

    else:
        print(f"  Unknown command: {command!r}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()

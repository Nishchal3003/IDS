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
  python main.py server    – Start the NIDS communication server
  python main.py client    – Start an interactive client terminal

Phase 1: Communication Network  ✓
Phase 2: Packet Capture         (coming next)
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

    else:
        print(f"  Unknown command: {command!r}")
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()

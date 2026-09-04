"""
main.py
-------
Intelligent-NIDS  top-level entry point.

Usage
-----
  python main.py nids              Start NIDS server (all-in-one: comm + capture + dashboard)
  python main.py client            Start an interactive client terminal (auto-discovers server)
  python main.py server            Start communication server only
  python main.py capture --live    Capture + live detection only
  python main.py dashboard         Start Streamlit dashboard only
  python main.py mock [seconds]    Run mock traffic (dev/testing)
  python main.py train             Train ML models
  python main.py evaluate          Evaluate trained model
"""

import sys


def print_usage() -> None:
    print("""
Intelligent Network Intrusion Detection System
===============================================

QUICK START:
  NIDS Server machine:
    python main.py nids              All-in-one: comm server + capture + dashboard

  Client machine (any LAN device):
    python main.py client            Auto-discovers server, no IP needed

ALL COMMANDS:
  python main.py nids              NIDS server (all-in-one)
  python main.py client            Interactive client (auto-discover)
  python main.py server            Communication server only
  python main.py capture --live    Packet capture + live detection only
  python main.py dashboard         Streamlit dashboard only
  python main.py mock [seconds]    Mock traffic for dev/testing
  python main.py train             Train ML models
  python main.py evaluate          Evaluate + generate reports
""")


def main() -> None:
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(0)

    command = sys.argv[1].lower()

    if command == "nids":
        from communication.nids_launcher import run_nids_server
        run_nids_server()

    elif command == "server":
        from communication.server import main as server_main
        server_main()

    elif command == "client":
        from communication.client import main as client_main
        client_main()

    elif command == "capture":
        from capture.capture_daemon import main as capture_main
        capture_main(sys.argv[2:])

    elif command == "train":
        from ml.train import run_training
        run_training()

    elif command == "evaluate":
        from ml.evaluate import run_evaluation
        run_evaluation()

    elif command == "dashboard":
        import subprocess
        import os
        dashboard_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "dashboard", "dashboard.py",
        )
        try:
            subprocess.run(
                [sys.executable, "-m", "streamlit", "run", dashboard_path],
                check=False,
            )
        except KeyboardInterrupt:
            print("\nDashboard stopped.")

    elif command == "mock":
        from dashboard.mock_traffic_generator import run_mock
        duration = float(sys.argv[2]) if len(sys.argv) > 2 else 120.0
        run_mock(duration_seconds=duration, verbose=True)

    else:
        print("  Unknown command: {!r}".format(command))
        print_usage()
        sys.exit(1)


if __name__ == "__main__":
    main()

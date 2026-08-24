"""
main.py
-------
Intelligent-NIDS  top-level entry point.

Usage
-----
  python main.py server            Start the communication server
  python main.py client            Start an interactive client terminal
  python main.py capture           Packet capture daemon (Phase 2)
  python main.py capture --live    Capture + live PortScan/DoS detection (Phase 4)
  python main.py train             Train ML models (Phase 3)
  python main.py evaluate          Evaluate trained model + generate reports (Phase 3)
  python main.py dashboard         Start Streamlit monitoring dashboard (Phase 5)
  python main.py mock [seconds]    Run mock traffic to test detection + dashboard
"""

import sys


def print_usage() -> None:
    print("""
Intelligent Network Intrusion Detection System
===============================================

Usage:
  python main.py server              Start the NIDS communication server
  python main.py client              Start an interactive client terminal

  python main.py capture             Start packet capture (Phase 2)
  python main.py capture --live      Capture + live PortScan/DoS detection (Phase 4)
  python main.py capture --list      List available network interfaces
  python main.py capture --help      All capture options

  python main.py train               Train ML intrusion detection models (Phase 3)
  python main.py evaluate            Evaluate + generate reports (Phase 3)

  python main.py dashboard           Start Streamlit monitoring dashboard (Phase 5)
  python main.py mock [seconds]      Simulate traffic to test detection + dashboard

Phase 1: Communication Network   [DONE]
Phase 2: Packet Capture          [DONE]
Phase 3: ML Pipeline             [DONE]
Phase 4: Real-time Detection     [DONE  use: capture --live]
Phase 5: Dashboard               [DONE  use: dashboard]
Phase 6: XAI / SHAP              [DONE  auto in dashboard when shap installed]
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
        subprocess.run(
            [sys.executable, "-m", "streamlit", "run", dashboard_path],
            check=False,
        )

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

"""
attacks/run_tests.py
--------------------
Auto-discovery test runner for the Intelligent-NIDS lab.

Automatically finds the current LAN IP of this machine,
then runs the authorized PortScan and DoS tests targeting it.

Useful for single-machine self-testing — no need to know or
hardcode your IP address.

USAGE
-----
# Self-test (target = this machine's own LAN IP)
    python attacks/run_tests.py

# Target a specific IP (another machine on the LAN)
    python attacks/run_tests.py --target 192.168.x.x

# Run only PortScan
    python attacks/run_tests.py --test portscan

# Run only DoS
    python attacks/run_tests.py --test dos

# Custom intensity
    python attacks/run_tests.py --ps-rate 300 --dos-rate 200 --dos-duration 15

REQUIREMENTS
------------
The NIDS server must already be running:
    Terminal 1: python main.py capture --live
    Terminal 2: python main.py dashboard

Then open http://localhost:8501 in a browser and run this script.
"""

import argparse
import os
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def get_lan_ip() -> str:
    """Discover this machine's outbound LAN IP (not loopback)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def print_header(target: str, tests: list):
    print()
    print("=" * 60)
    print("  NIDS END-TO-END ATTACK TEST RUNNER")
    print("=" * 60)
    print(f"  Target IP  : {target}")
    print(f"  Tests      : {', '.join(tests)}")
    print()
    print("  Make sure these are running BEFORE continuing:")
    print("    Terminal 1: python main.py capture --live")
    print("    Terminal 2: python main.py dashboard")
    print("    Browser   : http://localhost:8501")
    print()
    input("  Press ENTER when ready (or Ctrl+C to abort)...")
    print()


def main():
    p = argparse.ArgumentParser(
        description="Auto-discovery NIDS end-to-end test runner"
    )
    p.add_argument(
        "--target", "-t", default=None,
        help="Target IP (default: auto-detect this machine's LAN IP)"
    )
    p.add_argument(
        "--test", choices=["portscan", "dos", "both"], default="both",
        help="Which test to run (default: both)"
    )
    p.add_argument(
        "--ps-ports", default="20-120",
        help="PortScan port range (default: 20-120)"
    )
    p.add_argument(
        "--ps-rate", type=float, default=200,
        help="PortScan rate ports/sec (default: 200)"
    )
    p.add_argument(
        "--dos-port", type=int, default=5000,
        help="DoS target port (default: 5000 = NIDS server)"
    )
    p.add_argument(
        "--dos-rate", type=float, default=150,
        help="DoS connections/sec (default: 150)"
    )
    p.add_argument(
        "--dos-duration", type=float, default=10,
        help="DoS duration seconds (default: 10)"
    )
    p.add_argument(
        "--log", action="store_true",
        help="Save experiment results to attacks/experiment_log.json"
    )
    p.add_argument(
        "--no-pause", action="store_true",
        help="Skip the ready confirmation prompt"
    )
    args = p.parse_args()

    # Auto-discover IP
    target = args.target or get_lan_ip()
    tests  = (
        ["portscan", "dos"] if args.test == "both"
        else [args.test]
    )

    if not args.no_pause:
        print_header(target, tests)

    print(f"[RUNNER] Using target: {target}")
    print()

    # ── PortScan test ────────────────────────────────────────────────────────
    if "portscan" in tests:
        print("[RUNNER] Starting PortScan test...")
        from attacks.portscan_test import run_portscan, _is_private, _print_banner
        import argparse as _ap
        if not _is_private(target):
            print(f"  [ERROR] {target} is not a private IP. Skipping.")
        else:
            pf, pt = [int(x) for x in args.ps_ports.split("-")]
            _args = _ap.Namespace(
                target=target, port_from=pf, port_to=pt,
                rate=args.ps_rate, ports=None
            )
            _print_banner(_args)
            ps_result = run_portscan(
                target=target, port_from=pf, port_to=pt,
                rate=args.ps_rate, verbose=True,
            )
            if args.log:
                _save_log(ps_result)

        print()
        print("[RUNNER] Waiting 5s before DoS test (let NIDS finish processing)...")
        time.sleep(5)
        print()

    # ── DoS test ─────────────────────────────────────────────────────────────
    if "dos" in tests:
        print("[RUNNER] Starting DoS test...")
        from attacks.dos_test import run_dos_test, _is_private, _print_banner
        import argparse as _ap
        if not _is_private(target):
            print(f"  [ERROR] {target} is not a private IP. Skipping.")
        else:
            _args = _ap.Namespace(
                target=target, port=args.dos_port,
                rate=args.dos_rate, duration=args.dos_duration,
            )
            _print_banner(_args)
            dos_result = run_dos_test(
                target=target, port=args.dos_port,
                rate=args.dos_rate, duration=args.dos_duration,
                verbose=True,
            )
            if args.log:
                _save_log(dos_result)

    print()
    print("=" * 60)
    print("  TEST RUN COMPLETE")
    print("=" * 60)
    print("  Check the dashboard for alerts:")
    print("  http://localhost:8501")
    print()
    print("  Expected results:")
    if "portscan" in tests:
        print("  PortScan  -> 🔴 HIGH severity alert")
    if "dos" in tests:
        print("  DoS       -> 🚨 CRITICAL severity alert")
    print()


def _save_log(result: dict):
    import json
    log_path = os.path.join(os.path.dirname(__file__), "experiment_log.json")
    existing = []
    if os.path.exists(log_path):
        try:
            with open(log_path) as f:
                existing = json.load(f)
        except Exception:
            existing = []
    existing.append(result)
    with open(log_path, "w") as f:
        json.dump(existing, f, indent=2)
    print(f"  [LOG] Saved to {log_path}")


if __name__ == "__main__":
    main()

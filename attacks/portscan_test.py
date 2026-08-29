"""
attacks/portscan_test.py
------------------------
Authorized controlled PortScan test tool for the Intelligent-NIDS private lab.

PURPOSE
    Generates real TCP connection attempts across a configurable port range
    against the NIDS server. The NIDS packet sniffer observes the actual
    network traffic and the PortScanDetector identifies the pattern.

    This is NOT a mock — it sends real packets over the Wi-Fi/LAN.

SAFETY RULES
    • Target must be a private/LAN IP address (enforced).
    • Port range is bounded (max 1000 ports per run).
    • Rate is bounded (max 500 ports/sec).
    • Safe defaults: 100 ports, 200/sec rate.
    • Prints clear AUTHORIZED TEST banner.

USAGE (from Client C on the same LAN)
    python attacks/portscan_test.py --target 192.168.0.102
    python attacks/portscan_test.py --target 192.168.0.102 --ports 20-120 --rate 100

EXPECTED NIDS RESPONSE
    PacketSniffer captures SYN packets
    → FlowTracker tracks connections
    → PortScanDetector triggers on >= 10 unique ports in 5s window
    → Dashboard alert: 🚨 PortScan Detected
"""

import argparse
import ipaddress
import socket
import sys
import time
import os

# Experiment logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
]

MAX_PORTS_PER_RUN = 1000
MAX_RATE          = 500   # ports per second
DEFAULT_RATE      = 200
DEFAULT_PORT_FROM = 20
DEFAULT_PORT_TO   = 120
CONNECT_TIMEOUT   = 0.05  # 50ms per port — fast enough to be detectable


def _is_private(ip_str: str) -> bool:
    """Return True if the IP is in a private/loopback range."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _print_banner(args):
    print()
    print("=" * 60)
    print("  AUTHORIZED PORTSCAN TEST — PRIVATE LAB USE ONLY")
    print("=" * 60)
    print(f"  Target      : {args.target}")
    print(f"  Port range  : {args.port_from} – {args.port_to}")
    print(f"  Rate        : {args.rate} ports/second")
    print(f"  Total ports : {args.port_to - args.port_from + 1}")
    print("  NOTE: Only use on your own private/lab network.")
    print("=" * 60)
    print()


def _try_connect(target: str, port: int, timeout: float) -> str:
    """Attempt TCP connection. Returns 'open', 'closed', or 'filtered'."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target, port))
            return "open" if result == 0 else "closed"
    except socket.timeout:
        return "filtered"
    except OSError:
        return "error"


def run_portscan(target: str, port_from: int, port_to: int,
                 rate: float, verbose: bool = True) -> dict:
    """
    Execute the port scan. Returns experiment result dict.

    Parameters
    ----------
    target    : str   Target IP (must be private/LAN)
    port_from : int   First port in range
    port_to   : int   Last port in range (inclusive)
    rate      : float Ports per second (max 500)
    verbose   : bool  Print per-port results
    """
    if not _is_private(target):
        print(f"[ERROR] Target {target!r} is not a private/LAN address.")
        print("        PortScan test is restricted to private networks only.")
        sys.exit(1)

    num_ports   = port_to - port_from + 1
    delay       = 1.0 / min(rate, MAX_RATE)
    start_time  = time.time()
    open_ports  = []
    closed_count= 0

    for port in range(port_from, port_to + 1):
        status = _try_connect(target, port, CONNECT_TIMEOUT)
        if status == "open":
            open_ports.append(port)
            if verbose:
                print(f"  [OPEN]    {target}:{port}")
        elif verbose and port % 10 == 0:
            elapsed = time.time() - start_time
            done    = port - port_from + 1
            print(f"  [SCAN]    {done}/{num_ports} ports | {elapsed:.1f}s elapsed | open: {len(open_ports)}")
        time.sleep(delay)

    elapsed   = time.time() - start_time
    scan_rate = num_ports / max(elapsed, 0.001)

    result = {
        "test_type"      : "PortScan",
        "target"         : target,
        "port_from"      : port_from,
        "port_to"        : port_to,
        "ports_scanned"  : num_ports,
        "open_ports"     : open_ports,
        "open_count"     : len(open_ports),
        "elapsed_seconds": round(elapsed, 2),
        "actual_rate"    : round(scan_rate, 1),
        "start_time"     : time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
        "end_time"       : time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    print()
    print("=" * 60)
    print("  PortScan Complete")
    print("=" * 60)
    print(f"  Ports scanned : {num_ports}")
    print(f"  Open ports    : {len(open_ports)} {open_ports[:10]}{'...' if len(open_ports)>10 else ''}")
    print(f"  Duration      : {elapsed:.2f}s")
    print(f"  Actual rate   : {scan_rate:.1f} ports/sec")
    print(f"  NIDS should have detected PortScan if >= 10 ports reached in < 5s")
    print("=" * 60)

    return result


def _parse_args():
    p = argparse.ArgumentParser(
        description="Authorized PortScan test — private/lab network only"
    )
    p.add_argument(
        "--target", "-t", required=True,
        help="Target IP address (must be private/LAN)"
    )
    p.add_argument(
        "--port-from", "--pf", type=int, default=DEFAULT_PORT_FROM,
        dest="port_from",
        help=f"Start port (default: {DEFAULT_PORT_FROM})"
    )
    p.add_argument(
        "--port-to", "--pt", type=int, default=DEFAULT_PORT_TO,
        dest="port_to",
        help=f"End port inclusive (default: {DEFAULT_PORT_TO})"
    )
    p.add_argument(
        "--ports", "-p",
        help="Port range as 'start-end' (e.g. 20-120), overrides --port-from/--port-to"
    )
    p.add_argument(
        "--rate", "-r", type=float, default=DEFAULT_RATE,
        help=f"Ports per second (max {MAX_RATE}, default: {DEFAULT_RATE})"
    )
    p.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress per-port output"
    )
    p.add_argument(
        "--log", action="store_true",
        help="Save experiment result to attacks/experiment_log.json"
    )
    return p.parse_args()


def main():
    args = _parse_args()

    # Handle --ports shorthand
    if args.ports:
        try:
            pf, pt = args.ports.split("-")
            args.port_from = int(pf.strip())
            args.port_to   = int(pt.strip())
        except ValueError:
            print(f"[ERROR] --ports must be in format 'start-end', e.g. '20-120'")
            sys.exit(1)

    # Validate range
    if args.port_from < 1 or args.port_to > 65535 or args.port_from > args.port_to:
        print("[ERROR] Invalid port range. Must be 1–65535 with port_from <= port_to.")
        sys.exit(1)
    if args.port_to - args.port_from + 1 > MAX_PORTS_PER_RUN:
        print(f"[ERROR] Port range too large (max {MAX_PORTS_PER_RUN} ports per run).")
        sys.exit(1)

    _print_banner(args)

    result = run_portscan(
        target    = args.target,
        port_from = args.port_from,
        port_to   = args.port_to,
        rate      = args.rate,
        verbose   = not args.quiet,
    )

    if args.log:
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
        print(f"\n  [LOG] Experiment saved to: {log_path}")


if __name__ == "__main__":
    main()

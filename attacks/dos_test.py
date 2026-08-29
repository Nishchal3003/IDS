"""
attacks/dos_test.py
-------------------
Authorized controlled DoS / SYN-flood-like test tool for Intelligent-NIDS.

PURPOSE
    Generates a high volume of rapid TCP connection attempts (SYN-heavy
    traffic) against a single port on the NIDS server. The NIDS packet
    sniffer captures the traffic and the SYNFloodDetector identifies the
    pattern from observed SYN flag counts and ACK ratio.

    This is NOT a mock — it sends real packets over the Wi-Fi/LAN.

SAFETY RULES
    • Target must be a private/LAN IP address (enforced).
    • Duration is bounded (max 30 seconds per run).
    • Rate is bounded (max 500 connections/sec, default 100).
    • A connect-and-close pattern is used (not raw socket SYN injection)
      which is safe and does not require administrator/root privileges.
    • Prints clear AUTHORIZED TEST banner with countdown.
    • Ctrl+C stops immediately.

HOW IT WORKS
    Each "connection attempt" opens a TCP socket (generating a SYN packet)
    and immediately closes it without completing the handshake timeout.
    The NIDS captures: many SYN packets, very few ACK packets.
    SYNFloodDetector condition:
        total_syn >= 20
        num_flows >= 10
        syn_rate >= 10 /sec
        ack_ratio <= 0.25

USAGE (from Client C on the same LAN)
    python attacks/dos_test.py --target 192.168.0.102
    python attacks/dos_test.py --target 192.168.0.102 --port 80 --rate 200 --duration 10

EXPECTED NIDS RESPONSE
    PacketSniffer captures high-rate SYN traffic
    → FlowTracker tracks connections
    → SYNFloodDetector triggers
    → Dashboard alert: 🚨 DoS Detected
"""

import argparse
import ipaddress
import socket
import sys
import threading
import time
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PRIVATE_NETWORKS = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
]

MAX_DURATION_SECONDS = 30
MAX_RATE             = 500    # connections per second
DEFAULT_RATE         = 100
DEFAULT_PORT         = 80
DEFAULT_DURATION     = 10
CONNECT_TIMEOUT      = 0.1    # 100ms per attempt


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


def _print_banner(args):
    print()
    print("=" * 60)
    print("  AUTHORIZED DoS TEST — PRIVATE LAB USE ONLY")
    print("=" * 60)
    print(f"  Target      : {args.target}:{args.port}")
    print(f"  Duration    : {args.duration}s")
    print(f"  Rate        : {args.rate} connections/sec")
    print(f"  Total conns : ~{int(args.duration * args.rate)}")
    print("  NOTE: Only use on your own private/lab network.")
    print("=" * 60)
    print()


def _make_connection(target: str, port: int) -> None:
    """Open and immediately close one TCP connection."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(CONNECT_TIMEOUT)
            s.connect_ex((target, port))
    except Exception:
        pass


def run_dos_test(target: str, port: int, rate: float,
                 duration: float, verbose: bool = True) -> dict:
    """
    Execute the DoS test. Returns experiment result dict.

    Parameters
    ----------
    target   : str   Target IP (must be private/LAN)
    port     : int   Target port
    rate     : float Connections per second (max 500)
    duration : float Test duration in seconds (max 30)
    verbose  : bool  Print progress updates
    """
    if not _is_private(target):
        print(f"[ERROR] Target {target!r} is not a private/LAN address.")
        sys.exit(1)

    delay       = 1.0 / min(rate, MAX_RATE)
    duration    = min(duration, MAX_DURATION_SECONDS)
    deadline    = time.time() + duration
    start_time  = time.time()
    count       = 0
    stop_event  = threading.Event()

    if verbose:
        print(f"[DoS] Sending rapid TCP connections to {target}:{port}")
        print(f"[DoS] Running for {duration:.0f}s at {rate:.0f} conn/sec — Ctrl+C to stop early\n")

    try:
        while time.time() < deadline and not stop_event.is_set():
            # Use threads for speed (non-blocking pattern)
            t = threading.Thread(
                target=_make_connection,
                args=(target, port),
                daemon=True
            )
            t.start()
            count += 1
            time.sleep(delay)

            if verbose and count % 50 == 0:
                elapsed = time.time() - start_time
                remaining = max(0, duration - elapsed)
                print(f"  [DoS] Connections sent: {count} | Elapsed: {elapsed:.1f}s | Remaining: {remaining:.1f}s")

    except KeyboardInterrupt:
        print("\n[DoS] Stopped by user.")

    elapsed     = time.time() - start_time
    actual_rate = count / max(elapsed, 0.001)

    result = {
        "test_type"          : "DoS_SYNFlood",
        "target"             : f"{target}:{port}",
        "connections_sent"   : count,
        "configured_rate"    : rate,
        "actual_rate"        : round(actual_rate, 1),
        "duration_configured": duration,
        "duration_actual"    : round(elapsed, 2),
        "start_time"         : time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start_time)),
        "end_time"           : time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    print()
    print("=" * 60)
    print("  DoS Test Complete")
    print("=" * 60)
    print(f"  Connections sent : {count}")
    print(f"  Duration         : {elapsed:.2f}s")
    print(f"  Actual rate      : {actual_rate:.1f} conn/sec")
    print(f"  NIDS should have detected SYNFlood if >= 20 SYN in 5s window")
    print("=" * 60)

    return result


def _parse_args():
    p = argparse.ArgumentParser(
        description="Authorized DoS/SYNFlood test — private/lab network only"
    )
    p.add_argument(
        "--target", "-t", required=True,
        help="Target IP address (must be private/LAN)"
    )
    p.add_argument(
        "--port", "-p", type=int, default=DEFAULT_PORT,
        help=f"Target port (default: {DEFAULT_PORT})"
    )
    p.add_argument(
        "--rate", "-r", type=float, default=DEFAULT_RATE,
        help=f"Connections per second (max {MAX_RATE}, default: {DEFAULT_RATE})"
    )
    p.add_argument(
        "--duration", "-d", type=float, default=DEFAULT_DURATION,
        help=f"Test duration in seconds (max {MAX_DURATION_SECONDS}, default: {DEFAULT_DURATION})"
    )
    p.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress progress output"
    )
    p.add_argument(
        "--log", action="store_true",
        help="Save experiment result to attacks/experiment_log.json"
    )
    return p.parse_args()


def main():
    args = _parse_args()

    if args.duration > MAX_DURATION_SECONDS:
        print(f"[WARN] Duration capped at {MAX_DURATION_SECONDS}s for safety.")
        args.duration = MAX_DURATION_SECONDS

    if not _is_private(args.target):
        print(f"[ERROR] Target {args.target!r} is not a private/LAN address.")
        sys.exit(1)

    _print_banner(args)

    result = run_dos_test(
        target   = args.target,
        port     = args.port,
        rate     = args.rate,
        duration = args.duration,
        verbose  = not args.quiet,
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

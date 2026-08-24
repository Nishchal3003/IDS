"""
capture_daemon.py
-----------------
Top-level runner for the Phase-2 packet capture pipeline.

Started by:
    python main.py capture [options]

Options
-------
--interface, -i  <name>   Network interface to sniff (default: auto)
--duration,  -d  <secs>   Stop after N seconds (default: run until Ctrl+C)
--output,    -o  <dir>    Output directory for CSV (default: datasets/captures/)
--filter,    -f  <bpf>    BPF capture filter    (default: "ip")
--list,      -l           List available interfaces and exit
--quiet,     -q           Suppress per-flow console output
--timeout    <secs>       Flow idle timeout in seconds (default: 120)

Architecture
------------
Main thread:
  → Starts CaptureLogger (daemon thread)
  → Starts PacketSniffer (daemon thread)
  → Starts expiry timer  (daemon thread)
  → Blocks on user interrupt (Ctrl+C) or --duration timer

On shutdown (Ctrl+C or duration elapsed):
  1. Stop sniffer
  2. Flush all active flows → CaptureLogger queue
  3. Wait for queue to drain (CaptureLogger writes final rows)
  4. Stop logger, close CSV
  5. Print summary
"""

import argparse
import queue
import sys
import time
import threading
from pathlib import Path

from capture.constants import (
    CAPTURE_CSV_DIR,
    DEFAULT_FILTER,
    FLOW_TIMEOUT,
)
from capture.flow_tracker import FlowTracker
from capture.sniffer import (
    PacketSniffer,
    check_capture_backend,
    print_interfaces,
)
from capture.capture_logger import CaptureLogger


# ---------------------------------------------------------------------------
# Phase 4 live inference hook
# ---------------------------------------------------------------------------

def _make_live_hook(engine, bridge, tracker):
    """
    Return an on_flow_completed callback that feeds each completed flow
    through LiveInferenceEngine and pushes the result to DashboardBridge.
    """
    def _hook(flow_dict: dict) -> None:
        try:
            result = engine.process_flow(flow_dict)
            bridge.update(
                result,
                packet_count = 1,
                active_flows = tracker.active_flow_count,
            )
            if result.get("is_attack"):
                print(
                    "  [ALERT] {} | {} -> {} | {}".format(
                        result.get("final_decision"),
                        result.get("src_ip"),
                        result.get("dst_ip"),
                        result.get("detection_reason"),
                    )
                )
        except Exception:
            pass  # never let detection errors crash the capture thread
    return _hook


# ---------------------------------------------------------------------------
# Expiry thread
# ---------------------------------------------------------------------------

def _run_expiry_thread(tracker: FlowTracker, stop_event: threading.Event) -> None:
    """Periodically expire idle flows (runs in a daemon thread)."""
    interval = max(10.0, FLOW_TIMEOUT / 10)
    while not stop_event.is_set():
        expired = tracker.expire_idle_flows()
        if expired:
            print(f"  [EXPIRY] {expired} idle flow(s) expired.")
        stop_event.wait(interval)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list = None) -> None:
    args = _parse_args(argv)

    # ── --list: show interfaces and exit ─────────────────────────────────
    if args.list:
        print_interfaces()
        sys.exit(0)

    # ── Npcap check ───────────────────────────────────────────────────────
    if not check_capture_backend():
        sys.exit(1)

    # ── Banner ────────────────────────────────────────────────────────────
    _print_banner(args)

    # ── Build pipeline ────────────────────────────────────────────────────
    completed_q = queue.Queue()
    flow_timeout = args.timeout if args.timeout else FLOW_TIMEOUT

    tracker = FlowTracker(
        completed_queue = completed_q,
        flow_timeout    = flow_timeout,
    )

    logger = CaptureLogger(
        completed_queue = completed_q,
        output_dir      = args.output,
        verbose         = not args.quiet,
    )

    sniffer = PacketSniffer(
        flow_tracker = tracker,
        interface    = args.interface or None,
        bpf_filter   = args.filter,
    )

    # ── Phase 4: attach live inference hook if --live flag set ─────────────
    if getattr(args, "live", False):
        try:
            from ml.live_inference import get_engine
            from dashboard.dashboard_bridge import bridge_instance
            engine = get_engine()
            logger.on_flow_completed = _make_live_hook(engine, bridge_instance, tracker)
            print("  [OK] Live inference hook attached (PortScan + DoS detection active)")
        except Exception as exc:
            print(f"  [WARN] Live inference unavailable: {exc}")

    # ── Start all components ──────────────────────────────────────────────
    logger.start()
    sniffer.start()

    stop_expiry = threading.Event()
    expiry_thread = threading.Thread(
        target = _run_expiry_thread,
        args   = (tracker, stop_expiry),
        daemon = True,
        name   = "flow-expiry",
    )
    expiry_thread.start()

    print(f"  [OK] Capture started on interface: {args.interface or 'auto'}")
    print(f"  [OK] Writing flows to: {logger.csv_path}")
    if args.duration:
        print(f"  [OK] Will stop automatically after {args.duration}s")
    print(f"\n  Press Ctrl+C to stop.\n")

    # ── Wait (Ctrl+C or duration) ─────────────────────────────────────────
    try:
        if args.duration:
            time.sleep(args.duration)
            print(f"\n  [INFO] Duration ({args.duration}s) elapsed — stopping capture.")
        else:
            while sniffer.is_alive():
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Ctrl+C — stopping capture...")

    # ── Shutdown sequence ─────────────────────────────────────────────────
    stop_expiry.set()
    sniffer.stop()

    print(f"  [INFO] Flushing {tracker.active_flow_count} active flow(s)...")
    flushed = tracker.flush_all()

    # Wait for the queue to drain
    completed_q.join()

    logger.stop()

    # ── Summary ───────────────────────────────────────────────────────────
    stats = tracker.stats
    print()
    print("=" * 56)
    print("  Capture Complete")
    print("=" * 56)
    print(f"  Packets captured  : {stats['packets_seen']:,}")
    print(f"  Flows completed   : {stats['completed_flows']:,}")
    print(f"  Rows written      : {logger.rows_written:,}")
    print(f"  Output CSV        : {logger.csv_path}")
    print("=" * 56)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def _parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog        = "python main.py capture",
        description = "NIDS Phase 2 — Network Packet Capture & Feature Extraction",
        formatter_class = argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "-i", "--interface",
        help    = "Network interface to capture on (run --list to see options)",
        default = None,
    )
    p.add_argument(
        "-d", "--duration",
        help    = "Stop capturing after N seconds",
        type    = float,
        default = None,
    )
    p.add_argument(
        "-o", "--output",
        help    = f"Output directory for CSV (default: {CAPTURE_CSV_DIR})",
        default = CAPTURE_CSV_DIR,
    )
    p.add_argument(
        "-f", "--filter",
        help    = "BPF packet filter (default: 'ip' = all IPv4)",
        default = DEFAULT_FILTER,
    )
    p.add_argument(
        "-l", "--list",
        help    = "List available network interfaces and exit",
        action  = "store_true",
    )
    p.add_argument(
        "-q", "--quiet",
        help    = "Suppress per-flow console output",
        action  = "store_true",
    )
    p.add_argument(
        "--live",
        help    = "Enable Phase 4 live ML + behavioural detection (PortScan, DoS)",
        action  = "store_true",
    )
    p.add_argument(
        "--timeout",
        help    = f"Flow idle timeout in seconds (default: {FLOW_TIMEOUT})",
        type    = float,
        default = None,
    )
    return p.parse_args(argv)


def _print_banner(args: argparse.Namespace) -> None:
    print()
    print("=" * 56)
    print("  NIDS Phase 2 — Packet Capture")
    print("=" * 56)
    print(f"  Interface : {args.interface or 'auto-detect'}")
    print(f"  Filter    : {args.filter}")
    print(f"  Output    : {args.output}")
    print(f"  Duration  : {args.duration or 'until Ctrl+C'}")
    print("=" * 56)
    print()

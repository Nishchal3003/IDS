"""NIDS Phase-2 packet capture pipeline runner.

Usage: python main.py capture [-i interface] [-d secs] [-o dir] [-f bpf] [-l] [-q]
"""

import argparse
import queue
import sys
import threading
import time
from pathlib import Path

from capture.constants import CAPTURE_CSV_DIR, DEFAULT_FILTER, FLOW_TIMEOUT
from capture.capture_logger import CaptureLogger
from capture.flow_tracker import FlowTracker
from capture.sniffer import PacketSniffer, check_capture_backend, print_interfaces


def main(argv: list = None) -> None:
    p = argparse.ArgumentParser(prog="python main.py capture",
                                description="NIDS Phase 2 — Packet Capture & Feature Extraction")
    p.add_argument("-i", "--interface", default=None, help="Network interface (see --list)")
    p.add_argument("-d", "--duration",  type=float, default=None, help="Stop after N seconds")
    p.add_argument("-o", "--output",    default=CAPTURE_CSV_DIR, help="Output directory for CSV")
    p.add_argument("-f", "--filter",    default=DEFAULT_FILTER,  help="BPF packet filter")
    p.add_argument("-l", "--list",      action="store_true",     help="List interfaces and exit")
    p.add_argument("-q", "--quiet",     action="store_true",     help="Suppress per-flow output")
    p.add_argument("--timeout", type=float, default=None,        help="Flow idle timeout (s)")
    args = p.parse_args(argv)

    if args.list:
        print_interfaces(); sys.exit(0)
    if not check_capture_backend():
        sys.exit(1)

    flow_timeout = args.timeout or FLOW_TIMEOUT
    q = queue.Queue()
    tracker = FlowTracker(completed_queue=q, flow_timeout=flow_timeout)
    logger  = CaptureLogger(completed_queue=q, output_dir=args.output, verbose=not args.quiet)
    sniffer = PacketSniffer(flow_tracker=tracker, interface=args.interface or None, bpf_filter=args.filter)

    logger.start()
    sniffer.start()

    stop_expiry = threading.Event()
    def _expiry_loop():
        interval = max(10.0, flow_timeout / 10)
        while not stop_expiry.is_set():
            n = tracker.expire_idle_flows()
            if n: print(f"  [EXPIRY] {n} idle flow(s) expired.")
            stop_expiry.wait(interval)
    threading.Thread(target=_expiry_loop, daemon=True, name="flow-expiry").start()

    print(f"\n{'='*50}\n  NIDS Phase 2 — Packet Capture")
    print(f"  Interface: {args.interface or 'auto'}  |  Filter: {args.filter}")
    print(f"  Output: {logger.csv_path}")
    print(f"  Duration: {args.duration or 'until Ctrl+C'}")
    print(f"{'='*50}\n  Press Ctrl+C to stop.\n")

    try:
        if args.duration:
            time.sleep(args.duration)
            print(f"\n  [{args.duration}s elapsed] Stopping capture.")
        else:
            while sniffer.is_alive():
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n  Ctrl+C — stopping...")

    stop_expiry.set()
    sniffer.stop()
    print(f"  Flushing {tracker.active_flow_count} active flow(s)...")
    tracker.flush_all()
    q.join()
    logger.stop()

    s = tracker.stats
    print(f"\n{'='*50}\n  Capture Complete")
    print(f"  Packets: {s['packets_seen']:,}  |  Flows: {s['completed_flows']:,}  |  Rows: {logger.rows_written:,}")
    print(f"  CSV: {logger.csv_path}\n{'='*50}")


if __name__ == "__main__":
    main()

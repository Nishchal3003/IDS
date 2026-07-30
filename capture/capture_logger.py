"""
capture_logger.py
-----------------
Consumes completed Flow objects from the flow_tracker queue, extracts
features via ``feature_extractor``, and writes rows to a rotating CSV file.

Design
------
• Runs in a dedicated daemon thread — never blocks the sniffer.
• Opens the CSV in append mode; writes the header only for new files.
• Rotates the output file when MAX_CSV_ROWS is reached.
• Provides real-time console progress output (flow count + stats).
• Exposes a callback hook ``on_flow_completed`` for Phase 3 to attach
  the real-time ML classifier.
"""

import csv
import os
import queue
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from capture.constants import (
    CAPTURE_CSV_DIR,
    FEATURE_COLUMNS,
    MAX_CSV_ROWS,
)
from capture.feature_extractor import extract_features
from capture.flow import Flow


class CaptureLogger:
    """
    Reads completed flows from a queue and writes feature rows to CSV.

    Parameters
    ----------
    completed_queue : queue.Queue
        Source of completed Flow objects (produced by FlowTracker).
    output_dir : str | Path
        Directory where CSV files are written.
    session_name : str | None
        Base name for the output CSV.  Auto-generated if None.
    on_flow_completed : callable | None
        Optional callback ``fn(features_dict)`` invoked for every flow.
        Phase 3 attaches the ML classifier here.
    verbose : bool
        If True, print a one-line summary to the console for each flow.
    """

    def __init__(
        self,
        completed_queue    : queue.Queue,
        output_dir         : str = CAPTURE_CSV_DIR,
        session_name       : Optional[str] = None,
        on_flow_completed  : Optional[Callable] = None,
        verbose            : bool = True,
    ) -> None:
        self._queue       = completed_queue
        self._output_dir  = Path(output_dir)
        self._session     = session_name or _make_session_name()
        self._on_flow     = on_flow_completed
        self._verbose     = verbose

        self._rows_written: int = 0
        self._file_index  : int = 0
        self._csv_path    : Optional[Path] = None
        self._csv_file    = None
        self._csv_writer  = None

        self._running     : bool = False
        self._thread      : Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the logger consumer thread."""
        self._running = True
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._open_csv()
        self._thread = threading.Thread(
            target = self._consume_loop,
            daemon = True,
            name   = "capture-logger",
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the logger to stop after draining the queue."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)
        self._close_csv()

    @property
    def csv_path(self) -> Optional[Path]:
        return self._csv_path

    @property
    def rows_written(self) -> int:
        return self._rows_written

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _consume_loop(self) -> None:
        """Main loop: drain queue and write rows."""
        while self._running or not self._queue.empty():
            try:
                flow: Flow = self._queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                features = extract_features(flow)
            except Exception as exc:
                sys.stderr.write(f"[LOGGER] Feature extraction error: {exc}\n")
                continue

            self._write_row(features)

            # Optional real-time ML callback (Phase 3 hook)
            if self._on_flow:
                try:
                    self._on_flow(features)
                except Exception:
                    pass

            if self._verbose:
                self._print_flow_summary(features)

            self._queue.task_done()

    def _write_row(self, features: dict) -> None:
        """Write one feature row to the current CSV file."""
        if self._rows_written > 0 and self._rows_written % MAX_CSV_ROWS == 0:
            self._rotate_csv()

        if self._csv_writer is None:
            self._open_csv()

        self._csv_writer.writerow(
            {col: features.get(col, "") for col in FEATURE_COLUMNS}
        )
        self._csv_file.flush()
        self._rows_written += 1

    def _open_csv(self) -> None:
        """Open a new CSV file for writing."""
        suffix = f"_{self._file_index}" if self._file_index > 0 else ""
        fname  = f"{self._session}{suffix}.csv"
        self._csv_path = self._output_dir / fname

        is_new = not self._csv_path.exists()
        self._csv_file   = open(self._csv_path, "a", newline="", encoding="utf-8")
        self._csv_writer = csv.DictWriter(
            self._csv_file, fieldnames=FEATURE_COLUMNS
        )
        if is_new:
            self._csv_writer.writeheader()

    def _close_csv(self) -> None:
        if self._csv_file and not self._csv_file.closed:
            self._csv_file.flush()
            self._csv_file.close()

    def _rotate_csv(self) -> None:
        self._close_csv()
        self._file_index += 1
        self._open_csv()

    def _print_flow_summary(self, f: dict) -> None:
        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(f.get("protocol", 0), "???")
        dur_ms = int(f.get("Flow Duration", 0) / 1000)
        print(
            f"  [FLOW] {f.get('src_ip','?')}:{f.get('src_port','?')} -> "
            f"{f.get('dst_ip','?')}:{f.get('dst_port','?')} "
            f"| {proto_name} | {dur_ms} ms "
            f"| pkts: {int(f.get('Total Fwd Packets',0))}"
            f"+{int(f.get('Total Backward Packets',0))} "
            f"| label: {f.get('Label','?')}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_session_name() -> str:
    return "capture_" + datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

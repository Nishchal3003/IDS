"""
dashboard_bridge.py  -  Phase 5 inter-process state bridge.
Ported and completed from BSaiCharan-GH/XAI-NIDS dashboard/dashboard_bridge.py.
The XAI-NIDS source was truncated at the migration loop; full implementation here.

Architecture:
  CaptureLogger (capture thread)
      -> bridge.update(result_dict)
  Streamlit dashboard (main thread / separate process)
      -> bridge.get_snapshot()
      -> bridge.get_history(n)
"""

import json
import os
import sqlite3
import threading
import time
from collections import deque

BASE_DIR          = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH   = os.path.join(BASE_DIR, "ids_events.db")
DEFAULT_STATE_PATH = os.path.join(BASE_DIR, "live_state.json")


class DashboardBridge:
    """
    Inter-process state bridge using in-memory deque + SQLite history.
    Thread-safe: all public methods acquire self._lock.
    """

    def __init__(
        self,
        max_live_history = 100,
        db_path          = DEFAULT_DB_PATH,
        state_path       = DEFAULT_STATE_PATH,
    ):
        self._lock         = threading.Lock()
        self._max_history  = max_live_history
        self._db_path      = db_path
        self._state_path   = state_path
        self._recent_flows = deque(maxlen=max_live_history)
        self._alerts       = deque(maxlen=max_live_history)
        self._counters     = {
            "total_packets"  : 0,
            "active_flows"   : 0,
            "port_scan_count": 0,
            "dos_count"      : 0,
        }
        self._init_db()

    # ------------------------------------------------------------------ DB

    def _init_db(self):
        with sqlite3.connect(self._db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS detections (
                    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp            TEXT,
                    src_ip               TEXT,
                    src_port             INTEGER,
                    dst_ip               TEXT,
                    dst_port             INTEGER,
                    protocol             INTEGER,
                    ml_prediction        TEXT,
                    behavioural_detection TEXT,
                    final_decision       TEXT,
                    detection_reason     TEXT,
                    confidence           REAL,
                    top_shap_features    TEXT
                )
            """)
            # Schema migration: add any missing columns gracefully
            existing = {
                row[1]
                for row in conn.execute("PRAGMA table_info(detections)").fetchall()
            }
            migrations = {
                "ml_prediction"        : "TEXT",
                "behavioural_detection": "TEXT",
                "final_decision"       : "TEXT",
                "detection_reason"     : "TEXT",
                "top_shap_features"    : "TEXT",
            }
            for col, col_type in migrations.items():
                if col not in existing:
                    conn.execute(
                        "ALTER TABLE detections ADD COLUMN {} {}".format(col, col_type)
                    )

    def _persist_event(self, result):
        """Write an attack event to SQLite (non-blocking from capture thread)."""
        try:
            ts = result.get("timestamp", time.time())
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            with sqlite3.connect(self._db_path) as conn:
                conn.execute(
                    """
                    INSERT INTO detections
                        (timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                         ml_prediction, behavioural_detection, final_decision,
                         detection_reason, confidence, top_shap_features)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        ts_str,
                        result.get("src_ip", ""),
                        result.get("src_port", 0),
                        result.get("dst_ip", ""),
                        result.get("dst_port", 0),
                        result.get("protocol", 0),
                        result.get("ml_prediction", ""),
                        result.get("behavioural_detection", ""),
                        result.get("final_decision", ""),
                        result.get("detection_reason", ""),
                        result.get("confidence", 0.0),
                        json.dumps(result.get("top_shap_features", {})),
                    ),
                )
        except Exception:
            pass  # never let DB error crash the capture thread

    # ------------------------------------------------------------------ Public API

    def update(self, result: dict, packet_count: int = 1, active_flows: int = 0):
        """
        Called by the LiveInferenceEngine callback for every completed flow.

        Parameters
        ----------
        result       : dict from LiveInferenceEngine.process_flow()
        packet_count : increment for total packet counter
        active_flows : current active flow count from FlowTracker
        """
        with self._lock:
            ts = result.get("timestamp", time.time())
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            result["timestamp"] = ts_str

            self._recent_flows.append(result)
            self._counters["total_packets"] += packet_count
            self._counters["active_flows"]   = active_flows

            final = result.get("final_decision", "")
            if result.get("is_attack"):
                self._alerts.appendleft(result)
                if final == "PortScan":
                    self._counters["port_scan_count"] += 1
                elif final in ("DoS", "DDoS", "DoS_SYNFlood"):
                    self._counters["dos_count"] += 1

        # Persist attacks to SQLite (outside lock to minimise hold time)
        if result.get("is_attack"):
            self._persist_event(result)

    def get_snapshot(self) -> dict:
        """
        Return the current live state snapshot consumed by the Streamlit dashboard.
        """
        with self._lock:
            return {
                "recent_flows"   : list(self._recent_flows),
                "alerts"         : list(self._alerts),
                "total_packets"  : self._counters["total_packets"],
                "active_flows"   : self._counters["active_flows"],
                "port_scan_count": self._counters["port_scan_count"],
                "dos_count"      : self._counters["dos_count"],
            }

    def get_history(self, limit: int = 500) -> list:
        """Return historical detections from SQLite."""
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM detections ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception:
            return []

    def reset_counters(self):
        """Reset live counters (called at dashboard start or on user request)."""
        with self._lock:
            self._counters = {
                "total_packets"  : 0,
                "active_flows"   : 0,
                "port_scan_count": 0,
                "dos_count"      : 0,
            }
            self._recent_flows.clear()
            self._alerts.clear()


# ---------------------------------------------------------------------------
# Module-level singleton  (used by both capture thread and Streamlit)
# ---------------------------------------------------------------------------

bridge_instance = DashboardBridge()

"""
dashboard_bridge.py  -  Phase 5 inter-process state bridge.
Ported and completed from BSaiCharan-GH/XAI-NIDS dashboard/dashboard_bridge.py.

Design: fully in-memory (deque + thread lock) for live state.
SQLite used only for persistent historical records.
No temp-file writes: eliminates Windows file-lock races.

Capture thread  ->  bridge.update(result)
Streamlit thread -> bridge.get_snapshot() / bridge.get_history()
"""

import json
import os
import sqlite3
import threading
import time
from collections import deque

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "ids_events.db")


class DashboardBridge:
    """
    Thread-safe bridge between the inference/capture pipeline and Streamlit.
    All live state is in-memory; only attack events are persisted to SQLite.
    """

    def __init__(self, max_live_history=100, db_path=DEFAULT_DB_PATH):
        self._lock          = threading.Lock()
        self._max_history   = max_live_history
        self._db_path       = db_path
        self._recent_flows  = deque(maxlen=max_live_history)
        self._alerts        = deque(maxlen=max_live_history)
        self._counters      = {
            "total_packets"  : 0,
            "active_flows"   : 0,
            "port_scan_count": 0,
            "dos_count"      : 0,
        }
        if db_path != ":memory:":
            self._init_db()

    # ------------------------------------------------------------------ DB

    def _init_db(self):
        """Create detections table if missing, apply schema migrations."""
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS detections (
                        id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp             TEXT,
                        src_ip                TEXT,
                        src_port              INTEGER,
                        dst_ip                TEXT,
                        dst_port              INTEGER,
                        protocol              INTEGER,
                        ml_prediction         TEXT,
                        behavioural_detection TEXT,
                        final_decision        TEXT,
                        detection_reason      TEXT,
                        confidence            REAL,
                        top_shap_features     TEXT
                    )
                """)
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
        except Exception as exc:
            print("[DashboardBridge] DB init error: {}".format(exc))

    def _persist_event(self, result):
        """Store an attack event in SQLite (called outside the main lock)."""
        if self._db_path == ":memory:":
            return   # skip for in-process test instances
        try:
            ts     = result.get("timestamp", time.time())
            ts_str = str(ts) if isinstance(ts, str) else time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(float(ts))
            )
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
                        int(result.get("src_port") or 0),
                        result.get("dst_ip", ""),
                        int(result.get("dst_port") or 0),
                        int(result.get("protocol") or 0),
                        result.get("ml_prediction", ""),
                        result.get("behavioural_detection") or "",
                        result.get("final_decision", ""),
                        result.get("detection_reason", ""),
                        float(result.get("confidence") or 0.0),
                        json.dumps(result.get("top_shap_features", {})),
                    ),
                )
        except Exception as exc:
            print("[DashboardBridge] SQLite persist error: {}".format(exc))

    # ------------------------------------------------------------------ Public API

    def update(self, result: dict, packet_count: int = 1, active_flows: int = 0):
        """
        Called by LiveInferenceEngine for every completed flow.
        Updates in-memory state atomically; persists attacks to SQLite.
        """
        is_attack = result.get("is_attack", False)
        final     = result.get("final_decision", "")

        with self._lock:
            # Normalise timestamp to string for display
            ts = result.get("timestamp", time.time())
            if isinstance(ts, (int, float)):
                result = dict(result)   # don't mutate caller's dict
                result["timestamp"] = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(ts)
                )

            self._recent_flows.append(result)
            self._counters["total_packets"] += packet_count
            self._counters["active_flows"]   = active_flows

            if is_attack:
                self._alerts.appendleft(result)
                if final == "PortScan":
                    self._counters["port_scan_count"] += 1
                elif final in ("DoS", "DDoS", "DoS_SYNFlood"):
                    self._counters["dos_count"] += 1

        # Persist outside lock to minimise hold time
        if is_attack:
            self._persist_event(result)

    def get_snapshot(self) -> dict:
        """Return the current live state (in-memory, thread-safe)."""
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
        """Return historical attack detections from SQLite."""
        if self._db_path == ":memory:":
            return []
        try:
            with sqlite3.connect(self._db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM detections ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [dict(row) for row in rows]
        except Exception as exc:
            print("[DashboardBridge] History error: {}".format(exc))
            return []

    def reset_counters(self):
        """Reset live counters and alert list without deleting historical records."""
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
# Module-level singleton  (used by capture thread and Streamlit in same process)
# ---------------------------------------------------------------------------

bridge_instance = DashboardBridge()

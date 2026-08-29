"""
dashboard_bridge.py  -  Phase 5 cross-process state bridge.

ARCHITECTURE
  Process A (capture / mock):
      bridge.update(result)
        -> in-memory deque  (fast path, same-process access)
        -> SQLite tables     (shared with every other process)

  Process B (Streamlit dashboard):
      bridge.get_snapshot()  reads from SQLite -> always current
      bridge.get_history()   reads from SQLite detections table

SQLite tables
  recent_flows   : rolling last N flows (all traffic)
  live_counters  : single-row total packet/scan/dos counters
  detections     : append-only attack event log
"""

import json
import os
import sqlite3
import threading
import time
from collections import deque

BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "ids_events.db")
_SQLITE_TIMEOUT = 10.0   # seconds to wait for write lock


class DashboardBridge:
    """
    Thread-safe bridge between the inference/capture pipeline and Streamlit.

    In-memory state gives zero-overhead updates for the capture thread.
    SQLite gives cross-process visibility to the dashboard.
    """

    def __init__(self, max_live_history: int = 100, db_path: str = DEFAULT_DB_PATH):
        self._lock          = threading.Lock()
        self._max_history   = max_live_history
        self._db_path       = db_path
        self._in_memory     = db_path == ":memory:"   # unit-test mode

        # In-memory state (fast path for same-process tests / same-process use)
        self._recent_flows  = deque(maxlen=max_live_history)
        self._alerts        = deque(maxlen=max_live_history)
        self._counters      = {
            "total_packets"  : 0,
            "active_flows"   : 0,
            "port_scan_count": 0,
            "dos_count"      : 0,
        }

        if not self._in_memory:
            self._init_db()

    # ------------------------------------------------------------------ DB setup

    def _connect(self):
        return sqlite3.connect(self._db_path, timeout=_SQLITE_TIMEOUT, check_same_thread=False)

    def _init_db(self):
        """Create all required tables and apply schema migrations."""
        try:
            with self._connect() as conn:
                conn.execute("PRAGMA journal_mode=WAL")   # allow concurrent readers
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS live_counters (
                        id               INTEGER PRIMARY KEY CHECK (id = 1),
                        total_packets    INTEGER DEFAULT 0,
                        active_flows     INTEGER DEFAULT 0,
                        port_scan_count  INTEGER DEFAULT 0,
                        dos_count        INTEGER DEFAULT 0,
                        updated_at       TEXT
                    )
                """)
                conn.execute("""
                    INSERT OR IGNORE INTO live_counters (id, total_packets, active_flows,
                        port_scan_count, dos_count, updated_at)
                    VALUES (1, 0, 0, 0, 0, datetime('now'))
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS recent_flows (
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
                        is_attack             INTEGER DEFAULT 0
                    )
                """)
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
                # Schema migrations for older DB files
                existing_rf = {r[1] for r in conn.execute("PRAGMA table_info(recent_flows)")}
                rf_migrations = {
                    "behavioural_detection": "TEXT",
                    "detection_reason"     : "TEXT",
                    "is_attack"            : "INTEGER DEFAULT 0",
                }
                for col, col_type in rf_migrations.items():
                    if col not in existing_rf:
                        conn.execute("ALTER TABLE recent_flows ADD COLUMN {} {}".format(col, col_type))

                existing_det = {r[1] for r in conn.execute("PRAGMA table_info(detections)")}
                det_migrations = {
                    "ml_prediction"        : "TEXT",
                    "behavioural_detection": "TEXT",
                    "final_decision"       : "TEXT",
                    "detection_reason"     : "TEXT",
                    "top_shap_features"    : "TEXT",
                }
                for col, col_type in det_migrations.items():
                    if col not in existing_det:
                        conn.execute("ALTER TABLE detections ADD COLUMN {} {}".format(col, col_type))
        except Exception as exc:
            print("[DashboardBridge] DB init error: {}".format(exc))

    # ------------------------------------------------------------------ Internal writers

    def _ts_string(self, ts):
        if isinstance(ts, str):
            return ts
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))
        except Exception:
            return time.strftime("%Y-%m-%d %H:%M:%S")

    def _write_flow_to_db(self, result: dict) -> None:
        """Persist one flow row to recent_flows + trim to max_live_history."""
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO recent_flows
                        (timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                         ml_prediction, behavioural_detection, final_decision,
                         detection_reason, confidence, is_attack)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        result.get("timestamp", ""),
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
                        1 if result.get("is_attack") else 0,
                    ),
                )
                # Keep only the most recent max_live_history rows
                conn.execute(
                    """
                    DELETE FROM recent_flows WHERE id NOT IN (
                        SELECT id FROM recent_flows ORDER BY id DESC LIMIT ?
                    )
                    """,
                    (self._max_history,),
                )
        except Exception as exc:
            print("[DashboardBridge] Flow write error: {}".format(exc))

    def _update_counters_in_db(self, counters: dict) -> None:
        """Overwrite the single live_counters row."""
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    UPDATE live_counters SET
                        total_packets   = ?,
                        active_flows    = ?,
                        port_scan_count = ?,
                        dos_count       = ?,
                        updated_at      = datetime('now')
                    WHERE id = 1
                    """,
                    (
                        counters["total_packets"],
                        counters["active_flows"],
                        counters["port_scan_count"],
                        counters["dos_count"],
                    ),
                )
        except Exception as exc:
            print("[DashboardBridge] Counter write error: {}".format(exc))

    def _persist_event(self, result: dict) -> None:
        """Append an attack event to the detections log table."""
        try:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO detections
                        (timestamp, src_ip, src_port, dst_ip, dst_port, protocol,
                         ml_prediction, behavioural_detection, final_decision,
                         detection_reason, confidence, top_shap_features)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        result.get("timestamp", ""),
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
            print("[DashboardBridge] Event persist error: {}".format(exc))

    # ------------------------------------------------------------------ Internal readers

    def _build_in_memory_snapshot(self) -> dict:
        """Return current in-memory state (call with self._lock held)."""
        return {
            "recent_flows"   : list(self._recent_flows),
            "alerts"         : list(self._alerts),
            "total_packets"  : self._counters["total_packets"],
            "active_flows"   : self._counters["active_flows"],
            "port_scan_count": self._counters["port_scan_count"],
            "dos_count"      : self._counters["dos_count"],
        }

    def _read_snapshot_from_db(self) -> dict:
        """Read live state from SQLite (works across processes)."""
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row

                # Counters
                row = conn.execute("SELECT * FROM live_counters WHERE id=1").fetchone()
                c = dict(row) if row else {}

                # Recent flows (oldest first for table display)
                rows = conn.execute(
                    "SELECT * FROM recent_flows ORDER BY id DESC LIMIT ?",
                    (self._max_history,),
                ).fetchall()
                recent = [dict(r) for r in reversed(rows)]

                # Alerts = recent attack flows, newest first
                alerts = [f for f in reversed(recent) if f.get("is_attack")]

                return {
                    "recent_flows"   : recent,
                    "alerts"         : alerts,
                    "total_packets"  : c.get("total_packets", 0),
                    "active_flows"   : c.get("active_flows", 0),
                    "port_scan_count": c.get("port_scan_count", 0),
                    "dos_count"      : c.get("dos_count", 0),
                }
        except Exception as exc:
            print("[DashboardBridge] Snapshot read error: {}".format(exc))
            with self._lock:
                return self._build_in_memory_snapshot()

    # ------------------------------------------------------------------ Public API

    def update(self, result: dict, packet_count: int = 1, active_flows: int = 0) -> None:
        """
        Process one completed flow.
        - Updates in-memory state (fast, same-process access)
        - Writes to SQLite (cross-process dashboard visibility)
        """
        is_attack = result.get("is_attack", False)
        final     = result.get("final_decision", "")

        with self._lock:
            ts = result.get("timestamp", time.time())
            if isinstance(ts, (int, float)):
                result = dict(result)
                result["timestamp"] = self._ts_string(ts)

            self._recent_flows.append(result)
            self._counters["total_packets"] += packet_count
            self._counters["active_flows"]   = active_flows

            if is_attack:
                self._alerts.appendleft(result)
                if final == "PortScan":
                    self._counters["port_scan_count"] += 1
                elif final in ("DoS", "DDoS", "DoS_SYNFlood"):
                    self._counters["dos_count"] += 1

            counters_snapshot = dict(self._counters)

        # Write to SQLite outside the lock (non-blocking for capture thread)
        if not self._in_memory:
            self._write_flow_to_db(result)
            self._update_counters_in_db(counters_snapshot)
            if is_attack:
                self._persist_event(result)

    def get_snapshot(self) -> dict:
        """
        Return current live state.
        Reads from SQLite when available (cross-process), memory otherwise.
        """
        if self._in_memory:
            with self._lock:
                return self._build_in_memory_snapshot()
        return self._read_snapshot_from_db()

    def get_history(self, limit: int = 500) -> list:
        """Return historical attack events from the detections log."""
        if self._in_memory:
            return []
        try:
            with self._connect() as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT * FROM detections ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [dict(r) for r in rows]
        except Exception as exc:
            print("[DashboardBridge] History error: {}".format(exc))
            return []

    def reset_counters(self) -> None:
        """Reset live state counters and recent flows (keeps historical detections)."""
        with self._lock:
            self._counters = {
                "total_packets"  : 0,
                "active_flows"   : 0,
                "port_scan_count": 0,
                "dos_count"      : 0,
            }
            self._recent_flows.clear()
            self._alerts.clear()

        if not self._in_memory:
            try:
                with self._connect() as conn:
                    conn.execute("DELETE FROM recent_flows")
                    conn.execute(
                        """UPDATE live_counters SET total_packets=0, active_flows=0,
                           port_scan_count=0, dos_count=0, updated_at=datetime('now')
                           WHERE id=1"""
                    )
            except Exception as exc:
                print("[DashboardBridge] Reset error: {}".format(exc))


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

bridge_instance = DashboardBridge()

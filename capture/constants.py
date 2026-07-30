"""
constants.py  (capture module)
-------------------------------
All configuration constants and the canonical CIC-IDS 2017 feature column
names for the Phase-2 packet-capture / feature-extraction pipeline.

Design note
-----------
Column names are kept identical to the CIC-IDS 2017 CSV headers so that
a model trained on the public dataset can be loaded and used directly in
Phase 3 without any renaming / mapping step.
"""

# ---------------------------------------------------------------------------
# Flow lifecycle
# ---------------------------------------------------------------------------
FLOW_TIMEOUT: float     = 120.0   # seconds → idle flow is expired + flushed
ACTIVITY_TIMEOUT: float =   5.0   # seconds → gap that splits active / idle periods
TCP_FIN_TIMEOUT: float  =   5.0   # seconds → extra wait after FIN/RST before flush

# ---------------------------------------------------------------------------
# Capture defaults  (can be overridden via CLI or config/network_config.py)
# ---------------------------------------------------------------------------
DEFAULT_FILTER: str       = "ip"          # BPF filter applied to Scapy sniff
MAX_FLOWS: int            = 100_000       # evict oldest if tracker grows too large
BULK_BOUND: int           = 0             # minimum payload bytes to count as bulk
ACTIVE_IDLE_THRESH: float = ACTIVITY_TIMEOUT

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
CAPTURE_CSV_DIR: str      = "datasets/captures"
MAX_CSV_ROWS: int         = 500_000       # rotate CSV file after this many rows

# ---------------------------------------------------------------------------
# Protocol numbers
# ---------------------------------------------------------------------------
PROTO_TCP:  int = 6
PROTO_UDP:  int = 17
PROTO_ICMP: int = 1

# ---------------------------------------------------------------------------
# TCP flag bitmasks
# ---------------------------------------------------------------------------
TCP_FIN: int = 0x01
TCP_SYN: int = 0x02
TCP_RST: int = 0x04
TCP_PSH: int = 0x08
TCP_ACK: int = 0x10
TCP_URG: int = 0x20
TCP_ECE: int = 0x40
TCP_CWR: int = 0x80

# ---------------------------------------------------------------------------
# CIC-IDS 2017 feature column names  (exact match for dataset compatibility)
# ---------------------------------------------------------------------------
FEATURE_COLUMNS: list[str] = [
    # ── Identity (kept in output; dropped before ML inference) ──────────
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "flow_id",

    # ── Duration ─────────────────────────────────────────────────────────
    "Flow Duration",

    # ── Packet counts ────────────────────────────────────────────────────
    "Total Fwd Packets",
    "Total Backward Packets",

    # ── Byte lengths ─────────────────────────────────────────────────────
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",

    # ── Rates ────────────────────────────────────────────────────────────
    "Flow Bytes/s",
    "Flow Packets/s",

    # ── Inter-arrival times ──────────────────────────────────────────────
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",

    # ── TCP flags (directional) ──────────────────────────────────────────
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",

    # ── Header lengths ───────────────────────────────────────────────────
    "Fwd Header Length",
    "Bwd Header Length",

    # ── Packet rates ─────────────────────────────────────────────────────
    "Fwd Packets/s",
    "Bwd Packets/s",

    # ── Overall packet length stats ──────────────────────────────────────
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",

    # ── TCP flag totals ──────────────────────────────────────────────────
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",

    # ── Ratios and averages ──────────────────────────────────────────────
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",           # duplicate of Fwd Header Length (dataset artefact)

    # ── Bulk transfer stats ──────────────────────────────────────────────
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",

    # ── Subflow stats ────────────────────────────────────────────────────
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",

    # ── TCP window / segment ─────────────────────────────────────────────
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",

    # ── Active / Idle periods ────────────────────────────────────────────
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",

    # ── Label (Phase 3 fills this; BENIGN by default at capture time) ────
    "Label",

    # ── Capture timestamp (for audit trail) ──────────────────────────────
    "capture_ts",
]

# Columns that are purely numeric (for ML — identity + label columns excluded)
ML_FEATURE_COLUMNS: list[str] = FEATURE_COLUMNS[6:-2]   # skip identity, label, ts

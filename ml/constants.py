"""Constants for the Phase 3 ML pipeline."""

from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────
PROJECT_ROOT    = Path(__file__).resolve().parent.parent
DATASET_DIR     = PROJECT_ROOT / "datasets" / "cicids2017"
MODELS_DIR      = PROJECT_ROOT / "ml" / "models"
REPORTS_DIR     = PROJECT_ROOT / "ml" / "reports"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

BEST_MODEL_PATH = MODELS_DIR / "best_model.pkl"
SCALER_PATH     = MODELS_DIR / "scaler.pkl"
LABEL_MAP_PATH  = MODELS_DIR / "label_map.pkl"

# ── Dataset files ──────────────────────────────────────────────────────────
DATASET_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv",
    "Tuesday-WorkingHours.pcap_ISCX.csv",
    "Wednesday-workingHours.pcap_ISCX.csv",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
]

# ── Label mapping: CIC-IDS 2017 fine-grained → coarse attack class ─────────
# Maps every label in the dataset to one of 9 coarse classes (int ID).
LABEL_TO_CLASS: dict[str, str] = {
    "BENIGN"                          : "BENIGN",
    # DoS
    "DoS Hulk"                        : "DoS",
    "DoS GoldenEye"                   : "DoS",
    "DoS slowloris"                   : "DoS",
    "DoS Slowhttptest"                : "DoS",
    # DDoS
    "DDoS"                            : "DDoS",
    # Port Scan
    "PortScan"                        : "PortScan",
    # Brute Force
    "FTP-Patator"                     : "BruteForce",
    "SSH-Patator"                     : "BruteForce",
    # Web Attacks
    "Web Attack \x96 Brute Force"     : "WebAttack",
    "Web Attack \x96 XSS"             : "WebAttack",
    "Web Attack \x96 Sql Injection"   : "WebAttack",
    "Web Attack – Brute Force"        : "WebAttack",
    "Web Attack – XSS"                : "WebAttack",
    "Web Attack – Sql Injection"      : "WebAttack",
    # Botnet
    "Bot"                             : "Botnet",
    # Infiltration
    "Infiltration"                    : "Infiltration",
    # Heartbleed
    "Heartbleed"                      : "Heartbleed",
}

# Ordered class list (index = integer label)
CLASSES: list[str] = [
    "BENIGN",
    "DoS",
    "DDoS",
    "PortScan",
    "BruteForce",
    "WebAttack",
    "Botnet",
    "Infiltration",
    "Heartbleed",
]

CLASS_TO_ID: dict[str, int] = {c: i for i, c in enumerate(CLASSES)}
ID_TO_CLASS: dict[int, str] = {i: c for i, c in enumerate(CLASSES)}

# ── Feature columns (72 numeric features — CIC-IDS 2017 header names) ──────
# These exactly match the dataset column headers (after stripping whitespace).
FEATURE_COLS: list[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
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
    "Flow Bytes/s",
    "Flow Packets/s",
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
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

LABEL_COL = "Label"

# ── Training configuration ──────────────────────────────────────────────────
TEST_SIZE        = 0.20      # 80/20 train-test split
RANDOM_STATE     = 42
# Sampling: load at most this many rows per file to keep RAM manageable.
# Set to None to load everything (~2.8M rows → needs 8+ GB RAM).
ROWS_PER_FILE    = 200_000

# ── RF / XGBoost hyperparameters ───────────────────────────────────────────
RF_N_ESTIMATORS  = 100
XGB_N_ESTIMATORS = 200
XGB_MAX_DEPTH    = 8
MLP_HIDDEN       = (256, 128, 64)
MLP_MAX_ITER     = 200

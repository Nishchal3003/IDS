"""
ml/predict.py
-------------
Load the saved best model and scaler, then classify individual network flows.

Designed for Phase 4 real-time integration: capture/capture_daemon.py will
call classify_flow(flow_dict) for each completed flow.

Usage (standalone):
    from ml.predict import classify_flow
    result = classify_flow({"Flow Duration": 1000, "Total Fwd Packets": 5, ...})
    # → {"label": "DoS", "confidence": 0.94, "is_attack": True, "class_id": 1}
"""

import pickle
import warnings
from functools import lru_cache
from typing import Optional

import numpy as np

warnings.filterwarnings("ignore")

from ml.constants import (
    BEST_MODEL_PATH, CLASSES, FEATURE_COLS, ID_TO_CLASS,
    SCALER_PATH, LABEL_ENCODER_PATH,
)


# ── Cached model loader (loads once at first call) ─────────────────────────

@lru_cache(maxsize=1)
def _load_artifacts() -> tuple:
    """
    Load model + scaler + label_encoder from disk. Cached after first call.

    Returns
    -------
    (model, scaler, label_encoder, class_names)
    """
    if not BEST_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"No trained model at {BEST_MODEL_PATH}. Run: python main.py train"
        )
    if not SCALER_PATH.exists():
        raise FileNotFoundError(
            f"No scaler at {SCALER_PATH}. Run: python main.py train"
        )
    if not LABEL_ENCODER_PATH.exists():
        raise FileNotFoundError(
            f"No label encoder at {LABEL_ENCODER_PATH}. Run: python main.py train"
        )

    with open(BEST_MODEL_PATH, "rb") as fh:
        artifact = pickle.load(fh)
    with open(SCALER_PATH, "rb") as fh:
        scaler = pickle.load(fh)
    with open(LABEL_ENCODER_PATH, "rb") as fh:
        le = pickle.load(fh)

    model       = artifact["model"]
    class_names = artifact.get("classes", CLASSES)
    return model, scaler, le, class_names


def model_is_ready() -> bool:
    """Return True if a trained model exists on disk."""
    return BEST_MODEL_PATH.exists() and SCALER_PATH.exists()


def classify_flow(flow: dict) -> dict:
    """
    Classify a single network flow.

    The model was trained on LabelEncoder-encoded y (0..K-1 where K = number
    of classes present in the training sample). We use le.classes_ to map the
    encoded prediction back to the original class ID, then to a class name.
    """
    model, scaler, le, class_names = _load_artifacts()

    row = np.array(
        [float(flow.get(col, 0) or 0) for col in FEATURE_COLS],
        dtype=np.float64,
    )
    row = np.nan_to_num(row, nan=0.0, posinf=0.0, neginf=0.0)
    row_scaled = scaler.transform(row.reshape(1, -1))

    encoded_id  = int(model.predict(row_scaled)[0])          # 0..K-1
    original_id = int(le.classes_[encoded_id])               # back to CLASSES index
    label       = ID_TO_CLASS.get(original_id, "UNKNOWN")
    is_attack   = label != "BENIGN"

    confidence  = 1.0
    proba_dict: dict[str, float] = {}
    if hasattr(model, "predict_proba"):
        proba      = model.predict_proba(row_scaled)[0]
        confidence = float(proba[encoded_id])
        # Map encoded indices back to class names via le.classes_
        proba_dict = {
            ID_TO_CLASS.get(int(le.classes_[i]), str(i)): round(float(p), 4)
            for i, p in enumerate(proba)
        }

    return {
        "label"        : label,
        "class_id"     : original_id,
        "confidence"   : round(confidence, 4),
        "is_attack"    : is_attack,
        "probabilities": proba_dict,
    }


def classify_batch(flows: list[dict]) -> list[dict]:
    """Classify a list of flows efficiently using batch prediction."""
    if not flows:
        return []

    model, scaler, le, class_names = _load_artifacts()

    matrix = np.array(
        [[float(f.get(col, 0) or 0) for col in FEATURE_COLS] for f in flows],
        dtype=np.float64,
    )
    matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)
    matrix_scaled = scaler.transform(matrix)

    encoded_ids = model.predict(matrix_scaled)
    probas      = model.predict_proba(matrix_scaled) if hasattr(model, "predict_proba") else None

    results = []
    for i, enc_id in enumerate(encoded_ids):
        enc_id      = int(enc_id)
        original_id = int(le.classes_[enc_id])
        label       = ID_TO_CLASS.get(original_id, "UNKNOWN")
        conf        = float(probas[i][enc_id]) if probas is not None else 1.0
        proba_dict  = {}
        if probas is not None:
            proba_dict = {
                ID_TO_CLASS.get(int(le.classes_[j]), str(j)): round(float(probas[i][j]), 4)
                for j in range(probas.shape[1])
            }
        results.append({
            "label"        : label,
            "class_id"     : original_id,
            "confidence"   : round(conf, 4),
            "is_attack"    : label != "BENIGN",
            "probabilities": proba_dict,
        })
    return results


if __name__ == "__main__":
    # Quick smoke test with a synthetic benign-like flow
    test_flow = {col: 0.0 for col in FEATURE_COLS}
    test_flow.update({
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "Flow Duration": 50000,
        "Flow Bytes/s": 1200.0,
    })
    print("Classifying test flow...")
    result = classify_flow(test_flow)
    print(f"  Label      : {result['label']}")
    print(f"  Confidence : {result['confidence']:.4f}")
    print(f"  Is attack  : {result['is_attack']}")

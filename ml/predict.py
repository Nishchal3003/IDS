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
    SCALER_PATH,
)


# ── Cached model loader (loads once at first call) ─────────────────────────

@lru_cache(maxsize=1)
def _load_artifacts() -> tuple:
    """
    Load model + scaler from disk. Cached after first call.

    Returns
    -------
    (model, scaler, class_names)
    """
    if not BEST_MODEL_PATH.exists():
        raise FileNotFoundError(
            f"No trained model found at {BEST_MODEL_PATH}. "
            "Run: python main.py train"
        )
    if not SCALER_PATH.exists():
        raise FileNotFoundError(
            f"No scaler found at {SCALER_PATH}. "
            "Run: python main.py train"
        )

    with open(BEST_MODEL_PATH, "rb") as fh:
        artifact = pickle.load(fh)
    with open(SCALER_PATH, "rb") as fh:
        scaler = pickle.load(fh)

    model       = artifact["model"]
    class_names = artifact.get("classes", CLASSES)
    return model, scaler, class_names


def model_is_ready() -> bool:
    """Return True if a trained model exists on disk."""
    return BEST_MODEL_PATH.exists() and SCALER_PATH.exists()


def classify_flow(flow: dict) -> dict:
    """
    Classify a single network flow.

    Parameters
    ----------
    flow : dict
        Keys must match FEATURE_COLS (CIC-IDS 2017 column names).
        Missing keys are filled with 0.

    Returns
    -------
    dict with keys:
        label      : str  — coarse attack class name (e.g. "DoS", "BENIGN")
        class_id   : int  — integer class index
        confidence : float — probability of the predicted class (0–1)
        is_attack  : bool — True for any non-BENIGN label
        probabilities : dict[str, float] — per-class probabilities
    """
    model, scaler, class_names = _load_artifacts()

    # Build feature vector in the correct column order
    row = np.array(
        [float(flow.get(col, 0) or 0) for col in FEATURE_COLS],
        dtype=np.float64,
    )
    row = np.nan_to_num(row, nan=0.0, posinf=0.0, neginf=0.0)
    row_scaled = scaler.transform(row.reshape(1, -1))

    # Predict
    class_id   = int(model.predict(row_scaled)[0])
    label      = ID_TO_CLASS.get(class_id, "UNKNOWN")
    is_attack  = label != "BENIGN"

    # Confidence (probability if model supports it)
    confidence = 1.0
    proba_dict: dict[str, float] = {}
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(row_scaled)[0]
        confidence = float(proba[class_id])
        proba_dict = {
            class_names[i]: round(float(p), 4)
            for i, p in enumerate(proba)
            if i < len(class_names)
        }

    return {
        "label"        : label,
        "class_id"     : class_id,
        "confidence"   : round(confidence, 4),
        "is_attack"    : is_attack,
        "probabilities": proba_dict,
    }


def classify_batch(flows: list[dict]) -> list[dict]:
    """
    Classify a list of flows efficiently using batch prediction.

    Parameters
    ----------
    flows : list of flow dicts (same format as classify_flow)

    Returns
    -------
    list of result dicts (same format as classify_flow)
    """
    if not flows:
        return []

    model, scaler, class_names = _load_artifacts()

    matrix = np.array(
        [[float(f.get(col, 0) or 0) for col in FEATURE_COLS] for f in flows],
        dtype=np.float64,
    )
    matrix = np.nan_to_num(matrix, nan=0.0, posinf=0.0, neginf=0.0)
    matrix_scaled = scaler.transform(matrix)

    ids   = model.predict(matrix_scaled)
    probas = model.predict_proba(matrix_scaled) if hasattr(model, "predict_proba") else None

    results = []
    for i, class_id in enumerate(ids):
        class_id = int(class_id)
        label     = ID_TO_CLASS.get(class_id, "UNKNOWN")
        conf      = float(probas[i][class_id]) if probas is not None else 1.0
        proba_dict = {}
        if probas is not None:
            proba_dict = {
                class_names[j]: round(float(probas[i][j]), 4)
                for j in range(min(len(class_names), probas.shape[1]))
            }
        results.append({
            "label"        : label,
            "class_id"     : class_id,
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

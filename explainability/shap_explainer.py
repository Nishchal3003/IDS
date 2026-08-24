"""
shap_explainer.py  -  Phase 6 SHAP explainability for NIDS predictions.

Adapted from BSaiCharan-GH/XAI-NIDS explainability/shap_explainer.py
(source was committed truncated; completed here).

Usage (standalone):
    python explainability/shap_explainer.py

Usage (from dashboard / live inference):
    from explainability.shap_explainer import explain_flow
    top_features = explain_flow(flow_dict)   # returns {feature: shap_value, ...}

Requires: pip install shap
"""

import pickle
import sys
from pathlib import Path

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from ml.constants import (
    BEST_MODEL_PATH,
    FEATURE_COLS,
    ID_TO_CLASS,
    LABEL_ENCODER_PATH,
    SCALER_PATH,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_artifacts():
    """Load model + scaler + label_encoder once."""
    with open(BEST_MODEL_PATH, "rb") as fh:
        artifact = pickle.load(fh)
    with open(SCALER_PATH, "rb") as fh:
        scaler = pickle.load(fh)
    with open(LABEL_ENCODER_PATH, "rb") as fh:
        le = pickle.load(fh)
    return artifact["model"], scaler, le


def _shap_available():
    try:
        import shap  # noqa
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Core: explain a single flow
# ---------------------------------------------------------------------------

def explain_flow(flow: dict, top_n: int = 10) -> dict:
    """
    Compute SHAP values for one flow dict and return the top_n features.

    Parameters
    ----------
    flow  : dict  CIC-IDS 2017 feature keys (from feature_extractor)
    top_n : int   Number of top features to return

    Returns
    -------
    dict  {feature_name: shap_value}  sorted by |shap_value| descending
    """
    if not _shap_available():
        return {}

    if not BEST_MODEL_PATH.exists():
        return {}

    try:
        import shap
        model, scaler, le = _load_artifacts()

        # Build feature row
        row = np.array(
            [float(flow.get(col, 0) or 0) for col in FEATURE_COLS],
            dtype=np.float64,
        )
        row = np.nan_to_num(row, nan=0.0, posinf=0.0, neginf=0.0)
        row_scaled = scaler.transform(row.reshape(1, -1))

        # SHAP explainer: TreeExplainer for RF/XGBoost, KernelExplainer for others
        model_type = type(model).__name__
        if "Forest" in model_type or "XGB" in model_type or "Gradient" in model_type:
            explainer   = shap.TreeExplainer(model)
            shap_values = explainer.shap_values(row_scaled)
            # shap_values shape: [n_classes, n_samples, n_features] for multi-class RF
            pred_encoded = int(model.predict(row_scaled)[0])
            if isinstance(shap_values, list):
                values = shap_values[pred_encoded][0]
            else:
                values = shap_values[0, :, pred_encoded]
        else:
            # MLP or other: use KernelExplainer (slow, sample-based)
            def model_predict_proba(X):
                return model.predict_proba(X)
            explainer   = shap.KernelExplainer(model_predict_proba, row_scaled)
            shap_values = explainer.shap_values(row_scaled, nsamples=50)
            pred_encoded = int(model.predict(row_scaled)[0])
            if isinstance(shap_values, list):
                values = shap_values[pred_encoded][0]
            else:
                values = shap_values[0]

        # Build feature->value dict, sorted by |shap_value|
        result = dict(zip(FEATURE_COLS, values.tolist()))
        sorted_result = dict(
            sorted(result.items(), key=lambda x: abs(x[1]), reverse=True)[:top_n]
        )
        return sorted_result

    except Exception as exc:
        # Never crash the detection pipeline for explainability errors
        return {}


# ---------------------------------------------------------------------------
# explain_sample  (ported from XAI-NIDS — for batch / offline use)
# ---------------------------------------------------------------------------

def explain_sample(model, scaler, le, sample_df: pd.DataFrame, sample_index: int = 0):
    """
    Explain a single sample from a DataFrame (offline / batch mode).
    Ported from BSaiCharan-GH/XAI-NIDS explainability/shap_explainer.py.

    Parameters
    ----------
    model      : trained sklearn model
    scaler     : fitted StandardScaler
    le         : fitted LabelEncoder
    sample_df  : DataFrame containing one row (FEATURE_COLS columns)
    sample_index : row index within sample_df

    Returns
    -------
    pd.DataFrame with columns [Feature, SHAP, Absolute_SHAP]
    """
    if not _shap_available():
        print("[WARN] shap not installed. Run: pip install shap")
        return pd.DataFrame()

    import shap

    X = sample_df[FEATURE_COLS]
    X_scaled = scaler.transform(X)

    prediction   = model.predict(X_scaled)[0]
    original_id  = int(le.classes_[prediction])
    class_name   = ID_TO_CLASS.get(original_id, str(original_id))

    model_type = type(model).__name__
    if "Forest" in model_type or "XGB" in model_type:
        explainer   = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_scaled)
        if isinstance(shap_values, list):
            values = shap_values[prediction][0]
        else:
            values = shap_values[0, :, prediction]
    else:
        def pred_fn(X): return model.predict_proba(X)
        explainer   = shap.KernelExplainer(pred_fn, X_scaled)
        shap_values = explainer.shap_values(X_scaled, nsamples=50)
        if isinstance(shap_values, list):
            values = shap_values[prediction][0]
        else:
            values = shap_values[0]

    explanation = pd.DataFrame({"Feature": FEATURE_COLS, "SHAP": values})
    explanation["Absolute_SHAP"] = explanation["SHAP"].abs()
    explanation = explanation.sort_values("Absolute_SHAP", ascending=False)

    print("\n[SHAP] Prediction: {} | Actual index: {}".format(class_name, sample_index))
    print(explanation.head(15).to_string(index=False))
    return explanation


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from ml.preprocess import run_preprocessing

    print("Loading model and test data...")
    _, X_test, _, y_test, _, le = run_preprocessing(verbose=False)

    model, scaler, le = _load_artifacts()

    # Explain first 3 test samples
    for i in range(min(3, len(X_test))):
        row_df = pd.DataFrame([X_test[i]], columns=FEATURE_COLS)
        explain_sample(model, scaler, le, row_df, sample_index=i)

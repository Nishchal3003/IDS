"""
ml/train.py
-----------
Train multiple ML classifiers on the CIC-IDS 2017 dataset, evaluate them
on a held-out test set, and save the best model + scaler for inference.

Models trained:
  1. Random Forest        — fast, interpretable, good baseline
  2. XGBoost              — highest accuracy in IDS literature
  3. MLP Neural Network   — generalises well, picks up non-linear patterns

Usage:
    python main.py train
    OR
    python -m ml.train
"""

import pickle
import time
import warnings
from pathlib import Path

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    f1_score,
)
from sklearn.neural_network import MLPClassifier

warnings.filterwarnings("ignore")

try:
    from xgboost import XGBClassifier
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

from ml.constants import (
    BEST_MODEL_PATH, CLASSES, ID_TO_CLASS, MODELS_DIR,
    MLP_HIDDEN, MLP_MAX_ITER,
    RF_N_ESTIMATORS, RANDOM_STATE,
    XGB_MAX_DEPTH, XGB_N_ESTIMATORS,
)
from ml.preprocess import run_preprocessing
import numpy as np


def _build_models() -> list[tuple[str, object]]:
    """Return a list of (name, unfitted_estimator) tuples."""
    models = [
        (
            "Random Forest",
            RandomForestClassifier(
                n_estimators=RF_N_ESTIMATORS,
                class_weight="balanced",
                n_jobs=-1,
                random_state=RANDOM_STATE,
            ),
        ),
        (
            "MLP Neural Network",
            MLPClassifier(
                hidden_layer_sizes=MLP_HIDDEN,
                max_iter=MLP_MAX_ITER,
                random_state=RANDOM_STATE,
                early_stopping=True,
                validation_fraction=0.1,
            ),
        ),
    ]
    if XGBOOST_AVAILABLE:
        models.insert(
            1,
            (
                "XGBoost",
                XGBClassifier(
                    n_estimators=XGB_N_ESTIMATORS,
                    max_depth=XGB_MAX_DEPTH,
                    # use_label_encoder removed in XGBoost 2.x
                    eval_metric="mlogloss",
                    random_state=RANDOM_STATE,
                    n_jobs=-1,
                    verbosity=0,
                ),
            ),
        )
    else:
        print("  [WARN] xgboost not installed — skipping XGBoost. "
              "Install with: pip install xgboost")
    return models


def _train_and_evaluate(
    name: str,
    model,
    X_train: np.ndarray,
    X_test: np.ndarray,
    y_train: np.ndarray,
    y_test: np.ndarray,
    le,                      # sklearn LabelEncoder — maps encoded ID → original class name
) -> tuple[float, object]:
    """Fit model, print classification report, return (weighted_f1, fitted_model)."""
    print(f"\n  ── Training: {name} ──")
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    print(f"     Training time: {elapsed:.1f}s")

    y_pred  = model.predict(X_test)
    f1      = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    # Build human-readable class names from the LabelEncoder
    # le.classes_ = original class IDs (e.g. [0,1,2,3,4,6,7])
    # Encoded values 0..K-1 correspond to le.classes_[0..K-1]
    present      = sorted(set(y_test) | set(y_pred))
    target_names = [ID_TO_CLASS.get(int(le.classes_[i]), str(i)) for i in present]

    print(f"     Weighted F1  : {f1:.4f}")
    print("\n" + classification_report(
        y_test, y_pred,
        labels=present,
        target_names=target_names,
        zero_division=0,
    ))
    return f1, model


def save_model(name: str, model, f1: float) -> None:
    """Persist the model as best_model.pkl and save metadata."""
    with open(BEST_MODEL_PATH, "wb") as fh:
        pickle.dump({"name": name, "model": model, "f1": f1, "classes": CLASSES}, fh)
    print(f"  [OK]  Best model ({name}, F1={f1:.4f}) saved → {BEST_MODEL_PATH}")


def run_training(verbose: bool = True) -> None:
    """Full training pipeline: preprocess → train all models → save best."""
    # ── Load & preprocess ───────────────────────────────────────────────────
    X_train, X_test, y_train, y_test, _, le = run_preprocessing(verbose=verbose)

    print("\n" + "="*55)
    print("  Phase 3 — Step 2: Model Training")
    print("="*55)

    # ── Train all models ──────────────────────────────────────────────────
    models  = _build_models()
    results: list[tuple[float, str, object]] = []

    for name, estimator in models:
        f1, fitted = _train_and_evaluate(
            name, estimator, X_train, X_test, y_train, y_test, le
        )
        results.append((f1, name, fitted))

    # ── Pick best ───────────────────────────────────────────────────────
    results.sort(key=lambda t: t[0], reverse=True)
    best_f1, best_name, best_model = results[0]

    print("\n" + "="*55)
    print("  Model Comparison (by weighted F1)")
    print("="*55)
    for f1, name, _ in results:
        marker = " ← BEST" if name == best_name else ""
        print(f"    {name:<25}  F1 = {f1:.4f}{marker}")
    print()

    # ── Save best ───────────────────────────────────────────────────────
    save_model(best_name, best_model, best_f1)

    print("\n  Training complete!")
    print(f"  Run 'python main.py evaluate' for detailed metrics + confusion matrix.\n")


if __name__ == "__main__":
    run_training()

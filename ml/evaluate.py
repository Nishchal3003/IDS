"""
ml/evaluate.py
--------------
Detailed evaluation of the trained model on a fresh held-out test set.

Produces:
  - Full classification report (per-class precision/recall/F1)
  - Confusion matrix  → ml/reports/confusion_matrix.png
  - Feature importance → ml/reports/feature_importance.png  (RF/XGBoost only)
  - ROC curves        → ml/reports/roc_curves.png

Usage:
    python main.py evaluate
    OR
    python -m ml.evaluate
"""

import pickle
import warnings
from pathlib import Path

import numpy as np

warnings.filterwarnings("ignore")

from ml.constants import (
    BEST_MODEL_PATH, CLASSES, FEATURE_COLS, ID_TO_CLASS, REPORTS_DIR,
)
from ml.preprocess import run_preprocessing


def _check_matplotlib() -> bool:
    try:
        import matplotlib  # noqa
        return True
    except ImportError:
        print("  [WARN] matplotlib not installed — skipping plots.")
        print("         Install with: pip install matplotlib")
        return False


def _plot_confusion_matrix(y_test, y_pred, class_names: list[str]) -> None:
    import matplotlib.pyplot as plt
    from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix

    present = sorted(set(y_test) | set(y_pred))
    names   = [ID_TO_CLASS.get(i, str(i)) for i in present]
    cm      = confusion_matrix(y_test, y_pred, labels=present)

    fig, ax = plt.subplots(figsize=(10, 8))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=names)
    disp.plot(ax=ax, cmap="Blues", colorbar=True, xticks_rotation=45)
    ax.set_title("Confusion Matrix — NIDS ML Model", fontsize=14, pad=12)
    plt.tight_layout()
    out = REPORTS_DIR / "confusion_matrix.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"  [OK]  Confusion matrix → {out}")


def _plot_feature_importance(model, top_n: int = 25) -> None:
    import matplotlib.pyplot as plt

    # Works for RF and XGBoost
    if not hasattr(model, "feature_importances_"):
        print("  [SKIP] Model does not support feature_importances_")
        return

    importances = model.feature_importances_
    n = min(top_n, len(FEATURE_COLS))
    idx = np.argsort(importances)[::-1][:n]
    labels = [FEATURE_COLS[i] for i in idx]
    vals   = importances[idx]

    fig, ax = plt.subplots(figsize=(10, 6))
    bars = ax.barh(labels[::-1], vals[::-1], color="#4A90D9")
    ax.set_xlabel("Importance Score")
    ax.set_title(f"Top {n} Feature Importances", fontsize=14)
    plt.tight_layout()
    out = REPORTS_DIR / "feature_importance.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"  [OK]  Feature importance → {out}")


def _plot_roc_curves(model, X_test, y_test, class_names: list[str]) -> None:
    import matplotlib.pyplot as plt
    from sklearn.metrics import roc_curve, auc
    from sklearn.preprocessing import label_binarize

    if not hasattr(model, "predict_proba"):
        print("  [SKIP] Model does not support predict_proba — skipping ROC curves")
        return

    classes_present = sorted(set(y_test))
    y_bin  = label_binarize(y_test, classes=classes_present)
    y_prob = model.predict_proba(X_test)

    # y_prob columns may not align with all classes — select correct columns
    all_classes = list(range(len(CLASSES)))
    # indices of present classes in model's classes_ list
    model_classes = list(getattr(model, "classes_", classes_present))

    fig, ax = plt.subplots(figsize=(10, 7))
    colors  = plt.cm.tab10(np.linspace(0, 1, len(classes_present)))

    for j, cls_id in enumerate(classes_present):
        cls_name = ID_TO_CLASS.get(cls_id, str(cls_id))
        if cls_id not in model_classes:
            continue
        col_idx = model_classes.index(cls_id)
        if col_idx >= y_prob.shape[1]:
            continue
        fpr, tpr, _ = roc_curve(y_bin[:, j], y_prob[:, col_idx])
        roc_auc     = auc(fpr, tpr)
        ax.plot(fpr, tpr, color=colors[j], lw=1.5,
                label=f"{cls_name} (AUC={roc_auc:.3f})")

    ax.plot([0, 1], [0, 1], "k--", lw=0.8)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC Curves — per Attack Class", fontsize=14)
    ax.legend(loc="lower right", fontsize=8)
    plt.tight_layout()
    out = REPORTS_DIR / "roc_curves.png"
    plt.savefig(out, dpi=150)
    plt.close()
    print(f"  [OK]  ROC curves → {out}")


def run_evaluation(verbose: bool = True) -> None:
    """Load best model, re-run preprocessing, evaluate, and save reports."""
    if not BEST_MODEL_PATH.exists():
        print(f"\n  [ERR] No trained model at {BEST_MODEL_PATH}")
        print("  Run: python main.py train\n")
        return

    # Load model
    with open(BEST_MODEL_PATH, "rb") as fh:
        artifact = pickle.load(fh)
    model      = artifact["model"]
    model_name = artifact.get("name", "Unknown")
    saved_f1   = artifact.get("f1", 0.0)

    print("\n" + "="*55)
    print(f"  Phase 3 — Evaluation: {model_name}  (saved F1={saved_f1:.4f})")
    print("="*55)

    # Re-run preprocessing to get a fresh test set
    _, X_test, _, y_test, _ = run_preprocessing(verbose=verbose)

    from sklearn.metrics import (
        accuracy_score,
        classification_report,
        f1_score,
    )

    y_pred = model.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    wf1    = f1_score(y_test, y_pred, average="weighted", zero_division=0)

    print(f"\n  Accuracy  : {acc*100:.2f}%")
    print(f"  Weighted F1 : {wf1:.4f}")

    present      = sorted(set(y_test) | set(y_pred))
    target_names = [ID_TO_CLASS.get(i, str(i)) for i in present]

    print("\n  Per-class metrics:")
    print(classification_report(
        y_test, y_pred,
        labels=present,
        target_names=target_names,
        zero_division=0,
    ))

    # Plots
    has_mpl = _check_matplotlib()
    if has_mpl:
        print("  Generating plots...")
        _plot_confusion_matrix(y_test, y_pred, CLASSES)
        _plot_feature_importance(model)
        _plot_roc_curves(model, X_test, y_test, CLASSES)
        print(f"\n  Reports saved to: {REPORTS_DIR}")

    print("\n  Evaluation complete!\n")


if __name__ == "__main__":
    run_evaluation()

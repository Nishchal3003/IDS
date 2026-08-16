"""
ml/preprocess.py
----------------
Load, clean, and encode the CIC-IDS 2017 dataset for ML training.
"""

import warnings
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import pickle

from ml.constants import (
    DATASET_DIR, DATASET_FILES, FEATURE_COLS, LABEL_COL,
    LABEL_TO_CLASS, CLASS_TO_ID, SCALER_PATH, LABEL_MAP_PATH,
    ROWS_PER_FILE, TEST_SIZE, RANDOM_STATE,
)

warnings.filterwarnings("ignore")


def _strip_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Strip leading/trailing whitespace from all column names."""
    df.columns = df.columns.str.strip()
    return df


def _map_labels(df: pd.DataFrame) -> pd.DataFrame:
    """Map fine-grained CIC-IDS labels to coarse class names, then to int IDs."""
    # Strip whitespace in label values too
    df[LABEL_COL] = df[LABEL_COL].str.strip()
    # Map to coarse class (unknown labels → 'BENIGN' as safe fallback)
    df["coarse_label"] = df[LABEL_COL].map(LABEL_TO_CLASS).fillna("BENIGN")
    # Map class name → int ID
    df["label_id"] = df["coarse_label"].map(CLASS_TO_ID)
    return df


def load_dataset(
    files: list[str] = None,
    dataset_dir: Path = DATASET_DIR,
    rows_per_file: int = ROWS_PER_FILE,
    verbose: bool = True,
) -> pd.DataFrame:
    """
    Load CIC-IDS 2017 CSV files, clean columns, and return a combined DataFrame.

    Parameters
    ----------
    files        : list of CSV filenames to load (default: all 8 files)
    dataset_dir  : directory containing the CSVs
    rows_per_file: max rows to sample per file (None = load all)
    verbose      : print progress info

    Returns
    -------
    pd.DataFrame with stripped column names, coarse_label, and label_id columns.
    """
    files = files or DATASET_FILES
    frames = []

    for fname in files:
        path = dataset_dir / fname
        if not path.exists():
            if verbose:
                print(f"  [SKIP] File not found: {fname}")
            continue
        try:
            df = pd.read_csv(path, low_memory=False, nrows=rows_per_file,
                             encoding="utf-8", encoding_errors="replace")
        except Exception as e:
            if verbose:
                print(f"  [ERR]  Could not read {fname}: {e}")
            continue

        df = _strip_columns(df)
        df = _map_labels(df)
        frames.append(df)

        if verbose:
            counts = df["coarse_label"].value_counts().to_dict()
            print(f"  [OK]   {fname[:45]:<45}  rows={len(df):>7,}  labels={counts}")

    if not frames:
        raise RuntimeError("No dataset files could be loaded.")

    combined = pd.concat(frames, ignore_index=True)
    if verbose:
        print(f"\n  Combined rows: {len(combined):,}")
        print(f"  Label distribution:")
        for cls, cnt in combined["coarse_label"].value_counts().items():
            pct = cnt / len(combined) * 100
            print(f"    {cls:<15} {cnt:>8,}  ({pct:5.1f}%)")
    return combined


def prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """
    Extract feature matrix X and target vector y from the combined DataFrame.

    Missing feature columns are filled with 0. Infinity values are replaced.

    Returns
    -------
    X : pd.DataFrame of numeric features
    y : pd.Series of integer class IDs
    """
    # Keep only columns present in df (graceful handling)
    available = [c for c in FEATURE_COLS if c in df.columns]
    missing   = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        print(f"  [WARN] {len(missing)} feature column(s) not found in dataset: {missing[:5]}...")

    X = df[available].copy()
    # Fill missing feature cols with 0
    for c in missing:
        X[c] = 0.0

    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = df["label_id"].fillna(0).astype(int)
    return X, y


def split_and_scale(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = TEST_SIZE,
    random_state: int = RANDOM_STATE,
    save_scaler: bool = True,
) -> tuple:
    """
    Stratified train/test split + StandardScaler fit on training data.

    Returns
    -------
    X_train, X_test, y_train, y_test (all numpy arrays)
    """
    X_train, X_test, y_train, y_test = train_test_split(
        X.values, y.values,
        test_size=test_size,
        random_state=random_state,
        stratify=y.values,
    )

    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test  = scaler.transform(X_test)

    if save_scaler:
        with open(SCALER_PATH, "wb") as f:
            pickle.dump(scaler, f)
        print(f"  [OK]  Scaler saved → {SCALER_PATH}")

    return X_train, X_test, y_train, y_test, scaler


def run_preprocessing(verbose: bool = True) -> tuple:
    """
    Convenience wrapper: load → prepare → split → scale.

    Returns
    -------
    X_train, X_test, y_train, y_test, scaler
    """
    if verbose:
        print("\n" + "="*55)
        print("  Phase 3 — Step 1: Loading & Preprocessing Dataset")
        print("="*55)

    df = load_dataset(verbose=verbose)
    X, y = prepare_features(df)

    if verbose:
        print(f"\n  Feature matrix: {X.shape[0]:,} rows × {X.shape[1]} features")
        print(f"  Splitting {int((1-TEST_SIZE)*100)}/{int(TEST_SIZE*100)} train/test (stratified)...")

    result = split_and_scale(X, y, save_scaler=True)
    X_train, X_test, y_train, y_test, scaler = result

    if verbose:
        print(f"  Train: {len(X_train):,} | Test: {len(X_test):,}")

    return X_train, X_test, y_train, y_test, scaler


if __name__ == "__main__":
    run_preprocessing()

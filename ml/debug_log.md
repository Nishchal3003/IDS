# Phase 3 — Debug Log

> One entry per error encountered. Each entry follows: **Error → Root Cause → Fix → Decision Rationale**.

---

## BUG-001 — XGBoost: Invalid classes (non-consecutive label IDs)

**Date:** 2026-08-16  
**File:** `ml/train.py` → `ml/preprocess.py`  
**Severity:** Critical (training crashes before any model is saved)

### Error Message
`
ValueError: Invalid classes inferred from unique values of `y`.
Expected: [0 1 2 3 4 5 6], got [0 1 2 3 4 6 7]
`

### Root Cause

`ROWS_PER_FILE = 200_000` reads the **first** 200k rows from each CSV (not random).
The Thursday-WebAttacks CSV has benign traffic at the top; Web Attack rows appear much later.
Result: **WebAttack (class ID = 5)** is never loaded.

`y` has unique values `[0,1,2,3,4,6,7]` — gap at 5.
XGBoost infers `num_class` from the range of unique integers and requires them consecutive from 0.

### Data Flow (Before Fix)
`
CSV row sampling (first 200k rows)
        ↓
y = [0, 0, 1, 2, 3, 4, 6, 7, ...]   <- gap at 5 (WebAttack missing)
        ↓
XGBoost.fit(X_train, y_train)
        ↓
ValueError: Expected [0..6], got [0,1,2,3,4,6,7]
`

### Fix Applied

Added `sklearn.preprocessing.LabelEncoder` in `split_and_scale()`:

`python
le = LabelEncoder()
y_encoded = le.fit_transform(y.values)
# [0,1,2,3,4,6,7]  ->  [0,1,2,3,4,5,6]   (K=7 distinct classes)
`

`le.classes_` = `[0, 1, 2, 3, 4, 6, 7]` (original class IDs).
Inverse map at inference: `ID_TO_CLASS[le.classes_[model_output]]`.

New file saved: `ml/models/label_encoder.pkl`

### Decision Table

| Option | Chosen? | Reason |
|---|---|---|
| LabelEncoder on y | YES | Standard sklearn pattern; serializable; adapts to any subset of classes |
| Re-map CLASSES to present only | No | Breaks ID_TO_CLASS alignment across runs |
| Stratified random sampling | No | Complex + slow on 2.8M rows |
| ROWS_PER_FILE=None (all rows) | No | Requires 8+ GB RAM |

---

## BUG-002 — use_label_encoder deprecated (XGBoost 2.x)

**Date:** 2026-08-16  
**Severity:** Warning (TypeError on XGBoost >= 2.0)

### Error
`
TypeError: XGBClassifier.__init__() got an unexpected keyword argument 'use_label_encoder'
`

### Root Cause
`use_label_encoder=False` was valid in XGBoost 1.x but fully removed in 2.0.

### Fix
Removed the kwarg. BUG-001's LabelEncoder fix makes it unnecessary anyway.

---

*Add new entries below this line as they are encountered.*

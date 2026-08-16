# Phase 3 — Design Decisions

Rationale for every non-obvious technical choice in the Phase 3 ML pipeline.

---

## DD-001: Row Sampling (ROWS_PER_FILE = 200,000)

**Decision:** Cap each CSV file at 200k rows instead of loading all ~2.8M.

**Why:**
- Total dataset is ~885 MB on disk; fully loaded into pandas = ~6-8 GB RAM
- Most dev machines (8 GB) cannot hold the full dataset + scikit-learn models in RAM
- 200k × 8 files = 1.6M rows, which is sufficient for a generalisable model

**Tradeoff:**
- Some rare classes (WebAttack, Infiltration) may not appear in the first 200k rows of a file
  → Mitigated by BUG-001's LabelEncoder fix (model adapts to whatever classes appear)
- To train on full data: set `ROWS_PER_FILE = None` in `ml/constants.py`

---

## DD-002: Coarse Label Grouping (9 classes, not 15)

**Decision:** Map 15 fine-grained CIC-IDS labels to 9 coarse attack classes.

**Why:**
- Fine-grained labels (e.g. "DoS Hulk" vs "DoS GoldenEye") are rarely distinguishable
  from flow-level features alone — they all share the same core pattern (high rate + small RTT)
- Fewer classes → better generalisation; recall on rare sub-classes is near 0 anyway
- 9 classes is actionable for a NIDS operator ("block DoS traffic" vs "block DDoS traffic")

**Class Map:**

| Fine-grained | Coarse | Rationale |
|---|---|---|
| DoS Hulk / GoldenEye / slowloris / Slowhttptest | DoS | Same volumetric pattern |
| DDoS | DDoS | Distinct: multi-source vs single-source |
| FTP-Patator, SSH-Patator | BruteForce | Same: repeated login attempts |
| Web Attack – XSS/BruteForce/SQLi | WebAttack | Same: HTTP-layer exploits |
| Bot | Botnet | Distinct long-lived C2 pattern |
| Infiltration | Infiltration | Rare but distinct (low-and-slow) |
| Heartbleed | Heartbleed | TLS-layer exploit, unique features |

---

## DD-003: Three Models Trained and Compared

**Decision:** Train Random Forest, XGBoost, and MLP; auto-pick best by weighted F1.

**Why:**
- **Random Forest:** Fast, interpretable, feature importance available. Best for explaining to stakeholders.
- **XGBoost:** Consistently highest accuracy in published IDS literature on CIC-IDS 2017 (often >99% F1).
- **MLP:** Good at picking up non-linear correlations RF/XGB miss; graceful degradation on unseen attacks.

The best model is chosen automatically — no manual selection needed. The user can inspect the comparison table after training.

---

## DD-004: LabelEncoder Saved to Disk (label_encoder.pkl)

**Decision:** Persist the LabelEncoder alongside best_model.pkl and scaler.pkl.

**Why:**
- The same encoder used at training must be used at inference. Without this, model predictions
  (0..K-1 encoded integers) cannot be mapped back to human-readable class names.
- If we retrain on a different subset of classes, the encoder updates automatically.
- Three artifacts form a "model bundle": `best_model.pkl` + `scaler.pkl` + `label_encoder.pkl`

**Inference pipeline:**
`
raw_flow_dict
    -> StandardScaler.transform()   [scaler.pkl]
    -> model.predict()              [best_model.pkl]   -> encoded_id (0..K-1)
    -> le.classes_[encoded_id]                          -> original class ID
    -> ID_TO_CLASS[original_id]                         -> "DoS", "BENIGN", etc.
`

---

## DD-005: class_weight='balanced' for Random Forest

**Decision:** Use `class_weight='balanced'` instead of SMOTE oversampling.

**Why:**
- The dataset is severely imbalanced: BENIGN (~70%) vs rare attacks (<0.1%)
- SMOTE would require generating synthetic samples for rare classes — slow and memory-intensive
- `class_weight='balanced'` adjusts loss function weights inversely proportional to class frequency;
  near-zero additional compute cost; same or better precision/recall for rare classes in practice

---

## DD-006: `predict.py` Uses `@lru_cache(maxsize=1)`

**Decision:** Wrap `_load_artifacts()` with LRU cache.

**Why:**
- Phase 4 will call `classify_flow()` for every completed network flow (potentially thousands/minute)
- Loading 3 pkl files from disk on every call would be prohibitively slow (~50-200ms per call)
- With `@lru_cache`, artifacts are loaded once at first call and held in memory for the process lifetime
- `maxsize=1` = only the most recent call is cached (sufficient since we only have one model)

---

## DD-007: `FEATURE_COLS` in `ml/constants.py` mirrors CIC-IDS 2017 headers

**Decision:** Feature column names in Phase 3 exactly match the stripped CSV headers.

**Why:**
- Phase 2 `capture/constants.py` defines `ML_FEATURE_COLUMNS` with the same names (minus identity cols)
- When Phase 4 runs live capture → classify, the captured flow dict keys must match what the model was trained on
- No renaming/mapping step required at inference time

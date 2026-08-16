# Phase 3 - Component Flow

Complete data flow and component interaction for the ML pipeline.

---

## 1. Training Flow

    python main.py train
          |
          v
    ml/train.py :: run_training()
          |
          |-- ml/preprocess.py :: run_preprocessing()
          |       |
          |       |-- load_dataset()
          |       |       For each CSV in datasets/cicids2017/:
          |       |         pd.read_csv(nrows=200_000)
          |       |         strip column whitespace
          |       |         map fine-grained label -> coarse class (LABEL_TO_CLASS)
          |       |         map coarse class -> integer ID   (CLASS_TO_ID)
          |       |
          |       |-- prepare_features()
          |       |       Select 78 numeric columns (FEATURE_COLS)
          |       |       Replace Inf/NaN with 0
          |       |       Return (X: DataFrame, y: Series[int])
          |       |
          |       -- split_and_scale()
          |               LabelEncoder.fit_transform(y)
          |                 y_encoded: [0,1,2,3,4,5,6] (consecutive)
          |                 le.classes_: [0,1,2,3,4,6,7] (original IDs)
          |               train_test_split(X, y_encoded, stratify=y_encoded)
          |               StandardScaler.fit_transform(X_train)
          |               StandardScaler.transform(X_test)
          |               Save: ml/models/scaler.pkl
          |               Save: ml/models/label_encoder.pkl
          |               Return (X_train, X_test, y_train, y_test, scaler, le)
          |
          |-- _build_models()
          |       RandomForestClassifier(n_estimators=100, class_weight=balanced)
          |       XGBClassifier(n_estimators=200, max_depth=8)
          |       MLPClassifier(hidden=(256,128,64), max_iter=200)
          |
          For each model:
          |-- _train_and_evaluate(name, model, X_train, X_test, y_train, y_test, le)
          |       model.fit(X_train, y_train)
          |       y_pred = model.predict(X_test)
          |       weighted_f1 = f1_score(y_test, y_pred, average=weighted)
          |       target_names = [ID_TO_CLASS[le.classes_[i]] for i in present]
          |       Print classification_report
          |       Return (f1, fitted_model)
          |
          Sort by F1, pick best
          |
          save_model(best_name, best_model, best_f1)
                Save: ml/models/best_model.pkl


## 2. Inference Flow (Single Flow)

    classify_flow(flow_dict)                [ml/predict.py]
          |
          _load_artifacts()   [lru_cache - loads only once per process]
          |       load best_model.pkl + scaler.pkl + label_encoder.pkl
          |
          Build feature vector (78 floats), replace Inf/NaN with 0
          scaler.transform(row)
          |
          encoded_id = model.predict(row_scaled)   -> 0..K-1
          original_id = le.classes_[encoded_id]    -> original class ID
          label = ID_TO_CLASS[original_id]         -> DoS, BENIGN, etc.
          confidence = model.predict_proba()[encoded_id]
          |
          Return {label, confidence, is_attack, probabilities}


## 3. Evaluation Flow

    python main.py evaluate
          |
          ml/evaluate.py :: run_evaluation()
          |
          Load best_model.pkl + label_encoder.pkl
          run_preprocessing()  [fresh split - same as training]
          |
          y_pred = model.predict(X_test)
          accuracy_score, f1_score, classification_report
          |
          _plot_confusion_matrix -> ml/reports/confusion_matrix.png
          _plot_feature_importance -> ml/reports/feature_importance.png
          _plot_roc_curves -> ml/reports/roc_curves.png


## 4. File Map

    ml/
    |-- __init__.py              Package marker
    |-- constants.py             Paths, label maps, feature list, hyperparams
    |-- preprocess.py            Load + clean + encode + split + scale
    |-- train.py                 Train 3 models, compare, save best
    |-- predict.py               Load model + classify flows (lru_cache)
    |-- evaluate.py              Detailed evaluation + plot generation
    |-- debug_log.md             Bug tracker
    |-- decision.md              Design decision rationale
    |-- flow.md                  This file - data flow diagrams
    |
    |-- models/                  Created at training time
    |   |-- best_model.pkl       Trained model + name + f1 metadata
    |   |-- scaler.pkl           StandardScaler fitted on X_train
    |   -- label_encoder.pkl    LabelEncoder: encoded IDs <-> original class IDs
    |
    -- reports/                 Created at evaluation time
        |-- confusion_matrix.png
        |-- feature_importance.png
        -- roc_curves.png


## 5. Label Encoding Detail

    CIC-IDS fine label       -> coarse class  -> class ID -> LabelEncoder -> model y
    ---------------------------------------------------------------------------------
    BENIGN                   -> BENIGN         ->    0    ->      0       ->   0
    DoS Hulk                 -> DoS            ->    1    ->      1       ->   1
    DDoS                     -> DDoS           ->    2    ->      2       ->   2
    PortScan                 -> PortScan       ->    3    ->      3       ->   3
    FTP-Patator              -> BruteForce     ->    4    ->      4       ->   4
    Web Attack (XSS etc)  <- MISSING IN SAMPLE (200k row cap, rows appear late in CSV)
    Bot                      -> Botnet         ->    6    ->      5       ->   5
    Infiltration             -> Infiltration   ->    7    ->      6       ->   6
    Heartbleed               -> Heartbleed     ->    8    <- MISSING IN SAMPLE

    le.classes_ = [0, 1, 2, 3, 4, 6, 7]    (original IDs that appeared in data)
    Model trains on: [0, 1, 2, 3, 4, 5, 6]  (consecutive - XGBoost requirement met)

    At inference:
      model.predict() -> 5  (encoded)
      le.classes_[5]  -> 6  (original class ID = Botnet)
      ID_TO_CLASS[6]  -> Botnet

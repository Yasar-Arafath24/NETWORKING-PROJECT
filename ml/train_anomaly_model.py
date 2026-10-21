"""
NetSentry AI - Train and evaluate an Isolation Forest anomaly detector.

Run from the project root:
    python -m ml.train_anomaly_model

Input:
    datasets/processed/ml_ready_flows.csv

Output:
    models/anomaly_detector.joblib
    datasets/processed/anomaly_predictions.csv

Important:
- Isolation Forest is unsupervised. Its anomaly labels are not ground-truth attack labels.
- Repeated feature rows reduce the value of evaluation; inspect the dataset before relying on metrics.
"""

from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
DATASET_PATH = ROOT / "datasets" / "processed" / "ml_ready_flows.csv"
MODEL_PATH = ROOT / "models" / "anomaly_detector.joblib"
PREDICTIONS_PATH = ROOT / "datasets" / "processed" / "anomaly_predictions.csv"

# Columns that describe identifiers or labels, not numeric traffic behavior.
EXCLUDED_COLUMNS = {
    "source_file",
    "label",
    "target",
    "class",
    "is_attack",
    "is_anomaly",
    "anomaly",
    "prediction",
    "predicted_label",
    "src_ip",
    "dst_ip",
    "source_ip",
    "destination_ip",
    "src_port",
    "dst_port",
    "source_port",
    "destination_port",
    "flow_id",
    "timestamp",
    "start_time",
    "end_time",
}


def main():
    print("=" * 64)
    print("NetSentry AI - Anomaly Model Training")
    print("=" * 64)

    if not DATASET_PATH.exists():
        print(f"ERROR: Dataset not found: {DATASET_PATH}")
        print("Run dataset preparation first.")
        return 1

    df = pd.read_csv(DATASET_PATH)
    if df.empty:
        print("ERROR: Dataset is empty.")
        return 1

    print(f"Dataset: {DATASET_PATH}")
    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")

    # Only use numeric features and avoid obvious identifiers/labels.
    feature_columns = [
        col for col in df.columns
        if col.strip().lower() not in EXCLUDED_COLUMNS
        and pd.api.types.is_numeric_dtype(df[col])
    ]

    # Convert numeric-looking object columns if they contain mostly numeric values.
    for col in df.columns:
        if col.strip().lower() in EXCLUDED_COLUMNS or col in feature_columns:
            continue
        converted = pd.to_numeric(df[col], errors="coerce")
        if converted.notna().sum() >= max(1, int(0.8 * len(df))):
            df[col] = converted
            feature_columns.append(col)

    if not feature_columns:
        print("ERROR: No numeric feature columns were found.")
        print("Available columns:", df.columns.tolist())
        return 1

    X = df[feature_columns].replace([float("inf"), float("-inf")], pd.NA)
    # Drop entirely empty columns; impute remaining missing values.
    feature_columns = [c for c in feature_columns if X[c].notna().any()]
    X = X[feature_columns]

    if not feature_columns:
        print("ERROR: All candidate features are empty.")
        return 1

    # A feature with one unique value contributes no useful separation.
    varying = [c for c in feature_columns if X[c].nunique(dropna=True) > 1]
    if varying:
        feature_columns = varying
        X = X[feature_columns]

    if X.shape[1] == 0:
        print("ERROR: No varying numeric features remain.")
        return 1

    X = X.astype("float64")
    unique_rows = X.drop_duplicates().shape[0]
    duplicate_count = len(X) - unique_rows

    print("\nSelected features:")
    for col in feature_columns:
        print(f"  - {col}")
    print(f"\nDistinct feature rows: {unique_rows}/{len(X)}")
    print(f"Repeated feature rows: {duplicate_count}")

    if len(X) < 10:
        print("WARNING: Very small dataset. Model output is only a smoke test.")
    if unique_rows < 10:
        print("WARNING: Very few distinct rows; do not treat predictions as reliable.")

    pipeline = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "model",
                IsolationForest(
                    n_estimators=200,
                    contamination="auto",
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )

    pipeline.fit(X)
    predictions = pipeline.predict(X)  # 1 = inlier, -1 = anomaly
    scores = pipeline.decision_function(X)

    output = df.copy()
    output["anomaly_prediction"] = ["normal" if p == 1 else "anomaly" for p in predictions]
    output["anomaly_score"] = scores
    output["is_anomaly"] = predictions == -1

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    PREDICTIONS_PATH.parent.mkdir(parents=True, exist_ok=True)

    artifact = {
        "pipeline": pipeline,
        "feature_columns": feature_columns,
        "algorithm": "IsolationForest",
        "prediction_mapping": {1: "normal", -1: "anomaly"},
        "training_rows": int(len(X)),
        "distinct_training_rows": int(unique_rows),
    }
    joblib.dump(artifact, MODEL_PATH)
    output.to_csv(PREDICTIONS_PATH, index=False)

    anomaly_count = int((predictions == -1).sum())
    print("\nTraining completed.")
    print(f"Rows scored: {len(output)}")
    print(f"Predicted anomalies: {anomaly_count}")
    print(f"Predicted normal: {len(output) - anomaly_count}")
    print(f"Saved model: {MODEL_PATH}")
    print(f"Saved predictions: {PREDICTIONS_PATH}")
    print("\nNote: These are unsupervised model outputs, not verified attack labels.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

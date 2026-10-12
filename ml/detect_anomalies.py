
from pathlib import Path

import joblib
import pandas as pd


ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "processed" / "flow_features.csv"
MODEL_PATH = ROOT / "models" / "anomaly_detector.joblib"
OUTPUT_PATH = ROOT / "datasets" / "processed" / "anomaly_results.csv"


def main():
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            "Model not found. Run ml/train_anomaly_model.py first."
        )

    if not DATASET.is_file():
        raise FileNotFoundError(f"Dataset not found: {DATASET}")

    df = pd.read_csv(DATASET)

    if df.empty:
        raise ValueError("Dataset contains no flows.")

    saved = joblib.load(MODEL_PATH)
    pipeline = saved["pipeline"]
    feature_columns = saved["feature_columns"]

    missing = set(feature_columns) - set(df.columns)
    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    X = df[feature_columns].apply(
        pd.to_numeric, errors="coerce"
    )
    X = X.replace([float("inf"), float("-inf")], float("nan"))

    # Isolation Forest uses -1 for outliers and 1 for inliers.
    predictions = pipeline.predict(X)

    # Higher scores indicate more abnormal behavior for this model.
    scores = -pipeline.decision_function(X)

    results = df.copy()
    results["anomaly_score"] = scores
    results["anomaly_prediction"] = [
        "ANOMALY" if value == -1 else "NORMAL"
        for value in predictions
    ]

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(OUTPUT_PATH, index=False)

    anomaly_count = int((predictions == -1).sum())

    print("=" * 60)
    print("NetSentry AI - Anomaly Detection Results")
    print("=" * 60)
    print(f"Flows analyzed: {len(results)}")
    print(f"Unusual flows: {anomaly_count}")
    print(f"Output saved: {OUTPUT_PATH}")
    print("\nFirst 10 results:")

    display_columns = [
        "protocol",
        "packet_count",
        "total_bytes",
        "anomaly_score",
        "anomaly_prediction",
    ]
    print(results[display_columns].head(10).to_string(index=False))


if __name__ == "__main__":
    main()

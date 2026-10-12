
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parent.parent
DATASET = ROOT / "datasets" / "processed" / "flow_features.csv"
MODEL_PATH = ROOT / "models" / "anomaly_detector.joblib"

# Exclude IP addresses and ports from this initial behavioral model.
FEATURE_COLUMNS = [
    "duration",
    "packet_count",
    "total_bytes",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "packet_size_variance",
    "average_interarrival_time",
    "interarrival_variance",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "urg_count",
]


def main():
    print("=" * 60)
    print("NetSentry AI - Anomaly Model Training")
    print("=" * 60)

    if not DATASET.is_file():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET}\n"
            "Run the feature engineering pipeline first."
        )

    df = pd.read_csv(DATASET)

    missing = set(FEATURE_COLUMNS) - set(df.columns)
    if missing:
        raise ValueError(f"Missing dataset columns: {sorted(missing)}")

    if len(df) < 20:
        raise ValueError(
            f"Only {len(df)} flows available. "
            "Collect a larger capture before training."
        )

    X = df[FEATURE_COLUMNS].apply(
        pd.to_numeric, errors="coerce"
    )

    X = X.replace([float("inf"), float("-inf")], float("nan"))

    # Remove columns that contain no usable values.
    usable_columns = [
        col for col in X.columns if X[col].notna().any()
    ]
    X = X[usable_columns]

    if X.empty or not usable_columns:
        raise ValueError("No usable numeric features were found.")

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("model", IsolationForest(
            n_estimators=200,
            contamination="auto",
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X)

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump({
        "pipeline": pipeline,
        "feature_columns": usable_columns,
    }, MODEL_PATH)

    print(f"Training flows: {len(X)}")
    print(f"Features used: {len(usable_columns)}")
    print(f"Model saved: {MODEL_PATH}")
    print("Training completed.")

    print(
        "\nNote: Isolation Forest learns unusual patterns, "
        "not verified attacks. Evaluate it using representative "
        "captures and labeled test data."
    )


if __name__ == "__main__":
    main()

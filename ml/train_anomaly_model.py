
from fastapi import HTTPException
from ml.anomaly_service import predict_anomalies
from pathlib import Path
import argparse
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[1]

FEATURES = [
    "packet_count",
    "total_bytes",
    "duration",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "min_packet_size",
    "max_packet_size",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
]


def main():
    parser = argparse.ArgumentParser(
        description="Train the NetSentry AI anomaly detector"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=ROOT / "datasets" / "processed"
        / "training_features.csv",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "models" / "anomaly_detector.joblib",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.05,
        help="Expected proportion of anomalies, from greater than 0 to 0.5",
    )
    args = parser.parse_args()

    if not 0 < args.contamination <= 0.5:
        parser.error("--contamination must be greater than 0 and at most 0.5")

    dataset = args.input
    if not dataset.is_absolute():
        dataset = ROOT / dataset

    output = args.output
    if not output.is_absolute():
        output = ROOT / output

    if not dataset.is_file():
        sys.exit(f"Dataset not found: {dataset}")

    df = pd.read_csv(dataset)

    if df.empty:
        sys.exit("Dataset is empty. Collect flow data before training.")

    missing = [col for col in FEATURES if col not in df.columns]
    if missing:
        sys.exit(
            "Missing required feature columns: "
            + ", ".join(missing)
            + "\nInspect the CSV and update FEATURES to match the "
              "actual feature extractor."
        )

    X = df[FEATURES].apply(pd.to_numeric, errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.dropna(how="all").reset_index(drop=True)

    if len(X) < 20:
        sys.exit(
            f"Only {len(X)} usable rows. Collect at least 20 usable "
            "flow rows before running this training script. "
            "More diverse data is preferable."
        )

    all_missing = X.columns[X.isna().all()].tolist()
    if all_missing:
        sys.exit(
            "These features contain no usable numeric values: "
            + ", ".join(all_missing)
        )

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
        ("detector", IsolationForest(
            n_estimators=200,
            contamination=args.contamination,
            random_state=42,
            n_jobs=-1,
        )),
    ])

    pipeline.fit(X)
    predictions = pipeline.predict(X)

    output.parent.mkdir(parents=True, exist_ok=True)

    artifact = {
        "model": pipeline,
        "feature_columns": FEATURES,
        "model_type": "IsolationForest",
        "contamination": args.contamination,
        "training_rows": len(X),
    }

    joblib.dump(artifact, output)

    # Verify that the saved model can be loaded and used.
    saved = joblib.load(output)
    saved["model"].predict(X.iloc[:1])

    print("Training completed.")
    print(f"Training rows: {len(X)}")
    print(f"Feature count: {len(FEATURES)}")
    print(f"Training rows flagged as anomalies: {(predictions == -1).sum()}")
    print(f"Saved model: {output}")
    print("Model reload test: passed")
    print(
        "Note: training anomaly counts are not accuracy measurements."
    )


if __name__ == "__main__":
    main()


from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


# --------------------------------------------------
# NetSentry AI - Anomaly Detection
# --------------------------------------------------

ROOT_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = (
    ROOT_DIR / "datasets" / "processed" / "ml_ready_flows.csv"
)

MODEL_DIR = ROOT_DIR / "models"
MODEL_PATH = MODEL_DIR / "anomaly_detector.joblib"

FEATURE_COLUMNS = [
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

MINIMUM_FLOWS = 10


def _load_model_bundle():
    """Load the saved model and support both known bundle formats."""

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found: {MODEL_PATH}. Train the model first."
        )

    saved = joblib.load(MODEL_PATH)

    # Support a saved model bundle using either key.
    if isinstance(saved, dict):
        model = saved.get("pipeline", saved.get("model"))
        columns = saved.get("feature_columns", FEATURE_COLUMNS)
    else:
        # Support a legacy file containing the estimator directly.
        model = saved
        columns = FEATURE_COLUMNS

    if model is None:
        raise ValueError(
            "Invalid model bundle: missing 'pipeline' or 'model' key. "
            "Retrain the anomaly model."
        )

    if not hasattr(model, "predict"):
        raise ValueError(
            "Invalid model bundle: the saved model cannot predict."
        )

    if not hasattr(model, "decision_function"):
        raise ValueError(
            "Invalid model bundle: the saved model has no "
            "decision_function method."
        )

    if not isinstance(columns, list) or not columns:
        raise ValueError(
            "Invalid model bundle: feature_columns must be a non-empty list."
        )

    return model, columns


def train_model(dataset_path=None):
    """Train and save an Isolation Forest anomaly detector."""

    data_path = Path(dataset_path) if dataset_path else DATASET_PATH

    if not data_path.is_absolute():
        data_path = ROOT_DIR / data_path

    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    print("=" * 60)
    print("NetSentry AI - Anomaly Detection Training")
    print("=" * 60)
    print(f"Dataset: {data_path}")

    df = pd.read_csv(data_path)

    if df.empty:
        raise ValueError("The dataset is empty.")

    missing = [column for column in FEATURE_COLUMNS if column not in df.columns]

    if missing:
        raise ValueError(
            f"Dataset is missing required features: {missing}"
        )

    X = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    X = X.replace([float("inf"), float("-inf")], float("nan"))
    X = X.dropna(how="all")

    if (X < 0).any().any():
        raise ValueError("Network-flow features must not be negative.")

    if len(X) < MINIMUM_FLOWS:
        raise ValueError(
            f"Only {len(X)} usable rows found. "
            f"At least {MINIMUM_FLOWS} are required."
        )

    if X.nunique(dropna=True).max() <= 1:
        raise ValueError(
            "The dataset has no variation in its features. "
            "Collect more varied flows before training."
        )

    print(f"Usable rows: {len(X)}")
    print(f"Features: {len(FEATURE_COLUMNS)}")

    model = Pipeline(
        steps=[
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler()),
            (
                "detector",
                IsolationForest(
                    n_estimators=200,
                    contamination="auto",
                    random_state=42,
                ),
            ),
        ]
    )

    model.fit(X)

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "feature_columns": FEATURE_COLUMNS,
            "training_rows": len(X),
            "dataset_path": str(data_path),
        },
        MODEL_PATH,
    )

    print("-" * 60)
    print("Training completed successfully.")
    print(f"Training rows: {len(X)}")
    print(f"Model saved: {MODEL_PATH}")
    print("=" * 60)

    return model


def predict_anomalies(flows):
    """Predict whether each supplied flow looks anomalous."""

    if not flows:
        return []

    model, columns = _load_model_bundle()

    df = pd.DataFrame(flows)

    missing = [column for column in columns if column not in df.columns]

    if missing:
        raise ValueError(
            f"Flow data is missing required features: {missing}"
        )

    X = df[columns].apply(pd.to_numeric, errors="coerce")
    X = X.replace([float("inf"), float("-inf")], float("nan"))

    if X.isna().all(axis=1).any():
        raise ValueError(
            "At least one flow has no usable feature values."
        )

    if (X < 0).any().any():
        raise ValueError("Network-flow features must not be negative.")

    predictions = model.predict(X)
    scores = model.decision_function(X)

    results = []

    for index, prediction in enumerate(predictions):
        is_anomaly = bool(prediction == -1)

        results.append(
            {
                "flow_index": index,
                "anomaly": is_anomaly,
                "label": "SUSPICIOUS" if is_anomaly else "NORMAL",
                "anomaly_score": round(float(scores[index]), 6),
            }
        )

    return results


if __name__ == "__main__":
    dataset_arg = sys.argv[1] if len(sys.argv) > 1 else None
    train_model(dataset_arg)
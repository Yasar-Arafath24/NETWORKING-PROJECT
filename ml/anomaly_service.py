
"""Load the trained model and predict network-flow anomalies."""

from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "anomaly_detector.joblib"

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
    "min_packet_size",
    "max_packet_size",
]


def predict_anomalies(flows: list[dict]) -> list[dict]:
    """Return each flow with a prediction and anomaly score."""
    if not flows:
        return []

    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Trained model not found at {MODEL_PATH}. "
            "Train the anomaly model first."
        )

    model_data = joblib.load(MODEL_PATH)
    pipeline = model_data["pipeline"]
    feature_columns = model_data["feature_columns"]

    frame = pd.DataFrame(flows)

    for column in feature_columns:
        if column not in frame.columns:
            frame[column] = float("nan")

    features = frame[feature_columns].apply(
        pd.to_numeric, errors="coerce"
    )
    features = features.replace([float("inf"), float("-inf")], float("nan"))

    predictions = pipeline.predict(features)
    scores = -pipeline.decision_function(features)

    results = []
    for flow, prediction, score in zip(flows, predictions, scores):
        results.append({
            **flow,
            "anomaly_prediction": (
                "ANOMALY" if int(prediction) == -1 else "NORMAL"
            ),
            "anomaly_score": round(float(score), 6),
        })

    return results

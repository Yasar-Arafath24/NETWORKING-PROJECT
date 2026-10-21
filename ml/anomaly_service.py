
"""Load the trained anomaly pipeline and score network flows."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "anomaly_detector.joblib"

DEFAULT_FEATURE_COLUMNS = [
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


def load_model_data() -> dict:
    """Load and validate the saved model bundle."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Anomaly model not found: {MODEL_PATH}"
        )

    saved = joblib.load(MODEL_PATH)

    if not isinstance(saved, dict):
        raise ValueError(
            "Invalid model bundle: expected a dictionary."
        )

    if "pipeline" not in saved:
        raise ValueError(
            "Invalid model bundle: missing 'pipeline' key. "
            "Retrain the anomaly model."
        )

    pipeline = saved["pipeline"]

    if not hasattr(pipeline, "predict"):
        raise ValueError(
            "The saved pipeline does not support predict()."
        )

    columns = saved.get(
        "feature_columns",
        DEFAULT_FEATURE_COLUMNS,
    )

    if not isinstance(columns, (list, tuple)) or not columns:
        raise ValueError(
            "The model's feature_columns configuration is invalid."
        )

    return {
        "pipeline": pipeline,
        "feature_columns": list(columns),
    }


def predict_anomalies(flows: list[dict]) -> list[dict]:
    """
    Return predictions in the format expected by the PCAP API.

    Each result contains:
      - flow_index
      - anomaly: bool
      - label: NORMAL or SUSPICIOUS
      - anomaly_score
      - anomaly_prediction
    """
    if not flows:
        return []

    model_data = load_model_data()
    pipeline = model_data["pipeline"]
    feature_columns = model_data["feature_columns"]

    frame = pd.DataFrame(flows)

    # Use exactly the feature columns used during training.
    for column in feature_columns:
        if column not in frame.columns:
            frame[column] = np.nan

    features = frame[feature_columns].apply(
        pd.to_numeric,
        errors="coerce",
    )

    features = features.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    # Do not silently invent feature values if the input is unusable.
    if features.isna().all(axis=1).any():
        bad_rows = features.index[
            features.isna().all(axis=1)
        ].tolist()

        raise ValueError(
            "Some flows have no usable numeric model features. "
            f"Flow indexes: {bad_rows[:10]}"
        )

    predictions = np.asarray(pipeline.predict(features))

    if hasattr(pipeline, "decision_function"):
        raw_scores = np.asarray(
            pipeline.decision_function(features)
        ).reshape(-1)
        # IsolationForest: lower decision values are more anomalous.
        anomaly_scores = -raw_scores
    elif hasattr(pipeline, "score_samples"):
        raw_scores = np.asarray(
            pipeline.score_samples(features)
        ).reshape(-1)
        anomaly_scores = -raw_scores
    else:
        # A prediction can still be returned, but no calibrated
        # anomaly score is available from this estimator.
        anomaly_scores = np.full(len(flows), np.nan)

    if len(predictions) != len(flows):
        raise ValueError(
            "The model returned an unexpected number of predictions."
        )

    results = []

    for index, (flow, prediction, score) in enumerate(
        zip(flows, predictions, anomaly_scores)
    ):
        # IsolationForest convention: -1 = anomaly, 1 = normal.
        is_anomaly = int(prediction) == -1
        label = "SUSPICIOUS" if is_anomaly else "NORMAL"

        results.append({
            **flow,
            "flow_index": index,
            "anomaly": is_anomaly,
            "label": label,
            "anomaly_prediction": (
                "ANOMALY" if is_anomaly else "NORMAL"
            ),
            "anomaly_score": (
                round(float(score), 6)
                if np.isfinite(score)
                else None
            ),
        })

    return results

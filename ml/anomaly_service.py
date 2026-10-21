
"""Load the trained anomaly model and score network flows."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_PATH = PROJECT_ROOT / "models" / "anomaly_detector.joblib"

DEFAULT_FEATURE_COLUMNS = [
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


def load_model_data() -> dict:
    """Load and validate the saved anomaly model bundle."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(
            f"Anomaly model not found: {MODEL_PATH}"
        )

    saved = joblib.load(MODEL_PATH)

    if not isinstance(saved, dict):
        raise ValueError(
            "Invalid model bundle: expected a dictionary."
        )

    # Support both bundle formats used by this project.
    pipeline = saved.get("model", saved.get("pipeline"))

    if pipeline is None:
        raise ValueError(
            "Invalid model bundle: missing 'model' or 'pipeline'."
        )

    if not hasattr(pipeline, "predict"):
        raise ValueError(
            "The saved anomaly model does not support predict()."
        )

    columns = saved.get(
        "feature_columns",
        DEFAULT_FEATURE_COLUMNS,
    )

    if not isinstance(columns, (list, tuple)) or not columns:
        raise ValueError(
            "The model feature_columns configuration is invalid."
        )

    return {
        "pipeline": pipeline,
        "feature_columns": list(columns),
    }


def predict_anomalies(flows: list[dict]) -> list[dict]:
    """Return NORMAL/SUSPICIOUS predictions for network flows."""
    if not flows:
        return []

    model_data = load_model_data()
    pipeline = model_data["pipeline"]
    feature_columns = model_data["feature_columns"]

    frame = pd.DataFrame(flows)

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

    if features.isna().all(axis=1).any():
        bad_rows = features.index[
            features.isna().all(axis=1)
        ].tolist()

        raise ValueError(
            "Some flows have no usable numeric model features. "
            f"Flow indexes: {bad_rows[:10]}"
        )

    predictions = np.asarray(pipeline.predict(features))

    if len(predictions) != len(flows):
        raise ValueError(
            "The model returned an unexpected number of predictions."
        )

    if hasattr(pipeline, "decision_function"):
        raw_scores = np.asarray(
            pipeline.decision_function(features)
        ).reshape(-1)
        scores = -raw_scores
    elif hasattr(pipeline, "score_samples"):
        raw_scores = np.asarray(
            pipeline.score_samples(features)
        ).reshape(-1)
        scores = -raw_scores
    else:
        scores = np.full(len(flows), np.nan)

    results = []

    for index, (flow, prediction, score) in enumerate(
        zip(flows, predictions, scores)
    ):
        is_anomaly = int(prediction) == -1

        results.append({
            **flow,
            "flow_index": index,
            "anomaly": is_anomaly,
            "label": (
                "SUSPICIOUS" if is_anomaly else "NORMAL"
            ),
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

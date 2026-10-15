
from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = PROJECT_ROOT / "models" / "traffic_classifier.joblib"

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


class TrafficPredictionService:
    def __init__(self):
        self.model = None
        self.load_model()

    def load_model(self):
        if MODEL_PATH.exists():
            self.model = joblib.load(MODEL_PATH)
            print("Traffic classification model loaded successfully.")
        else:
            print(f"Model not found: {MODEL_PATH}")

    def predict(self, features: dict) -> dict:
        if self.model is None:
            raise RuntimeError("ML model is not loaded.")

        missing = [
            column
            for column in FEATURE_COLUMNS
            if column not in features
        ]

        if missing:
            raise ValueError(
                f"Missing required features: {', '.join(missing)}"
            )

        values = {
            column: float(features[column])
            for column in FEATURE_COLUMNS
        }

        if any(value < 0 for value in values.values()):
            raise ValueError("Features cannot be negative.")

        if values["duration"] == 0 and values["packet_count"] > 0:
            raise ValueError(
                "Duration must be greater than zero for non-empty traffic."
            )

        input_data = pd.DataFrame(
            [values],
            columns=FEATURE_COLUMNS,
        )

        prediction = self.model.predict(input_data)[0]

        result = {
            "prediction": str(prediction),
            "status": "success",
            "features_used": len(FEATURE_COLUMNS),
        }

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(input_data)[0]
            result["confidence"] = round(
                float(max(probabilities)), 4
            )

        return result


classifier = TrafficPredictionService()

from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[3]

MODEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "traffic_classifier.joblib"
)

LABEL_FILE = (
    PROJECT_ROOT
    / "models"
    / "label_encoder.joblib"
)


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


class TrafficClassifier:

    def __init__(self):

        if not MODEL_FILE.exists():
            raise FileNotFoundError(
                f"Model not found: {MODEL_FILE}"
            )

        if not LABEL_FILE.exists():
            raise FileNotFoundError(
                f"Label encoder not found: {LABEL_FILE}"
            )

        self.model = joblib.load(MODEL_FILE)
        self.label_encoder = joblib.load(LABEL_FILE)

    def predict(self, features: dict):

        missing = [
            column
            for column in FEATURE_COLUMNS
            if column not in features
        ]

        if missing:
            raise ValueError(
                f"Missing features: {missing}"
            )

        input_data = pd.DataFrame(
            [
                {
                    column: features[column]
                    for column in FEATURE_COLUMNS
                }
            ]
        )

        prediction = self.model.predict(input_data)[0]

        probabilities = self.model.predict_proba(
            input_data
        )[0]

        class_index = list(
            self.model.classes_
        ).index(prediction)

        confidence = float(
            probabilities[class_index]
        )

        label = self.label_encoder.inverse_transform(
            [prediction]
        )[0]

        return {
            "prediction": str(label),
            "confidence": round(confidence, 4),
        }


classifier = TrafficClassifier()
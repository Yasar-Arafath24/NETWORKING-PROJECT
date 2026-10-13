from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[3]
MODEL_PATH = PROJECT_ROOT / "models" / "traffic_classifier.joblib"
ENCODER_PATH = PROJECT_ROOT / "models" / "label_encoder.joblib"

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


class PredictionService:
    def __init__(self):
        self.model = None
        self.encoder = None
        self.load_model()

    def load_model(self):
        if MODEL_PATH.exists() and ENCODER_PATH.exists():
            self.model = joblib.load(MODEL_PATH)
            self.encoder = joblib.load(ENCODER_PATH)
            print("NetSentry AI: ML model loaded.")
        else:
            print("Warning: ML model files not found.")

    def predict_flow(self, flow: dict) -> dict:
        if self.model is None:
            raise RuntimeError(
                "Model not loaded. Train the model first."
            )

        features = {
            column: float(flow.get(column, 0))
            for column in FEATURE_COLUMNS
        }

        frame = pd.DataFrame([features], columns=FEATURE_COLUMNS)
        prediction = self.model.predict(frame)[0]

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(frame)[0]
            confidence = float(max(probabilities))
        else:
            confidence = None

        if self.encoder is not None:
            predicted_class = self.encoder.inverse_transform(
                [int(prediction)]
            )[0]
        else:
            predicted_class = str(prediction)

        return {
            "predicted_class": str(predicted_class),
            "confidence": confidence,
        }


prediction_service = PredictionService()
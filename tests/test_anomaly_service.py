
from pathlib import Path

import pytest

from ml.anomaly_service import MODEL_PATH, predict_anomalies


def test_empty_flows_return_empty_predictions():
    assert predict_anomalies([]) == []


def test_missing_model_is_reported(monkeypatch, tmp_path):
    missing_model = tmp_path / "missing_model.joblib"
    monkeypatch.setattr(
        "ml.anomaly_service.MODEL_PATH",
        missing_model,
    )

    with pytest.raises(FileNotFoundError):
        predict_anomalies([{"packet_count": 10}])


@pytest.mark.skipif(
    not MODEL_PATH.is_file(),
    reason="Train the anomaly model before running this test",
)
def test_prediction_count_matches_flow_count():
    import joblib

    artifact = joblib.load(MODEL_PATH)
    features = artifact["feature_columns"]

    # Synthetic values test the software contract, not detection accuracy.
    flow = {feature: 1.0 for feature in features}

    results = predict_anomalies([flow, flow.copy()])

    assert len(results) == 2

    for result in results:
        assert isinstance(result["anomaly"], bool)
        assert result["label"] in {"normal", "anomaly"}
        assert isinstance(result["anomaly_score"], float)

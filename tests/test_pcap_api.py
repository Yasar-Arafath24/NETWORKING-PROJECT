
from fastapi.testclient import TestClient

from backend.app.main import app
from tests.auth_helpers import authenticate_test_client

client = TestClient(app)
authenticate_test_client(client)


def test_pcap_analysis_rejects_missing_file():
    response = client.post("/api/v1/pcap/analyze")

    assert response.status_code in (400, 422)


def test_analysis_history_returns_valid_structure():
    response = client.get("/api/v1/monitoring/history")

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data["total_reports"], int)
    assert isinstance(data["reports"], list)


def test_pcap_analysis_enriches_flows_and_reports_suspicious_count(
    monkeypatch,
):
    from backend.app.api import routes
    from backend.app.services import pcap_service

    flows = [{"packet_count": 4}, {"packet_count": 8}]
    predictions = [
        {"anomaly": True, "label": "SUSPICIOUS", "anomaly_score": 0.5},
        {"anomaly": False, "label": "NORMAL", "anomaly_score": -0.2},
    ]
    monkeypatch.setattr(
        pcap_service,
        "analyze_pcap",
        lambda _: {
            "flows": flows,
            "total_packets": 12,
            "total_flows": len(flows),
        },
    )
    monkeypatch.setattr(
        routes,
        "predict_anomalies",
        lambda _: predictions,
    )
    monkeypatch.setattr(routes, "persist_analysis", lambda _response, _db, _owner_id: 1)
    monkeypatch.setattr(routes, "save_analysis", lambda _response: None)

    response = client.post(
        "/api/v1/pcap/analyze",
        files={
            "file": (
                "capture.pcap",
                b"\xd4\xc3\xb2\xa1",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["flows"][0]["anomaly"] is True
    assert data["flows"][0]["anomaly_score"] == 0.5
    assert data["flows"][1]["label"] == "NORMAL"
    assert data["suspicious_flows"] == 1
    assert data["anomalies_detected"] == 1
    assert data["anomaly_count"] == 1


def test_pcap_analysis_rejects_prediction_count_mismatch(monkeypatch):
    from backend.app.api import routes
    from backend.app.services import pcap_service

    flows = [{"packet_count": 4}, {"packet_count": 8}]
    monkeypatch.setattr(
        pcap_service,
        "analyze_pcap",
        lambda _: {
            "flows": flows,
            "total_packets": 12,
            "total_flows": len(flows),
        },
    )
    monkeypatch.setattr(
        routes,
        "predict_anomalies",
        lambda _: [{"anomaly": True}],
    )

    response = client.post(
        "/api/v1/pcap/analyze",
        files={
            "file": (
                "capture.pcap",
                b"\xd4\xc3\xb2\xa1",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "AI prediction count does not match flow count."
    )


def test_pcap_analysis_hides_internal_prediction_errors(monkeypatch):
    from backend.app.api import routes
    from backend.app.services import pcap_service

    monkeypatch.setattr(
        pcap_service,
        "analyze_pcap",
        lambda _: {
            "flows": [{"packet_count": 4}],
            "total_packets": 4,
            "total_flows": 1,
        },
    )

    def fail_prediction(_flows):
        raise RuntimeError("private-model-path-or-secret")

    monkeypatch.setattr(routes, "predict_anomalies", fail_prediction)
    response = client.post(
        "/api/v1/pcap/analyze",
        files={
            "file": (
                "capture.pcap",
                b"\xd4\xc3\xb2\xa1",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "PCAP analysis failed. Please verify the capture and try again."
    )
    assert "private-model-path-or-secret" not in response.text


def test_pcap_analysis_returns_zero_counts_for_empty_flows(monkeypatch):
    from backend.app.api import routes
    from backend.app.services import pcap_service

    def fail_if_predictions_run(_):
        raise AssertionError("Prediction should not run without flows.")

    monkeypatch.setattr(
        pcap_service,
        "analyze_pcap",
        lambda _: {
            "flows": [],
            "total_packets": 0,
            "total_flows": 0,
        },
    )
    monkeypatch.setattr(
        routes,
        "predict_anomalies",
        fail_if_predictions_run,
    )
    monkeypatch.setattr(routes, "persist_analysis", lambda _response, _db, _owner_id: 1)
    monkeypatch.setattr(routes, "save_analysis", lambda _response: None)

    response = client.post(
        "/api/v1/pcap/analyze",
        files={
            "file": (
                "capture.pcap",
                b"\xd4\xc3\xb2\xa1",
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["flows"] == []
    assert data["flows_returned"] == 0
    assert data["suspicious_flows"] == 0
    assert data["anomalies_detected"] == 0
    assert data["anomaly_count"] == 0

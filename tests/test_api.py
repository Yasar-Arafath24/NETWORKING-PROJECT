
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_root_health_alias():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_pcap_upload_alias_rejects_invalid_extension():
    response = client.post(
        "/api/v1/pcap/upload",
        files={"file": ("README.md", b"invalid capture")},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "Upload a .pcap or .pcapng file."


def test_system_info():
    response = client.get("/api/v1/system/info")

    assert response.status_code == 200
    assert response.json()["project"] == "NetSentry AI"


def test_prediction_rejects_missing_features():
    response = client.post(
        "/api/v1/predict",
        json={},
    )

    assert response.status_code == 422


def test_analysis_history_endpoint():
    response = client.get(
        "/api/v1/monitoring/history",
        params={"skip": 0, "limit": 20},
    )

    assert response.status_code == 200

    data = response.json()
    assert "total_reports" in data
    assert "reports" in data
    assert isinstance(data["reports"], list)


def test_analysis_history_rejects_invalid_limit():
    response = client.get(
        "/api/v1/monitoring/history",
        params={"limit": 101},
    )

    assert response.status_code == 422


def test_missing_report_returns_404():
    response = client.get(
        "/api/v1/monitoring/history/999999999",
    )

    assert response.status_code == 404


def test_live_flow_history_endpoint():
    response = client.get(
        "/api/v1/monitoring/history/flows",
        params={"limit": 20},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert isinstance(data["flows"], list)


def test_live_alert_history_endpoint():
    response = client.get(
        "/api/v1/monitoring/history/alerts",
        params={"limit": 20},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert isinstance(data["alerts"], list)


def test_live_detection_status_endpoint():
    response = client.get(
        "/api/v1/monitoring/live/detection-status",
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "detection" in data

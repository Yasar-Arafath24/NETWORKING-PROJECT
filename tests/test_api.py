
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


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

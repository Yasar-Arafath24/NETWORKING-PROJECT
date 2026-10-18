
from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_pcap_analysis_rejects_missing_file():
    response = client.post("/api/v1/pcap/analyze")

    assert response.status_code in (400, 422)


def test_analysis_history_returns_valid_structure():
    response = client.get("/api/v1/monitoring/history")

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data["total_reports"], int)
    assert isinstance(data["reports"], list)


from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app
from tests.auth_helpers import authenticate_test_client

client = TestClient(app)
authenticate_test_client(client)


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


def test_prediction_hides_internal_model_errors(monkeypatch):
    from backend.app.services import prediction_service

    def fail_prediction(_features):
        raise RuntimeError("private-model-path-or-secret")

    monkeypatch.setattr(prediction_service, "predict", fail_prediction)
    response = client.post(
        "/api/v1/predict",
        json={
            "packet_count": 1,
            "total_bytes": 60,
            "duration": 1,
            "packet_rate": 1,
            "byte_rate": 60,
            "average_packet_size": 60,
            "min_packet_size": 60,
            "max_packet_size": 60,
            "forward_packets": 1,
            "backward_packets": 0,
            "forward_bytes": 60,
            "backward_bytes": 0,
        },
    )

    assert response.status_code == 500
    assert response.json()["detail"] == (
        "Traffic prediction failed. Please try again later."
    )
    assert "private-model-path-or-secret" not in response.text


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


def test_pcap_replay_accepts_datasets_relative_and_prefixed_paths(monkeypatch):
    from backend.app.services import live_detection, live_monitor

    started = []
    monkeypatch.setattr(
        live_monitor.monitor,
        "start_replay",
        lambda **kwargs: started.append(kwargs),
    )
    monkeypatch.setattr(live_detection.live_detection, "start", lambda: None)

    for pcap_path in (
        "samples/netsentry_sample.pcap",
        "datasets/samples/netsentry_sample.pcap",
    ):
        response = client.post(
            "/api/v1/monitoring/live/replay",
            json={"pcap_path": pcap_path, "speed": 100},
        )

        assert response.status_code == 200, response.text

    expected_path = str(
        Path(__file__).resolve().parents[1]
        / "datasets"
        / "samples"
        / "netsentry_sample.pcap"
    )
    assert [call["pcap_path"] for call in started] == [expected_path, expected_path]


def test_pcap_replay_rejects_paths_outside_datasets():
    response = client.post(
        "/api/v1/monitoring/live/replay",
        json={"pcap_path": "../README.md", "speed": 1},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == (
        "PCAP replay is restricted to the project datasets directory."
    )


def test_pcap_replay_rejects_invalid_extension_and_missing_file():
    invalid_extension = client.post(
        "/api/v1/monitoring/live/replay",
        json={"pcap_path": "README.md", "speed": 1},
    )
    missing_file = client.post(
        "/api/v1/monitoring/live/replay",
        json={"pcap_path": "samples/does-not-exist.pcap", "speed": 1},
    )

    assert invalid_extension.status_code == 400
    assert "must have a .pcap or .pcapng" in invalid_extension.json()["detail"]
    assert missing_file.status_code == 404
    assert "not found" in missing_file.json()["detail"]


def test_pcap_replay_processes_a_real_sample_capture(monkeypatch):
    from backend.app.services import live_detection, live_monitor
    from backend.app.services.live_monitor import LiveMonitor

    monitor = LiveMonitor()
    monkeypatch.setattr(live_monitor, "monitor", monitor)
    monkeypatch.setattr(live_detection.live_detection, "start", lambda: None)

    response = client.post(
        "/api/v1/monitoring/live/replay",
        json={
            "pcap_path": "datasets/samples/netsentry_sample.pcap",
            "speed": 100,
        },
    )

    assert response.status_code == 200, response.text
    monitor._thread.join(timeout=5)
    status = monitor.status()
    assert status["running"] is False
    assert status["error"] is None
    assert status["total_packets"] > 0
    assert monitor.get_flows()

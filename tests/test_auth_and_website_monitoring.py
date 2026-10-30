from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.api import website_routes
from backend.app.models.analysis import AnalysisReport
from backend.app.models.live_monitoring import LiveFlowRecord, NetworkAlert
from backend.app.models.user import User
from backend.app.services.database import Base, get_db
from tests.auth_helpers import register_and_verify


def _client_with_account(email=None):
    client = TestClient(app)
    result = register_and_verify(client, {
        "name": "Monitor User",
        "email": email or f"monitor-{uuid4().hex}@gmail.com",
        "password": "SecurePass1234",
    })
    assert result.status_code == 200, result.text
    client.headers.update({"X-CSRF-Token": client.cookies.get("netsentry_csrf")})
    return client


def test_website_collector_connection_state_uses_ingestion_age_and_revocation():
    now = datetime.now(timezone.utc)
    assert website_routes._connection_state(True, None, now) == "NOT_CONFIGURED"
    assert website_routes._connection_state(True, now - timedelta(seconds=2), now) == "RECEIVING"
    assert website_routes._connection_state(True, now - timedelta(minutes=1), now) == "CONNECTED"
    assert website_routes._connection_state(True, now - timedelta(minutes=5), now) == "DISCONNECTED"
    assert website_routes._connection_state(True, None, now, collector_status="RUNNING", collector_last_seen=now) == "CONNECTED"
    assert website_routes._connection_state(True, None, now, collector_status="ERROR", collector_last_seen=now) == "ERROR"
    assert website_routes._connection_state(True, now - timedelta(seconds=2), now, collector_status="STOPPED", collector_last_seen=now) == "DISCONNECTED"
    assert website_routes._connection_state(False, now, now) == "DISCONNECTED"
    assert website_routes._connection_state(False, now, now, revoked_at=now) == "REVOKED"


def test_registration_rejects_non_gmail_and_normalizes_gmail():
    client = TestClient(app)
    invalid = client.post("/api/v1/auth/register", json={
        "name": "Monitor User", "email": "user@example.org", "password": "SecurePass1234",
    })
    assert invalid.status_code == 422
    valid = register_and_verify(client, {
        "name": "Monitor User", "email": f"  Monitor-{uuid4().hex}@GMAIL.COM  ", "password": "SecurePass1234",
    })
    assert valid.status_code == 200, valid.text
    assert valid.json()["user"]["email"].endswith("@gmail.com")


def test_website_telemetry_is_owner_scoped_and_filterable(monkeypatch):
    website_routes._rotation_times.clear()
    website_routes._ingest_times.clear()
    website_routes._health_times.clear()
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setenv("NETSENTRY_SITE_INGEST_PER_MINUTE", "20")
    try:
        owner = _client_with_account()
        other = _client_with_account()
        created = owner.post("/api/v1/websites", json={
            "name": "Authorized Test Site", "url": "https://monitor.example.test/",
            "platform": "nginx",
            "authorization_confirmed": True,
        })
        assert created.status_code == 201, created.text
        website = created.json()
        assert website["platform"] == "nginx"
        duplicate = owner.post("/api/v1/websites", json={
            "name": "Duplicate Site", "url": "https://monitor.example.test/",
            "authorization_confirmed": True,
        })
        assert duplicate.status_code == 409
        waiting = owner.get("/api/v1/websites").json()["websites"][0]
        assert waiting["integration_status"] == "NOT_CONFIGURED"
        assert waiting["total_events"] == 0
        initial_connection = owner.get(f"/api/v1/websites/{website['id']}/status")
        assert initial_connection.status_code == 200
        assert initial_connection.json()["status"] == "NOT_CONFIGURED"
        assert initial_connection.json()["verified"] is False
        empty_test = owner.post(f"/api/v1/websites/{website['id']}/test-connection")
        assert empty_test.status_code == 200
        assert empty_test.json()["verified"] is False
        assert "No authenticated event" in empty_test.json()["message"]
        paused = owner.patch(f"/api/v1/websites/{website['id']}?enabled=false")
        assert paused.status_code == 200
        assert owner.get(f"/api/v1/websites/{website['id']}/status").json()["status"] == "DISCONNECTED"
        resumed = owner.patch(f"/api/v1/websites/{website['id']}?enabled=true")
        assert resumed.status_code == 200
        platform_update = owner.patch(f"/api/v1/websites/{website['id']}?platform=nodejs")
        assert platform_update.status_code == 200
        assert platform_update.json()["platform"] == "nodejs"
        assert platform_update.json()["integration_method"] == "nodejs_jsonl"
        bad_method = owner.patch(f"/api/v1/websites/{website['id']}?platform=nginx&integration_method=fastapi_jsonl")
        assert bad_method.status_code == 422
        assert other.patch(f"/api/v1/websites/{website['id']}?platform=python").status_code == 404
        original_token = website["ingest_token"]
        rotated = owner.post(f"/api/v1/websites/{website['id']}/rotate-token")
        assert rotated.status_code == 200, rotated.text
        website = rotated.json()
        assert website["ingest_token"] != original_token
        health_url = f"/api/v1/website-ingest/{website['id']}/health"
        unauthenticated_health = owner.post(health_url, json={"status": "RUNNING"})
        assert unauthenticated_health.status_code == 401
        running_health = owner.post(health_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={"status": "RUNNING"})
        assert running_health.status_code == 202
        assert running_health.json()["status"] == "RUNNING"
        connected_without_events = owner.get(f"/api/v1/websites/{website['id']}/status").json()
        assert connected_without_events["status"] == "CONNECTED"
        assert connected_without_events["verified"] is False
        error_health = owner.post(health_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={"status": "ERROR", "error": "Log path denied"})
        assert error_health.status_code == 202
        error_status = owner.get(f"/api/v1/websites/{website['id']}/status").json()
        assert error_status["status"] == "ERROR"
        assert error_status["latest_ingestion_error"] == "Log path denied"
        cleared_health = owner.post(health_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={"status": "RUNNING"})
        assert cleared_health.status_code == 202
        forbidden_rotation = other.post(f"/api/v1/websites/{website['id']}/rotate-token")
        assert forbidden_rotation.status_code == 404
        event_url = f"/api/v1/website-ingest/{website['id']}/events"
        old_key_event = owner.post(event_url, headers={"Authorization": f"Bearer {original_token}"}, json={
            "method": "GET", "path": "/old-key", "status_code": 200,
        })
        assert old_key_event.status_code == 401
        website_routes._ingest_times.clear()
        for status, path in ((404, "/missing"), (500, "/server-error")):
            response = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
                "method": "GET", "path": path, "status_code": status,
                "event_id": f"fixture-{path.lstrip('/').replace('/', '-')}",
                "request_timestamp": "2026-10-29T10:00:00Z",
            })
            assert response.status_code == 202, response.text
        duplicate_event = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
            "method": "GET", "path": "/missing", "status_code": 404,
            "event_id": "fixture-missing",
        })
        assert duplicate_event.status_code == 202
        assert duplicate_event.json()["duplicate"] is True

        limited = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
            "method": "GET", "path": "/third-request", "status_code": 200,
        })
        assert limited.status_code == 202

        probe = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
            "method": "GET", "path": "/.env", "status_code": 200,
        })
        assert probe.status_code == 202
        detected = probe.json()["event"]
        assert detected["severity"] == "HEURISTIC"
        assert detected["classification"] == "SUSPICIOUS"
        assert detected["risk_score"] == 55
        assert detected["risk_severity"] == "HIGH"
        assert detected["detection_categories"] == ["sensitive_path"]
        assert "sensitive path" in detected["detection_reasons"][0]["message"]
        assert detected["ml_status"] == "unavailable_incompatible_features"
        detected_filter = owner.get(f"/api/v1/websites/{website['id']}/events", params={"classification": "suspicious", "severity": "HIGH"})
        assert detected_filter.status_code == 200
        assert detected_filter.json()["total"] == 1

        repeated_probe = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
            "method": "GET", "path": "/.env", "status_code": 404,
        })
        assert repeated_probe.status_code == 202
        site_alerts = owner.get(f"/api/v1/websites/{website['id']}/alerts")
        assert site_alerts.status_code == 200
        assert site_alerts.json()["total"] == 1
        alert = site_alerts.json()["alerts"][0]
        assert alert["related_event_count"] == 2
        assert alert["risk_score"] == 55
        assert other.patch(f"/api/v1/websites/{website['id']}/alerts/{alert['id']}", json={"status": "RESOLVED"}).status_code == 404
        updated_alert = owner.patch(f"/api/v1/websites/{website['id']}/alerts/{alert['id']}", json={"status": "INVESTIGATING"})
        assert updated_alert.status_code == 200
        assert updated_alert.json()["status"] == "INVESTIGATING"
        alert_detail = owner.get(f"/api/v1/websites/{website['id']}/alerts/{alert['id']}")
        assert alert_detail.status_code == 200
        assert alert_detail.json()["status_history"][0]["new_status"] == "INVESTIGATING"
        analytics = owner.get("/api/v1/websites/analytics", params={"site_id": website["id"]})
        assert analytics.status_code == 200
        assert analytics.json()["suspicious_count"] == 2
        assert analytics.json()["ml_status"] == "unavailable_incompatible_features"
        listed_site = owner.get("/api/v1/websites").json()["websites"][0]
        assert listed_site["integration_status"] == "RECEIVING"
        assert listed_site["total_events"] == 5
        assert listed_site["anomaly_count"] == 2
        assert listed_site["last_event_received"]

        tested_connection = owner.post(f"/api/v1/websites/{website['id']}/test-connection")
        assert tested_connection.status_code == 200
        assert tested_connection.json()["verified"] is True
        assert tested_connection.json()["status"] == "RECEIVING"
        assert tested_connection.json()["total_events"] == 5
        assert tested_connection.json()["anomaly_count"] == 2
        assert tested_connection.json()["requests_per_minute"] == 5
        assert other.get(f"/api/v1/websites/{website['id']}/status").status_code == 404
        assert other.post(f"/api/v1/websites/{website['id']}/test-connection").status_code == 404

        monkeypatch.setenv("NETSENTRY_SITE_INGEST_PER_MINUTE", "3")
        rate_limited = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
            "method": "GET", "path": "/rate-limited", "status_code": 200,
        })
        assert rate_limited.status_code == 429

        results = owner.get(f"/api/v1/websites/{website['id']}/events", params={
            "status_code": 404, "search": "missing", "limit": 1,
            "since": (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        })
        assert results.status_code == 200, results.text
        data = results.json()
        assert data["total"] == 1
        assert data["events"][0]["status_code"] == 404
        assert data["events"][0]["severity"] == "INFO"
        assert data["events"][0]["detection_status"] == "unassessed"
        assert data["summary"]["status_distribution"]["4xx"] == 2
        assert data["summary"]["status_distribution"]["5xx"] == 1

        owner_alerts = owner.get("/api/v1/monitoring/history/alerts").json()["alerts"]
        website_alerts = [alert for alert in owner_alerts if alert.get("event_type") == "website_traffic"]
        assert len(website_alerts) == 1
        assert website_alerts[0]["site_name"] == "Authorized Test Site"
        assert website_alerts[0]["request_path"] == "/.env"

        revoked = owner.post(f"/api/v1/websites/{website['id']}/revoke-token")
        assert revoked.status_code == 200
        assert revoked.json()["status"] == "REVOKED"
        assert "ingest_token" not in revoked.json()["site"]
        revoked_status = owner.get(f"/api/v1/websites/{website['id']}/status").json()
        assert revoked_status["status"] == "REVOKED"
        assert revoked_status["verified"] is True
        rejected_revoked_key = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
            "method": "GET", "path": "/revoked", "status_code": 200,
        })
        assert rejected_revoked_key.status_code == 401
        renewed = owner.post(f"/api/v1/websites/{website['id']}/rotate-token")
        assert renewed.status_code == 200
        assert renewed.json()["enabled"] is True

        unauthorized = other.get(f"/api/v1/websites/{website['id']}/events")
        assert unauthorized.status_code == 404
        assert other.get("/api/v1/monitoring/history/alerts").json()["alerts"] == []
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_historical_traffic_analytics_filters_saved_pcap_flows_and_is_owner_scoped():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        owner = _client_with_account()
        other = _client_with_account()
        with session_factory() as db:
            owner_user = db.query(User).filter(User.email == owner.get("/api/v1/auth/me").json()["user"]["email"]).one()
            other_user = db.query(User).filter(User.email == other.get("/api/v1/auth/me").json()["user"]["email"]).one()
            now = datetime.now(timezone.utc)
            db.add_all([
                AnalysisReport(owner_id=owner_user.id, total_packets=5, total_flows=2, created_at=now, report_data={
                    "flows": [
                        {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "src_port": 51515, "dst_port": 443, "protocol": "TCP", "packet_count": 3, "total_bytes": 300, "duration": 2, "label": "NORMAL"},
                        {"src_ip": "10.0.0.3", "dst_ip": "10.0.0.4", "src_port": 53000, "dst_port": 53, "protocol": "UDP", "packet_count": 2, "total_bytes": 100, "duration": 4, "label": "SUSPICIOUS"},
                    ],
                }),
                AnalysisReport(owner_id=other_user.id, total_packets=99, total_flows=8, created_at=now, report_data={
                    "flows": [{"src_ip": "192.0.2.1", "dst_ip": "192.0.2.2", "protocol": "TCP", "packet_count": 99, "total_bytes": 9900}],
                }),
            ])
            db.commit()

        result = owner.get("/api/v1/monitoring/traffic-analytics")
        assert result.status_code == 200, result.text
        data = result.json()
        assert data["total_packets"] == 5
        assert data["total_flows"] == 2
        assert data["total_bytes"] == 400
        assert data["total_matching_records"] == 2
        assert data["protocol_distribution"] == {"TCP": 1, "UDP": 1}
        assert data["transport_distribution"]["TCP"] == 1
        assert data["transport_distribution"]["UDP"] == 1
        assert {flow["src_ip"] for flow in data["flows"]} == {"10.0.0.1", "10.0.0.3"}

        filtered = owner.get("/api/v1/monitoring/traffic-analytics", params={"protocol": "tcp", "search": "10.0.0.1", "limit": 1})
        assert filtered.status_code == 200, filtered.text
        filtered_data = filtered.json()
        assert filtered_data["total_matching_records"] == 1
        assert filtered_data["total_flows"] == 1
        assert filtered_data["total_packets"] == 3
        assert filtered_data["flows"][0]["dst_port"] == 443

        private = other.get("/api/v1/monitoring/traffic-analytics")
        assert private.status_code == 200, private.text
        assert private.json()["total_packets"] == 99
        assert private.json()["total_flows"] == 8
        assert private.json()["flows"][0]["src_ip"] == "192.0.2.1"

        invalid_range = owner.get("/api/v1/monitoring/traffic-analytics", params={
            "since": "2026-10-30T12:00:00Z", "until": "2026-10-29T12:00:00Z",
        })
        assert invalid_range.status_code == 422
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_latest_analysis_and_live_history_are_private_to_the_owner():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        owner = _client_with_account()
        other = _client_with_account()
        owner_id = owner.get("/api/v1/auth/me").json()["user"]["id"]
        with session_factory() as db:
            db.add(AnalysisReport(owner_id=owner_id, total_packets=12, total_flows=1, report_data={"flows": [{"label": "SUSPICIOUS", "anomaly": True}], "suspicious_flows": 1}))
            db.add(LiveFlowRecord(owner_id=owner_id, session_id="owner-session", flow_id=1, src_ip="192.0.2.1", dst_ip="198.51.100.2", src_port=1234, dst_port=443, protocol="TCP", packet_count=2, total_bytes=150, duration=1.0, anomaly=True, label="SUSPICIOUS", features={}))
            db.add(NetworkAlert(owner_id=owner_id, session_id="owner-session", flow_id=1, severity="MEDIUM", title="Test alert", description="Owner private alert", anomaly_score=0.3, flow_data={}))
            db.commit()

        latest = owner.get("/api/v1/monitoring/latest")
        assert latest.status_code == 200
        assert latest.json()["flows"][0]["label"] == "SUSPICIOUS"
        assert other.get("/api/v1/monitoring/latest").status_code == 404
        assert len(owner.get("/api/v1/monitoring/history/flows").json()["flows"]) == 1
        assert other.get("/api/v1/monitoring/history/flows").json()["flows"] == []
        assert len(owner.get("/api/v1/monitoring/history/alerts").json()["alerts"]) == 1
        assert other.get("/api/v1/monitoring/history/alerts").json()["alerts"] == []
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()

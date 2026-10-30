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
            "authorization_confirmed": True,
        })
        assert created.status_code == 201, created.text
        website = created.json()
        event_url = f"/api/v1/website-ingest/{website['id']}/events"
        website_routes._ingest_times.clear()
        for status, path in ((404, "/missing"), (500, "/server-error")):
            response = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
                "method": "GET", "path": path, "status_code": status,
                "request_timestamp": "2026-10-29T10:00:00Z",
            })
            assert response.status_code == 202, response.text

        limited = owner.post(event_url, headers={"Authorization": f"Bearer {website['ingest_token']}"}, json={
            "method": "GET", "path": "/third-request", "status_code": 200,
        })
        assert limited.status_code == 202

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
        assert data["summary"]["status_distribution"]["4xx"] == 1
        assert data["summary"]["status_distribution"]["5xx"] == 1

        unauthorized = other.get(f"/api/v1/websites/{website['id']}/events")
        assert unauthorized.status_code == 404
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

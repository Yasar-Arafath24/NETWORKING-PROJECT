from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api.website_routes import WebsiteEventInput
from backend.app.models.website_monitor import WebsiteTrafficEvent
from backend.app.services.database import Base
from backend.app.services.website_detection import analyze_website_event


def _event(site_id, path, method="GET", status=200, source="203.0.113.4", duration=1, ua=""):
    return WebsiteTrafficEvent(
        site_id=site_id, request_path=path, method=method, status_code=status,
        duration_ms=duration, response_bytes=0, source_ip=source, user_agent=ua,
        severity="INFO", reason="", event_data={},
        created_at=datetime.now(timezone.utc),
    )


def test_website_rules_cover_normal_probe_scan_login_rate_errors_slow_method_and_user_agent(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    try:
        with Session() as db:
            normal = analyze_website_event(db, 1, WebsiteEventInput(path="/missing", status_code=404))
            assert normal["classification"] == "NORMAL"
            assert normal["risk_score"] == 0

            probe = analyze_website_event(db, 1, WebsiteEventInput(path="/.env", status_code=404, source_ip="203.0.113.4"))
            assert probe["categories"] == ["sensitive_path"]
            assert probe["risk_score"] == 55
            assert probe["severity"] == "HIGH"

            db.add_all([_event(2, "/.env"), _event(2, "/admin")])
            db.flush()
            scan = analyze_website_event(db, 2, WebsiteEventInput(path="/backup.zip", status_code=404, source_ip="203.0.113.4"))
            assert "directory_scan" in scan["categories"]
            assert "distinct sensitive paths" in next(r["message"] for r in scan["reasons"] if r["category"] == "directory_scan")

            db.add_all([_event(3, "/login", "POST", 401) for _ in range(4)])
            db.flush()
            brute_force = analyze_website_event(db, 3, WebsiteEventInput(path="/login", method="POST", status_code=401, source_ip="203.0.113.4"))
            assert "auth_bruteforce" in brute_force["categories"]

            monkeypatch.setenv("NETSENTRY_WEBSITE_SOURCE_RPM", "2")
            db.add(_event(4, "/", source="192.0.2.44"))
            db.flush()
            rate = analyze_website_event(db, 4, WebsiteEventInput(path="/", status_code=200, source_ip="192.0.2.44"))
            assert "request_rate" in rate["categories"]
            monkeypatch.delenv("NETSENTRY_WEBSITE_SOURCE_RPM")

            monkeypatch.setenv("NETSENTRY_WEBSITE_ERROR_BURST", "3")
            db.add_all([_event(5, "/api", status=500) for _ in range(2)])
            db.flush()
            server_errors = analyze_website_event(db, 5, WebsiteEventInput(path="/api", status_code=500, source_ip="203.0.113.4"))
            assert "server_error_burst" in server_errors["categories"]
            assert "not by itself an attack verdict" in next(r["message"] for r in server_errors["reasons"] if r["category"] == "server_error_burst")

            monkeypatch.setenv("NETSENTRY_WEBSITE_SLOW_MS", "1000")
            monkeypatch.setenv("NETSENTRY_WEBSITE_SLOW_REPEAT", "3")
            db.add_all([_event(6, "/slow", duration=1200) for _ in range(2)])
            db.flush()
            slow = analyze_website_event(db, 6, WebsiteEventInput(path="/slow", status_code=200, duration_ms=1500, source_ip="203.0.113.4"))
            assert "slow_request_burst" in slow["categories"]

            unusual_method = analyze_website_event(db, 7, WebsiteEventInput(path="/", method="TRACE", status_code=200))
            assert "unusual_method" in unusual_method["categories"]

            scanner = analyze_website_event(db, 8, WebsiteEventInput(path="/", status_code=200, user_agent="Nmap Scripting Engine"))
            assert "scanner_user_agent" in scanner["categories"]
            assert scanner["classification"] == "SUSPICIOUS"
            assert scanner["ml_status"] == "unavailable_incompatible_features"
    finally:
        engine.dispose()

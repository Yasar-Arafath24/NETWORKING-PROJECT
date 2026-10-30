import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen
from uuid import uuid4

import uvicorn
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api import website_routes
from backend.app.main import app
from backend.app.services.database import Base, get_db
from scripts import generic_traffic_collector as collector
from tests.auth_helpers import register_and_verify


def test_real_local_http_log_collector_ingestion_detection_and_isolation(tmp_path: Path):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    website_routes._rotation_times.clear()
    website_routes._ingest_times.clear()
    website_routes._health_times.clear()
    log_path = tmp_path / "site-access.jsonl"
    write_lock = threading.Lock()

    class SiteHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            status = 404 if self.path.split("?", 1)[0] == "/.env" else 200
            record = {
                "request_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "method": "GET", "path": self.path.split("?", 1)[0],
                "status_code": status, "duration_ms": 2.5, "response_bytes": 0,
                "source_ip": self.client_address[0], "user_agent": self.headers.get("User-Agent", ""),
            }
            with write_lock, log_path.open("a", encoding="utf-8") as log:
                log.write(json.dumps(record) + "\n")
                log.flush()
            self.send_response(status)
            self.end_headers()

        def log_message(self, *_args):
            pass

    website_server = ThreadingHTTPServer(("127.0.0.1", 0), SiteHandler)
    website_thread = threading.Thread(target=website_server.serve_forever, daemon=True)
    website_thread.start()

    api_socket = socket.socket()
    api_socket.bind(("127.0.0.1", 0))
    api_port = api_socket.getsockname()[1]
    api_socket.close()
    api_server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="critical", access_log=False))
    api_thread = threading.Thread(target=api_server.run, daemon=True)
    collector_thread = None
    collector_errors = []
    try:
        api_thread.start()
        deadline = time.time() + 10
        while not api_server.started and time.time() < deadline:
            time.sleep(0.05)
        assert api_server.started, "test FastAPI server did not start"
    
        owner = TestClient(app)
        verified = register_and_verify(owner, {
            "name": "E2E owner", "email": f"e2e-{uuid4().hex}@gmail.com", "password": "SecurePass1234",
        })
        assert verified.status_code == 200, verified.text
        owner.headers.update({"X-CSRF-Token": owner.cookies.get("netsentry_csrf")})
        website = owner.post("/api/v1/websites", json={
            "name": "Local E2E website", "url": f"http://127.0.0.1:{website_server.server_port}",
            "platform": "custom", "authorization_confirmed": True,
        })
        assert website.status_code == 201, website.text
        site = website.json()
        token = site["ingest_token"]
        site_id = site["id"]
        assert site["collector_process_status"] == "NOT_CONFIGURED"
    
        with pytest.raises(HTTPError) as not_found:
            urlopen(f"http://127.0.0.1:{website_server.server_port}/.env", timeout=3)
        assert not_found.value.code == 404
    
        def run_collector():
            try:
                collector.tail_file(str(log_path), f"http://127.0.0.1:{api_port}", site_id, token,
                                    "jsonl", 3, 1, 0.05, True)
            except Exception as exc:  # Surface background failures in the main test thread.
                collector_errors.append(exc)

        collector.running = True
        collector_thread = threading.Thread(target=run_collector, daemon=True)
        collector_thread.start()
        deadline = time.time() + 10
        status = {}
        while time.time() < deadline:
            status = owner.get(f"/api/v1/websites/{site_id}/status").json()
            if status.get("total_events", 0) >= 1:
                break
            time.sleep(0.1)
        assert not collector_errors, collector_errors
        assert status["total_events"] == 1
        assert status["anomaly_count"] == 1
        assert status["verified"] is True
        assert status["requests_per_minute"] == 1
        listed = owner.get(f"/api/v1/websites/{site_id}/events", params={"classification": "suspicious"}).json()
        assert listed["total"] == 1
        assert listed["events"][0]["path"] == "/.env"
        assert listed["events"][0]["source_ip"] == "127.0.0.1"
        alerts = owner.get(f"/api/v1/websites/{site_id}/alerts").json()
        assert alerts["total"] == 1

        collector.running = False
        collector_thread.join(timeout=3)
        assert not collector_thread.is_alive()

        # A collector restart replays the same file record; its stable ID prevents a duplicate count.
        collector.running = True
        collector_thread = threading.Thread(target=run_collector, daemon=True)
        collector_thread.start()
        time.sleep(0.4)
        collector.running = False
        collector_thread.join(timeout=3)
        assert not collector_thread.is_alive()
        assert not collector_errors, collector_errors
        assert owner.get(f"/api/v1/websites/{site_id}/status").json()["total_events"] == 1

        bad_token = owner.post(f"/api/v1/website-ingest/{site_id}/events", headers={
            "Authorization": "Bearer not-the-site-token",
        }, json={"method": "GET", "path": "/test", "status_code": 200})
        assert bad_token.status_code == 401
        assert bad_token.json()["detail"]["code"] == "TOKEN_INVALID"

        other = TestClient(app)
        other_verified = register_and_verify(other, {
            "name": "Other E2E user", "email": f"e2e-other-{uuid4().hex}@gmail.com", "password": "SecurePass1234",
        })
        assert other_verified.status_code == 200
        other.headers.update({"X-CSRF-Token": other.cookies.get("netsentry_csrf")})
        assert other.get(f"/api/v1/websites/{site_id}/events").status_code == 404
        assert other.get(f"/api/v1/websites/{site_id}/alerts").status_code == 404

        revoked = owner.post(f"/api/v1/websites/{site_id}/revoke-token")
        assert revoked.status_code == 200
        revoked_event = owner.post(f"/api/v1/website-ingest/{site_id}/events", headers={
            "Authorization": f"Bearer {token}",
        }, json={"method": "GET", "path": "/after-revoke", "status_code": 200})
        assert revoked_event.status_code == 401
        assert owner.get(f"/api/v1/websites/{site_id}/status").json()["status"] == "REVOKED"
    finally:
        collector.running = False
        if collector_thread and collector_thread.is_alive():
            collector_thread.join(timeout=3)
        api_server.should_exit = True
        if api_thread.is_alive():
            api_thread.join(timeout=5)
        website_server.shutdown()
        website_server.server_close()
        website_thread.join(timeout=3)
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()

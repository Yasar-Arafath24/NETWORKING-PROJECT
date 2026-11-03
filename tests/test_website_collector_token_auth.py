import hashlib
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api import website_routes
from backend.app.main import app
from backend.app.models.website_monitor import MonitoredWebsite
from backend.app.services.database import Base, get_db
from tests.auth_helpers import authenticate_test_client


def test_site_seven_rotated_collector_token_is_bound_to_site_and_revocable():
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
    try:
        owner = TestClient(app)
        owner_id = authenticate_test_client(owner)
        with session_factory() as db:
            for site_id in range(1, 7):
                db.add(MonitoredWebsite(
                    id=site_id,
                    owner_id=owner_id,
                    name=f"Existing site {site_id}",
                    url=f"https://existing-{site_id}.example.test",
                    token_hash=hashlib.sha256(f"existing-key-{site_id}".encode()).hexdigest(),
                    authorization_confirmed=True,
                ))
            db.commit()

        website = owner.post("/api/v1/websites", json={
            "name": "Site seven",
            "url": f"https://site-seven-{uuid4().hex}.example.test",
            "platform": "python",
            "integration_method": "fastapi_jsonl",
            "authorization_confirmed": True,
        })
        assert website.status_code == 201, website.text
        site_seven = website.json()
        assert site_seven["id"] == 7
        original_key = site_seven["ingest_token"]
        with session_factory() as db:
            row = db.query(MonitoredWebsite).filter_by(id=7).one()
            assert row.token_hash == hashlib.sha256(original_key.encode()).hexdigest()

        rotated = owner.post("/api/v1/websites/7/rotate-token")
        assert rotated.status_code == 200, rotated.text
        rotated_site = rotated.json()
        assert rotated_site["id"] == 7
        current_key = rotated_site["ingest_token"]
        assert current_key != original_key
        with session_factory() as db:
            row = db.query(MonitoredWebsite).filter_by(id=7).one()
            assert row.token_hash == hashlib.sha256(current_key.encode()).hexdigest()
            assert row.collector_revoked_at is None

        stale_key = owner.post("/api/v1/website-ingest/7/events", headers={
            "Authorization": f"Bearer {original_key}",
        }, json={"method": "GET", "path": "/stale", "status_code": 200})
        assert stale_key.status_code == 401

        second = owner.post("/api/v1/websites", json={
            "name": "Site eight",
            "url": f"https://site-eight-{uuid4().hex}.example.test",
            "platform": "python",
            "integration_method": "fastapi_jsonl",
            "authorization_confirmed": True,
        })
        assert second.status_code == 201, second.text
        site_eight = second.json()
        assert site_eight["id"] == 8
        second_key = site_eight["ingest_token"]

        site_seven_events = "/api/v1/website-ingest/7/events"
        site_eight_events = "/api/v1/website-ingest/8/events"
        payload = {"method": "GET", "path": "/", "status_code": 200}

        valid = owner.post(site_seven_events, headers={
            "Authorization": f"Bearer {current_key}",
        }, json=payload)
        assert valid.status_code == 202, valid.text

        invalid = owner.post(site_seven_events, headers={
            "Authorization": "Bearer definitely-not-a-valid-key",
        }, json=payload)
        assert invalid.status_code == 401
        assert invalid.json()["detail"]["code"] == "TOKEN_INVALID"

        wrong_site = owner.post(site_eight_events, headers={
            "Authorization": f"Bearer {current_key}",
        }, json=payload)
        assert wrong_site.status_code == 401
        assert wrong_site.json()["detail"]["code"] == "TOKEN_INVALID"

        valid_second_site = owner.post(site_eight_events, headers={
            "Authorization": f"bEaReR {second_key}",
        }, json=payload)
        assert valid_second_site.status_code == 202, valid_second_site.text

        assert all(
            "ingest_token" not in site
            for site in owner.get("/api/v1/websites").json()["websites"]
        )

        other = TestClient(app)
        authenticate_test_client(other)
        assert other.post("/api/v1/websites/7/rotate-token").status_code == 404

        revoked = owner.post("/api/v1/websites/7/revoke-token")
        assert revoked.status_code == 200
        rejected_revoked = owner.post(site_seven_events, headers={
            "Authorization": f"Bearer {current_key}",
        }, json=payload)
        assert rejected_revoked.status_code == 401
        assert rejected_revoked.json()["detail"]["code"] == "TOKEN_INVALID"

        regenerated = owner.post("/api/v1/websites/7/rotate-token")
        assert regenerated.status_code == 200
        regenerated_key = regenerated.json()["ingest_token"]
        assert regenerated.json()["id"] == 7
        accepted_after_regeneration = owner.post(site_seven_events, headers={
            "Authorization": f"Bearer {regenerated_key}",
        }, json=payload)
        assert accepted_after_regeneration.status_code == 202
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()

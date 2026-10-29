from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api import auth_routes
from backend.app.main import app
from backend.app.models.user import User
from backend.app.services.database import Base, get_db


@pytest.fixture
def google_client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "netsentry-test-client-id.apps.googleusercontent.com")
    try:
        with TestClient(app) as client:
            config = client.get("/api/v1/auth/google/config")
            assert config.status_code == 200
            assert config.json()["client_id"] == "netsentry-test-client-id.apps.googleusercontent.com"
            assert config.json()["nonce"] == client.cookies.get("netsentry_google_nonce")
            yield client, config.json()["nonce"], session_factory
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def mock_claims(monkeypatch, nonce, **overrides):
    claims = {
        "sub": "google-subject-" + uuid4().hex,
        "email": "google-user@gmail.com",
        "email_verified": True,
        "name": "Google User",
        "nonce": nonce,
    }
    claims.update(overrides)
    monkeypatch.setattr(auth_routes, "verify_google_credential", lambda _credential, _client_id: claims)
    return claims


def test_google_creates_session_for_verified_gmail(google_client, monkeypatch):
    client, nonce, _ = google_client
    mock_claims(monkeypatch, nonce)
    response = client.post("/api/v1/auth/google", json={"credential": "x" * 120, "nonce": nonce})

    assert response.status_code == 200, response.text
    assert response.json()["user"]["email"] == "google-user@gmail.com"
    assert client.get("/api/v1/auth/me").status_code == 200
    assert client.cookies.get("netsentry_google_nonce") is None


@pytest.mark.parametrize(
    ("claims", "status"),
    [
        ({"email": "person@example.org", "email_verified": True}, 422),
        ({"email": "google-user@gmail.com", "email_verified": False}, 403),
    ],
)
def test_google_rejects_non_gmail_or_unverified_claims(google_client, monkeypatch, claims, status):
    client, nonce, _ = google_client
    mock_claims(monkeypatch, nonce, **claims)
    response = client.post("/api/v1/auth/google", json={"credential": "x" * 120, "nonce": nonce})
    assert response.status_code == status


def test_google_rejects_invalid_token_and_mismatched_nonce(google_client, monkeypatch):
    client, nonce, _ = google_client
    monkeypatch.setattr(auth_routes, "verify_google_credential", lambda *_args: (_ for _ in ()).throw(ValueError("invalid token")))
    invalid = client.post("/api/v1/auth/google", json={"credential": "x" * 120, "nonce": nonce})
    assert invalid.status_code == 401

    mock_claims(monkeypatch, "different-nonce")
    mismatch = client.post("/api/v1/auth/google", json={"credential": "x" * 120, "nonce": nonce})
    assert mismatch.status_code == 401


def test_verified_google_identity_links_existing_gmail_account(google_client, monkeypatch):
    client, nonce, session_factory = google_client
    email = f"existing-{uuid4().hex}@gmail.com"
    registered = client.post("/api/v1/auth/register", json={
        "name": "Existing User", "email": email, "password": "StrongPassword123",
    })
    assert registered.status_code == 201
    user_id = registered.json()["user"]["id"]
    mock_claims(monkeypatch, nonce, email=email)
    linked = client.post("/api/v1/auth/google", json={"credential": "x" * 120, "nonce": nonce})
    assert linked.status_code == 200, linked.text
    assert linked.json()["user"]["id"] == user_id
    with session_factory() as db:
        user = db.get(User, user_id)
        assert user.google_subject.startswith("google-subject-")


def test_google_sign_in_requires_backend_configuration(google_client, monkeypatch):
    client, nonce, _ = google_client
    monkeypatch.delenv("GOOGLE_CLIENT_ID")
    response = client.post("/api/v1/auth/google", json={"credential": "x" * 120, "nonce": nonce})
    assert response.status_code == 503

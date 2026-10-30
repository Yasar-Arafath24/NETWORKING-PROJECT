from uuid import uuid4
from unittest.mock import patch
import re

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.api import auth_routes
from backend.app.services.database import Base, get_db


def test_signup_requires_email_code_then_restores_session(monkeypatch):
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("NETSENTRY_SMTP_FROM", "verify@netsentry.invalid")
    sent = {}
    email = f"otp-{uuid4().hex}@gmail.com"
    client = TestClient(app)

    with patch(
        "backend.app.api.auth_routes.send_verification_email",
        side_effect=lambda _email, _name, code: sent.update(code=code),
    ):
        registered = client.post("/api/v1/auth/register", json={
            "name": "OTP User", "email": email, "password": "Aa1234",
        })

    assert registered.status_code == 201, registered.text
    assert registered.json()["verification_required"] is True
    assert "user" not in registered.json()
    assert client.cookies.get("netsentry_session") is None
    duplicate_signup = client.post("/api/v1/auth/register", json={
        "name": "OTP User", "email": email, "password": "Aa1234",
    })
    assert duplicate_signup.status_code == 429

    login_before_verification = client.post("/api/v1/auth/login", json={
        "email": email, "password": "Aa1234",
    })
    assert login_before_verification.status_code == 403

    verified = client.post("/api/v1/auth/verify-email", json={
        "email": email, "code": sent["code"],
    })
    assert verified.status_code == 200, verified.text
    assert verified.json()["user"]["email"] == email
    assert client.cookies.get("netsentry_session")
    client.headers.update({"X-CSRF-Token": client.cookies.get("netsentry_csrf")})
    assert client.get("/api/v1/auth/me").json()["user"]["email"] == email

    # A new browser page/client with the persistent cookie automatically restores the account.
    returning_client = TestClient(app)
    returning_client.cookies.update(client.cookies)
    assert returning_client.get("/api/v1/auth/me").json()["user"]["email"] == email


def test_signup_code_rejects_wrong_code_and_throttles_attempts(monkeypatch):
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("NETSENTRY_SMTP_FROM", "verify@netsentry.invalid")
    sent = {}
    email = f"otp-limit-{uuid4().hex}@gmail.com"
    client = TestClient(app)
    with patch(
        "backend.app.api.auth_routes.send_verification_email",
        side_effect=lambda _email, _name, code: sent.update(code=code),
    ):
        response = client.post("/api/v1/auth/register", json={
            "name": "OTP User", "email": email, "password": "Aa1234",
        })
    assert response.status_code == 201, response.text

    for _ in range(5):
        invalid = client.post("/api/v1/auth/verify-email", json={"email": email, "code": "000000" if sent["code"] != "000000" else "999999"})
        assert invalid.status_code == 400
    blocked = client.post("/api/v1/auth/verify-email", json={"email": email, "code": sent["code"]})
    assert blocked.status_code == 429


def test_signup_password_minimum_is_six_characters():
    client = TestClient(app)
    too_short = client.post("/api/v1/auth/register", json={
        "name": "Short Password", "email": f"short-{uuid4().hex}@gmail.com", "password": "Aa123",
    })
    assert too_short.status_code == 422


def test_local_console_delivery_is_explicit_and_logs_code(monkeypatch, caplog):
    monkeypatch.setenv("NETSENTRY_ENV", "development")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "console")
    auth_routes.send_verification_email("dev@example.invalid", "Dev User", "654321")
    assert "Development OTP" in caplog.text
    assert "654321" in caplog.text


def test_local_signup_completes_using_console_code(monkeypatch, caplog):
    monkeypatch.setenv("NETSENTRY_ENV", "development")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "console")
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        email = f"console-{uuid4().hex}@gmail.com"
        with caplog.at_level("WARNING"):
            created = client.post("/api/v1/auth/register", json={
                "name": "Local Signup", "email": email, "password": "Aa1234",
            })
        assert created.status_code == 201, created.text
        assert created.json()["delivery"] == "console"
        match = re.search(r"Development OTP for .*: (\d{6})", caplog.text)
        assert match
        assert match.group(1) not in str(created.json())
        verified = client.post("/api/v1/auth/verify-email", json={"email": email, "code": match.group(1)})
        assert verified.status_code == 200, verified.text
        assert verified.json()["user"]["email"] == email
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_registration_explains_missing_smtp_configuration(monkeypatch):
    monkeypatch.setenv("NETSENTRY_ENV", "production")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.delenv("NETSENTRY_SMTP_HOST", raising=False)
    monkeypatch.delenv("NETSENTRY_SMTP_FROM", raising=False)
    response = TestClient(app).post("/api/v1/auth/register", json={
        "name": "SMTP Missing", "email": f"smtp-{uuid4().hex}@gmail.com", "password": "Aa1234",
    })
    assert response.status_code == 503
    assert "NETSENTRY_SMTP_HOST" in response.json()["detail"]
    assert "NETSENTRY_EMAIL_DELIVERY=console" in response.json()["detail"]

from datetime import datetime, timedelta, timezone
import smtplib
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from fastapi import HTTPException
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.api import auth_routes
from backend.app.main import app
from backend.app.models.user import EmailVerification, PasswordResetOtp, User
from backend.app.services.database import Base, get_db


@pytest.mark.parametrize(
    ("use_tls", "use_ssl", "factory_name", "starttls_expected"),
    [("true", "false", "SMTP", True), ("false", "true", "SMTP_SSL", False)],
)
def test_smtp_uses_configured_transport(monkeypatch, use_tls, use_ssl, factory_name, starttls_expected):
    class FakeSMTP:
        def __init__(self):
            self.message = None
            self.started_tls = False

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def starttls(self, **_kwargs):
            self.started_tls = True

        def send_message(self, message):
            self.message = message

    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-password-reset-secret-with-32-chars")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "")
    monkeypatch.setenv("SMTP_PASSWORD", "")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "security@netsentry.invalid")
    monkeypatch.setenv("SMTP_FROM_NAME", "NetSentry Tests")
    monkeypatch.setenv("SMTP_USE_TLS", use_tls)
    monkeypatch.setenv("SMTP_USE_SSL", use_ssl)
    smtp = FakeSMTP()
    constructor_args = {}

    def create_smtp(*args, **kwargs):
        constructor_args.update(kwargs)
        return smtp

    monkeypatch.setattr(auth_routes.smtplib, factory_name, create_smtp)
    auth_routes.send_password_reset_email("user@example.org", "Test User", "135790")
    assert smtp.started_tls is starttls_expected
    assert "135790" in smtp.message.get_content()
    assert smtp.message["From"] == "NetSentry Tests <security@netsentry.invalid>"
    assert ("context" in constructor_args) is (factory_name == "SMTP_SSL")


def _client(monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        with factory() as db:
            yield db

    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-password-reset-secret-with-32-chars")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "")
    monkeypatch.setenv("SMTP_PASSWORD", "")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "security@netsentry.invalid")
    monkeypatch.setenv("SMTP_FROM_NAME", "NetSentry Tests")
    monkeypatch.setenv("SMTP_USE_TLS", "true")
    monkeypatch.setenv("SMTP_USE_SSL", "false")
    app.dependency_overrides[get_db] = override_db
    return TestClient(app), factory, engine


def _register_verified(client, email):
    codes = {}
    with patch(
        "backend.app.api.auth_routes.send_verification_email",
        side_effect=lambda _email, _name, code: codes.update(code=code),
    ):
        response = client.post("/api/v1/auth/register", json={
            "name": "Reset User",
            "email": email,
            "password": "OldPassword123",
        })
    assert response.status_code == 201, response.text
    verification = client.post("/api/v1/auth/verify-email", json={"email": email, "code": codes["code"]})
    assert verification.status_code == 200, verification.text


def test_registration_supports_organization_email_and_password_login(monkeypatch):
    client, _factory, engine = _client(monkeypatch)
    try:
        email = f"person-{uuid4().hex}@engineering.example.edu"
        _register_verified(client, email)
        client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": client.cookies.get("netsentry_csrf")})
        logged_in = client.post("/api/v1/auth/login", json={"email": email, "password": "OldPassword123"})
        assert logged_in.status_code == 200, logged_in.text
        assert logged_in.json()["user"]["email"] == email
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_signup_otp_expires_after_five_minutes(monkeypatch):
    client, factory, engine = _client(monkeypatch)
    try:
        email = f"expiry-{uuid4().hex}@company.example.org"
        code = {}
        with patch(
            "backend.app.api.auth_routes.send_verification_email",
            side_effect=lambda _email, _name, otp: code.update(value=otp),
        ):
            registered = client.post("/api/v1/auth/register", json={
                "name": "Expiry User",
                "email": email,
                "password": "OldPassword123",
            })
        assert registered.status_code == 201, registered.text
        with factory() as db:
            user = db.query(User).filter(User.email == email).one()
            record = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).one()
            assert auth_routes._aware(record.expires_at) - auth_routes._aware(record.created_at) == timedelta(minutes=5)
            assert code["value"] not in record.code_hash

            record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        expired = client.post("/api/v1/auth/verify-email", json={"email": email, "code": code["value"]})
        assert expired.status_code == 400
        assert "expired" in expired.json()["detail"].lower()
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_password_reset_verifies_hashed_otp_and_invalidates_old_password(monkeypatch):
    client, factory, engine = _client(monkeypatch)
    code = {}
    try:
        email = f"reset-{uuid4().hex}@gmail.com"
        _register_verified(client, email)
        with patch(
            "backend.app.api.auth_routes.send_password_reset_email",
            side_effect=lambda _email, _name, otp: code.update(value=otp),
        ):
            request = client.post("/api/v1/auth/forgot-password", json={"email": email})
        assert request.status_code == 202
        assert request.json() == {"message": auth_routes.RESET_GENERIC_MESSAGE}
        assert "code" not in request.json()
        with factory() as db:
            user = db.query(User).filter(User.email == email).one()
            otp = db.query(PasswordResetOtp).filter(PasswordResetOtp.user_id == user.id).one()
            assert code["value"] not in otp.code_hash

        invalid = client.post("/api/v1/auth/verify-reset-otp", json={"email": email, "code": "000000" if code["value"] != "000000" else "999999"})
        assert invalid.status_code == 400
        verified = client.post("/api/v1/auth/verify-reset-otp", json={"email": email, "code": code["value"]})
        assert verified.status_code == 200, verified.text
        assert "reset_token" not in verified.json()
        assert client.cookies.get("netsentry_reset_token")
        with factory() as db:
            user = db.query(User).filter(User.email == email).one()
            otp = db.query(PasswordResetOtp).filter(PasswordResetOtp.user_id == user.id).one()
            assert code["value"] not in otp.code_hash
        reused = client.post("/api/v1/auth/verify-reset-otp", json={"email": email, "code": code["value"]})
        assert reused.status_code == 400
        csrf = client.cookies.get("netsentry_reset_csrf")
        client.headers.update({"X-CSRF-Token": csrf})

        changed = client.post("/api/v1/auth/reset-password", json={"password": "NewSecurePass123"})
        assert changed.status_code == 200, changed.text
        assert client.cookies.get("netsentry_reset_token") is None
        with factory() as db:
            user = db.query(User).filter(User.email == email).one()
            assert not db.query(PasswordResetOtp).filter(PasswordResetOtp.user_id == user.id).first()
            assert not auth_routes._password_matches("OldPassword123", user.password_hash)
            assert auth_routes._password_matches("NewSecurePass123", user.password_hash)

        assert client.get("/api/v1/auth/me").status_code == 401
        assert client.post("/api/v1/auth/login", json={"email": email, "password": "OldPassword123"}).status_code == 401
        assert client.post("/api/v1/auth/login", json={"email": email, "password": "NewSecurePass123"}).status_code == 200
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_reset_request_is_generic_and_enforces_cooldown_for_known_and_unknown_email(monkeypatch):
    client, _factory, engine = _client(monkeypatch)
    try:
        email = f"generic-{uuid4().hex}@company.example.com"
        _register_verified(client, email)
        with patch("backend.app.api.auth_routes.send_password_reset_email"):
            known = client.post("/api/v1/auth/forgot-password", json={"email": email})
            unknown = client.post("/api/v1/auth/forgot-password", json={"email": f"missing-{uuid4().hex}@company.example.com"})
        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()
        repeated = client.post("/api/v1/auth/forgot-password", json={"email": email})
        assert repeated.status_code == 429
        assert repeated.json()["detail"] == "Too many requests. Wait before trying again."
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_reset_otp_expiry_and_attempt_limit(monkeypatch):
    client, factory, engine = _client(monkeypatch)
    codes = {}
    try:
        email = f"expire-{uuid4().hex}@example.org"
        _register_verified(client, email)
        with patch(
            "backend.app.api.auth_routes.send_password_reset_email",
            side_effect=lambda _email, _name, otp: codes.update(value=otp),
        ):
            assert client.post("/api/v1/auth/forgot-password", json={"email": email}).status_code == 202
        for _ in range(auth_routes.EMAIL_CODE_MAX_ATTEMPTS):
            rejected = client.post("/api/v1/auth/verify-reset-otp", json={"email": email, "code": "000000" if codes["value"] != "000000" else "999999"})
            assert rejected.status_code == 400
        blocked = client.post("/api/v1/auth/verify-reset-otp", json={"email": email, "code": codes["value"]})
        assert blocked.status_code == 400

        with factory() as db:
            user = db.query(User).filter(User.email == email).one()
            record = db.query(PasswordResetOtp).filter(PasswordResetOtp.user_id == user.id).one()
            record.attempts = 0
            record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            db.commit()
        expired = client.post("/api/v1/auth/verify-reset-otp", json={"email": email, "code": codes["value"]})
        assert expired.status_code == 400
        assert expired.json()["detail"] == auth_routes.RESET_INVALID_MESSAGE
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_smtp_failure_does_not_leak_account_or_otp(monkeypatch, caplog):
    client, factory, engine = _client(monkeypatch)
    try:
        email = f"delivery-{uuid4().hex}@example.com"
        _register_verified(client, email)
        with patch("backend.app.api.auth_routes.smtplib.SMTP", side_effect=smtplib.SMTPException("SMTP_PASSWORD=secret")):
            response = client.post("/api/v1/auth/forgot-password", json={"email": email})
        assert response.status_code == 503
        assert "SMTP email delivery failed" in response.json()["detail"]
        assert "SMTP_PASSWORD=secret" not in response.json()["detail"]
        assert "SMTP_PASSWORD=secret" not in caplog.text
        assert "Password reset email delivery failed." in caplog.text
        with factory() as db:
            user = db.query(User).filter(User.email == email).one()
            assert db.query(PasswordResetOtp).filter(PasswordResetOtp.user_id == user.id).first() is None
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_smtp_authentication_failure_is_actionable_without_leaking_credentials(monkeypatch):
    class RejectingSMTP:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def starttls(self, **_kwargs):
            pass

        def login(self, _username, _password):
            raise smtplib.SMTPAuthenticationError(535, b"authentication failed")

    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-password-reset-secret-with-32-chars")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("SMTP_HOST", "smtp.test.invalid")
    monkeypatch.setenv("SMTP_PORT", "587")
    monkeypatch.setenv("SMTP_USERNAME", "account@example.com")
    monkeypatch.setenv("SMTP_PASSWORD", "private-test-app-password")
    monkeypatch.setenv("SMTP_FROM_EMAIL", "security@example.com")
    monkeypatch.setenv("SMTP_USE_TLS", "true")
    monkeypatch.setenv("SMTP_USE_SSL", "false")

    with patch("backend.app.api.auth_routes.smtplib.SMTP", return_value=RejectingSMTP()):
        with pytest.raises(HTTPException) as error:
            auth_routes.send_password_reset_email("user@example.org", "Test User", "135790")

    assert error.value.status_code == 503
    assert "Gmail requires a Google App Password" in error.value.detail
    assert "private-test-app-password" not in error.value.detail
    assert "account@example.com" not in error.value.detail

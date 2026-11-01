from datetime import datetime, timedelta, timezone
from uuid import uuid4
from unittest.mock import patch
import pytest

from fastapi.testclient import TestClient
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.api import auth_routes
from backend.app.models.user import AuthRateLimit, EmailVerification, User
from backend.app.services.database import Base, get_db


def test_signup_requires_email_code_then_restores_session(monkeypatch):
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("MAIL_HOST", "smtp.test.invalid")
    monkeypatch.setenv("MAIL_FROM", "verify@netsentry.invalid")
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


def test_unverified_login_resends_code_only_after_password_verification(monkeypatch):
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("MAIL_HOST", "smtp.test.invalid")
    monkeypatch.setenv("MAIL_FROM", "verify@netsentry.invalid")
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    sent = {}
    email = f"login-otp-{uuid4().hex}@company.example.org"
    try:
        client = TestClient(app)
        with patch(
            "backend.app.api.auth_routes.send_verification_email",
            side_effect=lambda _email, _name, code: sent.update(code=code),
        ):
            registered = client.post("/api/v1/auth/register", json={
                "name": "Login OTP User",
                "email": email,
                "password": "Aa1234",
            })
        assert registered.status_code == 201, registered.text
        with factory() as db:
            user = db.query(auth_routes.User).filter(auth_routes.User.email == email).one()
            db.query(auth_routes.EmailVerification).filter(
                auth_routes.EmailVerification.user_id == user.id
            ).delete()
            db.query(AuthRateLimit).update(
                {"window_started_at": datetime.now(timezone.utc) - timedelta(minutes=2)}
            )
            db.commit()

        with patch("backend.app.api.auth_routes.send_verification_email") as send_email:
            invalid_password = client.post("/api/v1/auth/login", json={
                "email": email,
                "password": "WrongPassword123",
            })
        assert invalid_password.status_code == 401
        send_email.assert_not_called()

        with patch(
            "backend.app.api.auth_routes.send_verification_email",
            side_effect=lambda _email, _name, code: sent.update(code=code),
        ) as send_email:
            pending = client.post("/api/v1/auth/login", json={
                "email": email,
                "password": "Aa1234",
            })
        assert pending.status_code == 403
        assert "new code was sent" in pending.json()["detail"].lower()
        send_email.assert_called_once()
        assert client.cookies.get("netsentry_session") is None

        verified = client.post("/api/v1/auth/verify-email", json={
            "email": email,
            "code": sent["code"],
        })
        assert verified.status_code == 200, verified.text
        assert verified.json()["user"]["email"] == email
        assert client.cookies.get("netsentry_session")

        client.post("/api/v1/auth/logout", headers={
            "X-CSRF-Token": client.cookies.get("netsentry_csrf"),
        })
        logged_in = client.post("/api/v1/auth/login", json={
            "email": email,
            "password": "Aa1234",
        })
        assert logged_in.status_code == 200, logged_in.text
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_signup_code_rejects_wrong_code_and_throttles_attempts(monkeypatch):
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("MAIL_HOST", "smtp.test.invalid")
    monkeypatch.setenv("MAIL_FROM", "verify@netsentry.invalid")
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


def test_console_delivery_is_rejected_without_logging_otp(monkeypatch, caplog):
    monkeypatch.setenv("NETSENTRY_ENV", "development")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "console")
    with pytest.raises(HTTPException) as error:
        auth_routes.send_verification_email("dev@example.invalid", "Dev User", "654321")
    assert error.value.status_code == 503
    assert "654321" not in caplog.text


def test_local_signup_does_not_log_console_code(monkeypatch, caplog):
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
        created = client.post("/api/v1/auth/register", json={
            "name": "Local Signup", "email": email, "password": "Aa1234",
        })
        assert created.status_code == 503
        assert "654321" not in caplog.text
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_registration_explains_missing_smtp_configuration(monkeypatch):
    monkeypatch.setenv("NETSENTRY_ENV", "production")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.delenv("MAIL_HOST", raising=False)
    monkeypatch.delenv("MAIL_FROM", raising=False)
    monkeypatch.delenv("MAIL_USERNAME", raising=False)
    monkeypatch.delenv("MAIL_PASSWORD", raising=False)
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_FROM_EMAIL", raising=False)
    monkeypatch.delenv("NETSENTRY_SMTP_HOST", raising=False)
    monkeypatch.delenv("NETSENTRY_SMTP_FROM", raising=False)
    response = TestClient(app).post("/api/v1/auth/register", json={
        "name": "SMTP Missing", "email": f"smtp-{uuid4().hex}@gmail.com", "password": "Aa1234",
    })
    assert response.status_code == 503
    assert "MAIL_HOST" in response.json()["detail"]


def test_brevo_authentication_failure_is_actionable_without_credentials(monkeypatch, caplog):
    class RejectingSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def starttls(self, **_kwargs):
            pass

        def login(self, *_args):
            import smtplib

            raise smtplib.SMTPAuthenticationError(525, b"credentials rejected")

    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("MAIL_HOST", "smtp-relay.brevo.com")
    monkeypatch.setenv("MAIL_PORT", "587")
    monkeypatch.setenv("MAIL_USERNAME", "private-smtp-login")
    monkeypatch.setenv("MAIL_PASSWORD", "private-smtp-key")
    monkeypatch.setenv("MAIL_FROM", "verified@example.invalid")
    monkeypatch.setenv("MAIL_STARTTLS", "true")
    monkeypatch.setenv("MAIL_SSL_TLS", "false")

    with patch("backend.app.api.auth_routes.smtplib.SMTP", RejectingSMTP):
        with pytest.raises(HTTPException) as error:
            auth_routes.send_verification_email(
                "person@example.invalid", "Test User", "123456"
            )

    assert error.value.status_code == 503
    assert "status 525" in error.value.detail
    assert "newly generated Brevo SMTP key" in error.value.detail
    assert "private-smtp-login" not in error.value.detail
    assert "private-smtp-key" not in error.value.detail
    assert "123456" not in caplog.text
    assert "private-smtp-key" not in caplog.text


def test_failed_registration_email_does_not_leave_unverified_user(monkeypatch):
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("MAIL_HOST", "smtp.test.invalid")
    monkeypatch.setenv("MAIL_FROM", "verify@netsentry.invalid")
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_db():
        with factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_db
    email = f"failed-delivery-{uuid4().hex}@example.invalid"
    try:
        with patch(
            "backend.app.api.auth_routes.send_verification_email",
            side_effect=HTTPException(503, "SMTP authentication failed."),
        ):
            response = TestClient(app).post(
                "/api/v1/auth/register",
                json={
                    "name": "Failed Delivery",
                    "email": email,
                    "password": "Aa1234",
                },
            )

        assert response.status_code == 503
        with factory() as db:
            assert db.query(User).filter(User.email == email).first() is None
            assert db.query(EmailVerification).count() == 0
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_gmail_requires_an_app_password(monkeypatch):
    monkeypatch.setenv("NETSENTRY_OTP_SECRET", "test-secret-with-more-than-32-characters")
    monkeypatch.setenv("NETSENTRY_EMAIL_DELIVERY", "smtp")
    monkeypatch.setenv("MAIL_HOST", "smtp.gmail.com")
    monkeypatch.setenv("MAIL_PORT", "587")
    monkeypatch.setenv("MAIL_FROM", "user@gmail.com")
    monkeypatch.setenv("MAIL_USERNAME", "")
    monkeypatch.setenv("MAIL_PASSWORD", "")
    monkeypatch.setenv("MAIL_STARTTLS", "true")
    monkeypatch.setenv("MAIL_SSL_TLS", "false")

    with pytest.raises(HTTPException) as error:
        auth_routes._validate_email_delivery_config()

    assert error.value.status_code == 503
    assert "MAIL_USERNAME and MAIL_PASSWORD" in error.value.detail

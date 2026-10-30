from uuid import uuid4
import os
from unittest.mock import patch


def register_and_verify(client, values):
    """Create a test account while replacing SMTP with a captured OTP."""
    os.environ.setdefault("NETSENTRY_OTP_SECRET", "test-only-secret-with-at-least-32-characters")
    os.environ.setdefault("NETSENTRY_SMTP_HOST", "smtp.test.invalid")
    os.environ.setdefault("NETSENTRY_SMTP_FROM", "test@netsentry.invalid")
    sent = {}
    with patch("backend.app.api.auth_routes.send_verification_email", side_effect=lambda _email, _name, code: sent.update(code=code)):
        response = client.post("/api/v1/auth/register", json=values)
        if response.status_code == 201:
            email = response.json()["email"]
            verified = client.post("/api/v1/auth/verify-email", json={"email": email, "code": sent["code"]})
            assert verified.status_code == 200, verified.text
            return verified
        return response


def authenticate_test_client(client):
    response = register_and_verify(client, {
        "name": "Test User",
        "email": f"test-{uuid4().hex}@gmail.com",
        "password": "Test123",
    })
    assert response.status_code == 200, response.text
    csrf = client.cookies.get("netsentry_csrf")
    assert csrf
    client.headers.update({"X-CSRF-Token": csrf})
    return response.json()["user"]["id"]

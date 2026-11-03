from uuid import uuid4
from unittest.mock import patch


def register_and_verify(client, values):
    """Create a test account and verify its generated email code."""
    sent = {}
    with patch(
        "backend.app.api.auth_routes.send_verification_email",
        side_effect=lambda _email, _name, code: sent.update(code=code),
    ):
        registered = client.post("/api/v1/auth/register", json=values)
    if registered.status_code != 201 or not registered.json().get("verification_required"):
        return registered
    return client.post("/api/v1/auth/verify-email", json={
        "email": values["email"],
        "code": sent["code"],
    })


def authenticate_test_client(client):
    response = register_and_verify(client, {
        "name": "Test User",
        "email": f"test-{uuid4().hex}@gmail.com",
        "password": "Test123",
    })
    assert response.status_code in (200, 201), response.text
    csrf = client.cookies.get("netsentry_csrf")
    assert csrf
    client.headers.update({"X-CSRF-Token": csrf})
    return response.json()["user"]["id"]

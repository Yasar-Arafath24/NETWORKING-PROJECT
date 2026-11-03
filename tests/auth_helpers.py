from uuid import uuid4


def register_and_verify(client, values):
    """Create and authenticate a test account without email verification."""
    return client.post("/api/v1/auth/register", json=values)


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

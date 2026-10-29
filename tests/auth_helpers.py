from uuid import uuid4


def authenticate_test_client(client):
    response = client.post("/api/v1/auth/register", json={
        "name": "Test User",
        "email": f"test-{uuid4().hex}@gmail.com",
        "password": "TestPassword123",
    })
    assert response.status_code == 201, response.text
    csrf = client.cookies.get("netsentry_csrf")
    assert csrf
    client.headers.update({"X-CSRF-Token": csrf})
    return response.json()["user"]["id"]

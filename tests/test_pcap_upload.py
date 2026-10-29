
from pathlib import Path

from fastapi.testclient import TestClient

from backend.app.main import app
from tests.auth_helpers import authenticate_test_client

client = TestClient(app)
authenticate_test_client(client)

# Project root: the directory containing this test's parent folder
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def find_pcap_file():
    """Find an existing PCAP file inside the project."""
    search_dirs = [
        PROJECT_ROOT / "datasets",
        PROJECT_ROOT / "tests",
    ]

    candidates = []

    for directory in search_dirs:
        if directory.exists():
            candidates.extend(directory.rglob("*.pcap"))
            candidates.extend(directory.rglob("*.pcapng"))

    # Avoid duplicate paths and return the first available capture.
    candidates = sorted(set(candidates))

    if not candidates:
        return None

    return candidates[0]


def test_real_pcap_upload():
    pcap_path = find_pcap_file()

    assert pcap_path is not None, (
        "No .pcap or .pcapng file found. "
        "Place a test capture inside the project's datasets/ or tests/ folder."
    )

    print(f"\nTesting PCAP file: {pcap_path}")

    with pcap_path.open("rb") as pcap_file:
        response = client.post(
            "/api/v1/pcap/analyze",
            files={
                "file": (
                    pcap_path.name,
                    pcap_file,
                    "application/octet-stream",
                )
            },
        )

    assert response.status_code == 200, (
        f"PCAP analysis failed with HTTP {response.status_code}: "
        f"{response.text}"
    )

    data = response.json()

    assert "total_packets" in data, data
    assert "total_flows" in data, data
    assert isinstance(data["total_packets"], int), data
    assert isinstance(data["total_flows"], int), data
    assert data["total_packets"] >= 0
    assert data["total_flows"] >= 0
    assert "risk_assessment" in data, data


from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)

UPLOAD_URL = "/api/v1/pcap/analyze"


def test_rejects_unsupported_extension():
    response = client.post(
        UPLOAD_URL,
        files={"file": ("capture.txt", b"not a pcap", "text/plain")},
    )
    assert response.status_code == 400


def test_rejects_invalid_pcap_signature():
    response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "capture.pcap",
                b"NOT_A_VALID_PCAP_FILE",
                "application/octet-stream",
            )
        },
    )
    assert response.status_code == 400


def test_rejects_empty_pcap():
    response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "empty.pcap",
                b"",
                "application/octet-stream",
            )
        },
    )
    assert response.status_code == 400


def test_accepts_real_pcap():
    from pathlib import Path

    candidates = [
        Path("datasets/duplicate_backups/phase1_test_capture.pcapng"),
        Path("datasets/raw/57c81bec8b6347529b80d4443fd8d97.pcapng"),
        Path("datasets/duplicate_backups/e9c86e0827234f4aa0308e21461f83ed.pcapng"),
    ]

    pcap_path = next((path for path in candidates if path.is_file()), None)
    assert pcap_path is not None, "No test PCAP file was found."

    with pcap_path.open("rb") as capture:
        response = client.post(
            UPLOAD_URL,
            files={
                "file": (
                    pcap_path.name,
                    capture,
                    "application/octet-stream",
                )
            },
        )

    assert response.status_code == 200, response.text

def test_rejects_upload_over_size_limit():
    from backend.app.core.upload_validation import MAX_UPLOAD_SIZE

    oversized_content = b"\x00" * (MAX_UPLOAD_SIZE + 1)

    response = client.post(
        UPLOAD_URL,
        files={
            "file": (
                "oversized.pcap",
                oversized_content,
                "application/octet-stream",
            )
        },
    )

    assert response.status_code == 413, response.text

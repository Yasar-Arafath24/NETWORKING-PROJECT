
from fastapi.testclient import TestClient

from backend.app.main import app
from tests.auth_helpers import authenticate_test_client

client = TestClient(app)
authenticate_test_client(client)

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

    project_root = Path(__file__).resolve().parent.parent
    raw_dir = project_root / "datasets" / "raw"

    candidates = [
        raw_dir / "phase1_test_capture.pcapng",
        raw_dir / "netsentry_test.pcap",
        project_root / "datasets" / "duplicate_backups" / "phase1_test_capture.pcapng",
        raw_dir / "57c81bec8b6347529b80d4443fd8d97.pcapng",
        project_root / "datasets" / "duplicate_backups" / "e9c86e0827234f4aa0308e21461f83ed.pcapng",
    ]

    pcap_path = next((path for path in candidates if path.is_file()), None)

    # Fall back to any capture that ships under datasets/raw.
    if pcap_path is None:
        pcap_path = next(
            (
                path
                for pattern in ("*.pcapng", "*.pcap")
                for path in sorted(raw_dir.glob(pattern))
            ),
            None,
        )

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


import pytest

from backend.app.core.upload_validation import validate_pcap_upload


def test_rejects_unsupported_extension():
    with pytest.raises(ValueError, match="Only .pcap"):
        validate_pcap_upload("capture.txt", b"test")


def test_rejects_empty_file():
    with pytest.raises(ValueError, match="empty"):
        validate_pcap_upload("capture.pcap", b"")


def test_rejects_invalid_signature():
    with pytest.raises(ValueError, match="signature"):
        validate_pcap_upload("capture.pcap", b"NOTP")


def test_rejects_file_over_size_limit():
    # The size check runs before signature validation.
    content = b"\x00" * (20 * 1024 * 1024 + 1)

    with pytest.raises(ValueError, match="20 MiB"):
        validate_pcap_upload("capture.pcap", content)


def test_accepts_recognized_pcap_signature():
    content = b"\xd4\xc3\xb2\xa1" + b"\x00" * 20

    validate_pcap_upload("capture.pcap", content)


from pathlib import Path

# Maximum upload size: 20 MiB
MAX_UPLOAD_SIZE = 20 * 1024 * 1024

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

# Standard PCAP and PCAPNG file signatures
PCAP_MAGIC_NUMBERS = {
    b"\xd4\xc3\xb2\xa1",  # PCAP, little-endian microseconds
    b"\xa1\xb2\xc3\xd4",  # PCAP, big-endian microseconds
    b"\x4d\x3c\xb2\xa1",  # PCAP, little-endian nanoseconds
    b"\xa1\xb2\x3c\x4d",  # PCAP, big-endian nanoseconds
    b"\x0a\x0d\x0d\x0a",  # PCAPNG
}


def validate_pcap_upload(filename: str, content: bytes) -> None:
    """Raise ValueError if the uploaded capture is invalid."""

    if not filename:
        raise ValueError("A filename is required.")

    extension = Path(filename).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("Only .pcap and .pcapng files are allowed.")

    if not content:
        raise ValueError("The uploaded file is empty.")

    if len(content) > MAX_UPLOAD_SIZE:
        raise ValueError("Upload exceeds the 20 MiB size limit.")

    if len(content) < 4:
        raise ValueError("The file is too small to be a valid capture.")

    if content[:4] not in PCAP_MAGIC_NUMBERS:
        raise ValueError("The file does not have a recognized PCAP signature.")

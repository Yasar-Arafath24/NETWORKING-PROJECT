from pathlib import Path
from scapy.all import rdpcap


PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The sample capture may live directly in datasets/raw or in a subfolder.
CAPTURE_NAME = "phase1_test_capture.pcapng"
CAPTURE_DIRS = [
    PROJECT_ROOT / "datasets" / "raw",
    PROJECT_ROOT / "datasets" / "raw" / "normal",
]


def find_capture() -> Path:
    for directory in CAPTURE_DIRS:
        candidate = directory / CAPTURE_NAME
        if candidate.exists():
            return candidate
    return CAPTURE_DIRS[0] / CAPTURE_NAME


PCAP_FILE = find_capture()


def main():
    print("=" * 50)
    print("NetSentry AI - PCAP Reader Test")
    print("=" * 50)

    print(f"PCAP file: {PCAP_FILE}")

    if not PCAP_FILE.exists():
        print("ERROR: PCAP file not found.")
        return

    packets = rdpcap(str(PCAP_FILE))

    print(f"Packets loaded: {len(packets)}")
    print()

    for index, packet in enumerate(packets[:10], start=1):
        print(f"Packet {index}: {packet.summary()}")

    print()
    print("Scapy PCAP reading: SUCCESS")


if __name__ == "__main__":
    main()
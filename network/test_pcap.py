from pathlib import Path
from scapy.all import rdpcap


PROJECT_ROOT = Path(__file__).resolve().parent.parent
PCAP_FILE = PROJECT_ROOT / "datasets" / "raw" / "phase1_test_capture.pcapng"


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
from pathlib import Path

from scapy.all import Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "datasets" / "raw"


def create_capture(output_path: Path | str) -> Path:
    """Generate a small synthetic PCAP used by the smoke checks."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    packets = []

    for i in range(20):
        src_ip = f"192.168.1.{10 + i}"
        dst_ip = "192.168.1.100"
        src_port = 40000 + i
        dst_port = 80 if i % 2 == 0 else 443

        request = (
            Ether()
            / IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1)
            / Raw(load=b"GET /test HTTP/1.1")
        )

        response = (
            Ether()
            / IP(src=dst_ip, dst=src_ip)
            / TCP(sport=dst_port, dport=src_port, flags="PA", seq=1)
            / Raw(load=b"HTTP/1.1 200 OK")
        )

        request.time = 1_700_000_000 + i * 2
        response.time = 1_700_000_001 + i * 2

        packets.extend([request, response])

    for i in range(10):
        packet = (
            Ether()
            / IP(src=f"192.168.1.{50 + i}", dst="192.168.1.100")
            / UDP(sport=53000 + i, dport=53)
            / Raw(load=f"dns-{i}".encode())
        )
        packet.time = 1_700_000_050 + i
        packets.append(packet)

    for i in range(10):
        packet = (
            Ether()
            / IP(src=f"192.168.1.{70 + i}", dst="192.168.1.100")
            / ICMP()
            / Raw(load=b"test-ping")
        )
        packet.time = 1_700_000_100 + i
        packets.append(packet)

    wrpcap(str(output), packets)
    return output


def ensure_test_capture() -> Path:
    """Create the sample captures used by the smoke tests if they are missing."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)

    default_capture = RAW_DIR / "netsentry_test.pcap"
    legacy_capture = RAW_DIR / "phase1_test_capture.pcapng"

    if not default_capture.exists():
        create_capture(default_capture)

    if not legacy_capture.exists():
        create_capture(legacy_capture)

    return default_capture


if __name__ == "__main__":
    output = ensure_test_capture()
    print(f"Created: {output}")
    print(f"Raw directory: {RAW_DIR}")
    print("Note: This is synthetic test traffic, not real attack traffic.")
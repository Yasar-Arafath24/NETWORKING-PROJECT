
from pathlib import Path
from scapy.all import Ether, IP, UDP, TCP, DNS, DNSQR, Raw, wrpcap, rdpcap


def create_test_pcap():
    """Generate a small, valid synthetic PCAP for NetSentry AI testing."""

    output_file = Path("datasets/processed/valid_test_capture.pcap")
    output_file.parent.mkdir(parents=True, exist_ok=True)

    packets = []

    # Packet 1: DNS query
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(
            rd=1,
            id=1001,
            qd=DNSQR(qname="example.com", qtype="A"),
        )
    )

    # Packet 2: DNS response
    packets.append(
        Ether()
        / IP(src="8.8.8.8", dst="192.168.1.10")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=1001,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=None,
        )
    )

    # Packet 3: TCP SYN
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=51000, dport=80, flags="S", seq=1000)
    )

    # Packet 4: TCP SYN-ACK
    packets.append(
        Ether()
        / IP(src="192.168.1.20", dst="192.168.1.10")
        / TCP(sport=80, dport=51000, flags="SA", seq=2000, ack=1001)
    )

    # Packet 5: Synthetic application payload
    packets.append(
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / UDP(sport=52000, dport=52001)
        / Raw(load=b"NetSentry AI synthetic test traffic")
    )

    # Packet 6: Response payload
    packets.append(
        Ether()
        / IP(src="192.168.1.20", dst="192.168.1.10")
        / UDP(sport=52001, dport=52000)
        / Raw(load=b"Synthetic test response")
    )

    # Write a genuine PCAP file with a valid PCAP global header.
    wrpcap(str(output_file), packets)

    # Read it back to verify the file can be parsed.
    verified_packets = rdpcap(str(output_file))

    if len(verified_packets) != len(packets):
        raise RuntimeError("PCAP verification failed: packet count mismatch.")

    with output_file.open("rb") as file:
        signature = file.read(4)

    valid_signatures = {
        bytes.fromhex("d4c3b2a1"),
        bytes.fromhex("a1b2c3d4"),
        bytes.fromhex("4d3cb2a1"),
        bytes.fromhex("a1b23c4d"),
    }

    if signature not in valid_signatures:
        raise RuntimeError(
            f"Unexpected PCAP signature: {signature.hex()}"
        )

    print("=" * 55)
    print("NetSentry AI - Test PCAP Generator")
    print("=" * 55)
    print(f"File: {output_file.resolve()}")
    print(f"Packets: {len(verified_packets)}")
    print(f"Size: {output_file.stat().st_size} bytes")
    print(f"PCAP signature: {signature.hex()}")
    print("Verification: PASSED")
    print("=" * 55)


if __name__ == "__main__":
    try:
        create_test_pcap()
    except ImportError:
        print("Scapy is not installed.")
        print("Install it with: python -m pip install scapy")
    except Exception as error:
        print(f"Failed to create test PCAP: {error}")
        raise

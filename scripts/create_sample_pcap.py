"""Generate a small, safe, synthetic PCAP sample for NetSentry AI.

The capture mixes several common protocols (DNS, TCP/HTTP, TCP/TLS, ICMP
and UDP) across a few seconds so the flow engine extracts a handful of
realistic flows. It contains only synthetic lab traffic and no private data.

Run from the project root:

    python scripts/create_sample_pcap.py

It writes the same bytes to two locations:

    datasets/samples/netsentry_sample.pcap          (for backend testing)
    frontend/public/samples/netsentry_sample.pcap  (served by the frontend,
                                                     available for download)
"""

from pathlib import Path

from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    Raw,
    TCP,
    UDP,
    Ether,
    rdpcap,
    wrpcap,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent

OUTPUT_PATHS = [
    PROJECT_ROOT / "datasets" / "samples" / "netsentry_sample.pcap",
    PROJECT_ROOT / "frontend" / "public" / "samples" / "netsentry_sample.pcap",
]

# Synthetic addresses (documentation ranges / private lab ranges only).
CLIENT = "192.168.1.50"
GATEWAY = "192.168.1.1"
DNS_SERVER = "8.8.8.8"
WEB_SERVER = "93.184.216.34"
TLS_SERVER = "104.18.32.7"
SSH_CLIENT = "192.168.1.60"
SSH_SERVER = "192.168.1.100"

BASE_TIME = 1730000000.0  # Fixed epoch keeps the sample reproducible.


def build_packets():
    """Return the ordered list of synthetic packets."""

    packets = []

    def add(packet, offset):
        packet.time = BASE_TIME + offset
        packets.append(packet)
        return packet

    # --- Flow 1: DNS lookup (UDP/53) -----------------------------------
    add(
        Ether()
        / IP(src=CLIENT, dst=DNS_SERVER)
        / UDP(sport=53000, dport=53)
        / DNS(rd=1, id=1001, qd=DNSQR(qname="example.com", qtype="A")),
        0.00,
    )
    add(
        Ether()
        / IP(src=DNS_SERVER, dst=CLIENT)
        / UDP(sport=53, dport=53000)
        / DNS(
            id=1001,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.com", qtype="A"),
            an=DNSRR(rrname="example.com", type="A", rdata=WEB_SERVER),
        ),
        0.05,
    )

    # --- Flow 2: TCP handshake + HTTP GET (TCP/80) ---------------------
    add(
        Ether()
        / IP(src=CLIENT, dst=WEB_SERVER)
        / TCP(sport=51000, dport=80, flags="S", seq=1000),
        0.10,
    )
    add(
        Ether()
        / IP(src=WEB_SERVER, dst=CLIENT)
        / TCP(sport=80, dport=51000, flags="SA", seq=2000, ack=1001),
        0.14,
    )
    add(
        Ether()
        / IP(src=CLIENT, dst=WEB_SERVER)
        / TCP(sport=51000, dport=80, flags="A", seq=1001, ack=2001),
        0.15,
    )
    add(
        Ether()
        / IP(src=CLIENT, dst=WEB_SERVER)
        / TCP(sport=51000, dport=80, flags="PA", seq=1001, ack=2001)
        / Raw(
            load=(
                b"GET /index.html HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: NetSentry-AI/1.0\r\n\r\n"
            )
        ),
        0.20,
    )
    add(
        Ether()
        / IP(src=WEB_SERVER, dst=CLIENT)
        / TCP(sport=80, dport=51000, flags="PA", seq=2001, ack=1090)
        / Raw(
            load=(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: 44\r\n\r\n"
                b"<html><body>NetSentry sample</body></html>"
            )
        ),
        0.35,
    )
    add(
        Ether()
        / IP(src=CLIENT, dst=WEB_SERVER)
        / TCP(sport=51000, dport=80, flags="A", seq=1090, ack=2200),
        0.37,
    )

    # --- Flow 3: TLS handshake (TCP/443) -------------------------------
    add(
        Ether()
        / IP(src=CLIENT, dst=TLS_SERVER)
        / TCP(sport=51200, dport=443, flags="S", seq=3000),
        0.60,
    )
    add(
        Ether()
        / IP(src=TLS_SERVER, dst=CLIENT)
        / TCP(sport=443, dport=51200, flags="SA", seq=4000, ack=3001),
        0.66,
    )
    add(
        Ether()
        / IP(src=CLIENT, dst=TLS_SERVER)
        / TCP(sport=51200, dport=443, flags="A", seq=3001, ack=4001),
        0.67,
    )
    add(
        Ether()
        / IP(src=CLIENT, dst=TLS_SERVER)
        / TCP(sport=51200, dport=443, flags="PA", seq=3001, ack=4001)
        / Raw(load=b"\x16\x03\x01\x00\x2f" + b"\x01" + b"NetSentryTLSClientHello"),
        0.70,
    )
    add(
        Ether()
        / IP(src=TLS_SERVER, dst=CLIENT)
        / TCP(sport=443, dport=51200, flags="PA", seq=4001, ack=3072)
        / Raw(load=b"\x16\x03\x03\x00\x2f" + b"NetSentryTLSServerHello"),
        0.88,
    )

    # --- Flow 4: ICMP echo request/reply --------------------------------
    add(
        Ether() / IP(src=CLIENT, dst="8.8.4.4") / ICMP(type=8, id=2000),
        1.20,
    )
    add(
        Ether() / IP(src="8.8.4.4", dst=CLIENT) / ICMP(type=0, id=2000),
        1.25,
    )

    # --- Flow 5: UDP application traffic (NTP-style) --------------------
    add(
        Ether()
        / IP(src=CLIENT, dst=GATEWAY)
        / UDP(sport=55000, dport=123)
        / Raw(load=b"\x1b" + b"\x00" * 47),
        1.60,
    )
    add(
        Ether()
        / IP(src=GATEWAY, dst=CLIENT)
        / UDP(sport=123, dport=55000)
        / Raw(load=b"\x1c" + b"\x00" * 47),
        1.65,
    )

    # --- Flow 6: SSH handshake (TCP/22) ---------------------------------
    add(
        Ether()
        / IP(src=SSH_CLIENT, dst=SSH_SERVER)
        / TCP(sport=52000, dport=22, flags="S", seq=5000),
        2.10,
    )
    add(
        Ether()
        / IP(src=SSH_SERVER, dst=SSH_CLIENT)
        / TCP(sport=22, dport=52000, flags="SA", seq=6000, ack=5001),
        2.16,
    )
    add(
        Ether()
        / IP(src=SSH_CLIENT, dst=SSH_SERVER)
        / TCP(sport=52000, dport=22, flags="A", seq=5001, ack=6001)
        / Raw(load=b"SSH-2.0-NetSentry_1.0\r\n"),
        2.20,
    )

    return packets


def main():
    packets = build_packets()

    for output_path in OUTPUT_PATHS:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        wrpcap(str(output_path), packets)

        # Verify the file parses back and has a valid capture signature.
        with output_path.open("rb") as handle:
            signature = handle.read(4)

        valid_signatures = {
            bytes.fromhex("d4c3b2a1"),
            bytes.fromhex("a1b2c3d4"),
            bytes.fromhex("4d3cb2a1"),
            bytes.fromhex("a1b23c4d"),
            bytes.fromhex("0a0d0d0a"),
        }

        if signature not in valid_signatures:
            raise RuntimeError(
                f"Unexpected capture signature for {output_path}: "
                f"{signature.hex()}"
            )

        verified = rdpcap(str(output_path))

        print(f"Written {output_path.relative_to(PROJECT_ROOT)}")
        print(f"  packets : {len(verified)}")
        print(f"  size    : {output_path.stat().st_size} bytes")
        print(f"  magic   : {signature.hex()}")

    print("Sample PCAP generation: SUCCESS")


if __name__ == "__main__":
    main()

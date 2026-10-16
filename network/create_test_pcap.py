
from pathlib import Path
from scapy.all import Ether, IP, TCP, UDP, ICMP, Raw, wrpcap

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "datasets" / "raw" / "netsentry_test.pcap"

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

packets = []

# Create sample TCP traffic
for i in range(15):
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=50000, dport=80, seq=i + 1, flags="PA")
        / Raw(load=f"HTTP test packet {i}".encode())
    )
    packet.time = 1700000000 + i * 0.1
    packets.append(packet)

# Create sample UDP traffic
for i in range(10):
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.30")
        / UDP(sport=53000, dport=53)
        / Raw(load=f"DNS test packet {i}".encode())
    )
    packet.time = 1700000100 + i * 0.2
    packets.append(packet)

# Create sample ICMP traffic
for i in range(5):
    packet = (
        Ether()
        / IP(src="192.168.1.10", dst="192.168.1.40")
        / ICMP()
        / Raw(load=b"NetSentry ICMP test")
    )
    packet.time = 1700000200 + i * 0.5
    packets.append(packet)

wrpcap(str(OUTPUT), packets)

print("PCAP created successfully.")
print(f"File: {OUTPUT}")
print(f"Packets: {len(packets)}")
print("Traffic: TCP, UDP, and ICMP")
print("Note: This is synthetic test traffic, not a live capture.")

from pathlib import Path

from scapy.all import rdpcap


def analyze_pcap(file_path: Path) -> dict:
    """
    Read a PCAP/PCAPNG file and return basic packet statistics.
    """

    packets = rdpcap(str(file_path))

    protocol_counts = {
        "TCP": 0,
        "UDP": 0,
        "ICMP": 0,
        "OTHER": 0,
    }

    packet_details = []

    for index, packet in enumerate(packets[:20], start=1):

        if packet.haslayer("TCP"):
            protocol = "TCP"
            protocol_counts["TCP"] += 1

        elif packet.haslayer("UDP"):
            protocol = "UDP"
            protocol_counts["UDP"] += 1

        elif packet.haslayer("ICMP"):
            protocol = "ICMP"
            protocol_counts["ICMP"] += 1

        else:
            protocol = "OTHER"
            protocol_counts["OTHER"] += 1

        source_ip = None
        destination_ip = None

        if packet.haslayer("IP"):
            source_ip = packet["IP"].src
            destination_ip = packet["IP"].dst

        packet_details.append(
            {
                "packet_number": index,
                "protocol": protocol,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "packet_size": len(packet),
            }
        )

    return {
        "total_packets": len(packets),
        "protocol_counts": protocol_counts,
        "sample_packets": packet_details,
    }
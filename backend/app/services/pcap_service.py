from pathlib import Path

from network.flow_engine import analyze_pcap


def analyze_pcap_file(pcap_path: Path):
    """
    Analyze an uploaded PCAP/PCAPNG file
    using the NetSentry flow engine.
    """

    flows = analyze_pcap(str(pcap_path))

    protocol_counts = {}
    sample_packets = []

    total_packets = 0

    for flow in flows:
        protocol = str(flow.get("protocol", "OTHER"))

        protocol_counts[protocol] = (
            protocol_counts.get(protocol, 0) + 1
        )

        packet_count = flow.get("packet_count", 0)
        total_packets += packet_count

    for index, flow in enumerate(flows[:10], start=1):
        sample_packets.append({
            "flow_number": index,
            "protocol": flow.get("protocol", "OTHER"),
            "packet_count": flow.get("packet_count", 0),
            "total_bytes": flow.get("total_bytes", 0),
            "duration": flow.get("duration", 0),
            "source_ip": flow.get("source_ip"),
            "destination_ip": flow.get("destination_ip"),
            "source_port": flow.get("source_port"),
            "destination_port": flow.get("destination_port")
        })

    return {
        "total_packets": total_packets,
        "total_flows": len(flows),
        "protocol_counts": protocol_counts,
        "sample_flows": sample_packets
    }
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, UDP, rdpcap


def get_flow_key(packet):
    """
    Create a bidirectional flow key.

    A flow is identified by:
    source/destination IP,
    source/destination port,
    and protocol.
    """

    if not packet.haslayer(IP):
        return None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    else:
        protocol = str(packet[IP].proto)
        src_port = 0
        dst_port = 0

    endpoint_1 = (src_ip, src_port)
    endpoint_2 = (dst_ip, dst_port)

    if endpoint_1 <= endpoint_2:
        return (
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        )

    return (
        dst_ip,
        src_ip,
        dst_port,
        src_port,
        protocol,
    )


def build_flows(packets):
    """
    Group packets into bidirectional flows.
    """

    flows = defaultdict(list)

    for packet in packets:
        key = get_flow_key(packet)

        if key is not None:
            flows[key].append(packet)

    return flows


def extract_flow_features(flows):
    """
    Convert each flow into an ML-ready feature record.
    """

    results = []

    for flow_id, packets in flows.items():

        if not packets:
            continue

        first_packet = packets[0]
        last_packet = packets[-1]

        start_time = float(first_packet.time)
        end_time = float(last_packet.time)

        duration = max(end_time - start_time, 0.0)

        total_bytes = sum(len(packet) for packet in packets)
        packet_count = len(packets)

        packet_rate = (
            packet_count / duration
            if duration > 0
            else 0.0
        )

        byte_rate = (
            total_bytes / duration
            if duration > 0
            else 0.0
        )

        packet_sizes = [
            len(packet)
            for packet in packets
        ]

        average_packet_size = (
            sum(packet_sizes) / packet_count
            if packet_count > 0
            else 0.0
        )

        min_packet_size = (
            min(packet_sizes)
            if packet_sizes
            else 0
        )

        max_packet_size = (
            max(packet_sizes)
            if packet_sizes
            else 0
        )

        # Directional statistics
        endpoint_a = (
            flow_id[0],
            flow_id[2],
        )

        forward_packets = 0
        backward_packets = 0
        forward_bytes = 0
        backward_bytes = 0

        for packet in packets:

            if not packet.haslayer(IP):
                continue

            packet_endpoint = (
                packet[IP].src,
                (
                    packet[TCP].sport
                    if packet.haslayer(TCP)
                    else packet[UDP].sport
                    if packet.haslayer(UDP)
                    else 0
                ),
            )

            packet_size = len(packet)

            if packet_endpoint == endpoint_a:
                forward_packets += 1
                forward_bytes += packet_size
            else:
                backward_packets += 1
                backward_bytes += packet_size

        results.append(
            {
                "flow_id": len(results) + 1,

                "src_ip": flow_id[0],
                "dst_ip": flow_id[1],

                "src_port": flow_id[2],
                "dst_port": flow_id[3],

                "protocol": flow_id[4],

                "packet_count": packet_count,
                "total_bytes": total_bytes,

                "duration": round(duration, 6),

                "packet_rate": round(
                    packet_rate,
                    4,
                ),

                "byte_rate": round(
                    byte_rate,
                    4,
                ),

                "average_packet_size": round(
                    average_packet_size,
                    4,
                ),

                "min_packet_size": min_packet_size,
                "max_packet_size": max_packet_size,

                "forward_packets": forward_packets,
                "backward_packets": backward_packets,

                "forward_bytes": forward_bytes,
                "backward_bytes": backward_bytes,
            }
        )

    return results


def analyze_pcap(pcap_file: Path):
    """
    Read a PCAP/PCAPNG file and generate
    flow-level behavioral features.
    """

    packets = rdpcap(str(pcap_file))

    flows = build_flows(packets)

    features = extract_flow_features(flows)

    return {
        "total_packets": len(packets),
        "total_flows": len(flows),
        "flows": features,
    }
from collections import defaultdict
from pathlib import Path

from scapy.all import IP, TCP, UDP, rdpcap


# A flow is closed after this much inactivity.
FLOW_TIMEOUT = 60.0


def get_packet_endpoint(packet):
    """Return (IP, port) for a packet."""

    if not packet.haslayer(IP):
        return None

    ip = packet[IP]

    if packet.haslayer(TCP):
        port = packet[TCP].sport
    elif packet.haslayer(UDP):
        port = packet[UDP].sport
    else:
        port = 0

    return ip.src, port


def get_flow_identity(packet):
    """
    Return a normalized bidirectional flow identity.

    TCP/UDP:
        src IP, dst IP, src port, dst port, protocol

    Other IP traffic:
        src IP, dst IP, 0, 0, protocol
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
        protocol = "ICMP" if packet[IP].proto == 1 else str(packet[IP].proto)
        src_port = 0
        dst_port = 0

    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)

    if endpoint_a <= endpoint_b:
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
    Build bidirectional flows with an inactivity timeout.

    A new flow is created when the same normalized flow
    becomes inactive for more than FLOW_TIMEOUT seconds.
    """

    active_flows = {}
    completed_flows = []

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        key = get_flow_identity(packet)

        if key is None:
            continue

        timestamp = float(packet.time)

        # Check whether this flow already exists.
        if key in active_flows:

            flow = active_flows[key]

            if timestamp - flow["last_seen"] > FLOW_TIMEOUT:
                completed_flows.append(flow)

                flow = {
                    "key": key,
                    "packets": [],
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                }

                active_flows[key] = flow

        else:
            flow = {
                "key": key,
                "packets": [],
                "first_seen": timestamp,
                "last_seen": timestamp,
            }

            active_flows[key] = flow

        flow["packets"].append(packet)
        flow["last_seen"] = timestamp

    # Finish remaining active flows.
    completed_flows.extend(active_flows.values())

    return completed_flows


def extract_flow_features(flows):
    """Convert reconstructed flows into ML-ready feature records."""

    results = []

    for flow_number, flow in enumerate(flows, start=1):

        packets = flow["packets"]

        if not packets:
            continue

        key = flow["key"]

        src_ip = key[0]
        dst_ip = key[1]
        src_port = key[2]
        dst_port = key[3]
        protocol = key[4]

        first_seen = flow["first_seen"]
        last_seen = flow["last_seen"]

        duration = max(last_seen - first_seen, 0.0)

        packet_count = len(packets)

        packet_sizes = [
            len(packet)
            for packet in packets
        ]

        total_bytes = sum(packet_sizes)

        average_packet_size = (
            total_bytes / packet_count
            if packet_count
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

        # First endpoint defines the forward direction.
        forward_endpoint = (
            src_ip,
            src_port,
        )

        forward_packets = 0
        backward_packets = 0
        forward_bytes = 0
        backward_bytes = 0

        for packet in packets:

            endpoint = get_packet_endpoint(packet)

            if endpoint == forward_endpoint:

                forward_packets += 1
                forward_bytes += len(packet)

            else:

                backward_packets += 1
                backward_bytes += len(packet)

        results.append(
            {
                "flow_id": flow_number,

                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "src_port": src_port,
                "dst_port": dst_port,

                "protocol": protocol,

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

                "start_time": first_seen,
                "end_time": last_seen,
            }
        )

    return results


def analyze_pcap(pcap_file: Path):
    """Read a PCAP/PCAPNG file and extract flow features."""

    packets = rdpcap(str(pcap_file))

    flows = build_flows(packets)

    features = extract_flow_features(flows)

    return {
        "total_packets": len(packets),
        "total_flows": len(features),
        "flows": features,
    }
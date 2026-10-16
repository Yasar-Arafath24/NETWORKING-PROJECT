
"""Extract bidirectional network flows from PCAP and PCAPNG files."""

from collections import defaultdict
from pathlib import Path

from scapy.all import IP, IPv6, TCP, UDP, ICMP, PcapReader


def _packet_details(packet):
    """Return IPs, ports, protocol, and packet size for supported packets."""
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
    else:
        return None

    if TCP in packet:
        transport = packet[TCP]
        protocol = "TCP"
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
    elif UDP in packet:
        transport = packet[UDP]
        protocol = "UDP"
        src_port = int(transport.sport)
        dst_port = int(transport.dport)
    elif ICMP in packet:
        protocol = "ICMP"
        src_port = 0
        dst_port = 0
    else:
        # Ignore other IP protocols in this initial flow engine.
        return None

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": len(packet),
        "timestamp": float(packet.time),
    }


def analyze_pcap(file_path: Path | str) -> dict:
    """Read a capture and return packet totals and bidirectional flow statistics."""
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    # Each key is independent of packet direction, so replies join the same flow.
    flow_data = {}

    total_packets = 0

    with PcapReader(str(path)) as reader:
        for packet in reader:
            total_packets += 1
            details = _packet_details(packet)

            if details is None:
                continue

            src = (
                details["src_ip"],
                details["src_port"],
            )
            dst = (
                details["dst_ip"],
                details["dst_port"],
            )

            # Canonical endpoint ordering groups both traffic directions.
            if src <= dst:
                endpoint_a, endpoint_b = src, dst
            else:
                endpoint_a, endpoint_b = dst, src

            key = (
                details["protocol"],
                endpoint_a,
                endpoint_b,
            )

            if key not in flow_data:
                flow_data[key] = {
                    "first_src": src,
                    "first_dst": dst,
                    "src_ip": details["src_ip"],
                    "dst_ip": details["dst_ip"],
                    "src_port": details["src_port"],
                    "dst_port": details["dst_port"],
                    "protocol": details["protocol"],
                    "packet_sizes": [],
                    "timestamps": [],
                    "forward_packets": 0,
                    "backward_packets": 0,
                    "forward_bytes": 0,
                    "backward_bytes": 0,
                }

            flow = flow_data[key]
            size = details["size"]

            flow["packet_sizes"].append(size)
            flow["timestamps"].append(details["timestamp"])

            if src == flow["first_src"] and dst == flow["first_dst"]:
                flow["forward_packets"] += 1
                flow["forward_bytes"] += size
            else:
                flow["backward_packets"] += 1
                flow["backward_bytes"] += size

    flows = []

    for flow_id, data in enumerate(flow_data.values(), start=1):
        sizes = data["packet_sizes"]
        timestamps = data["timestamps"]

        packet_count = len(sizes)
        total_bytes = sum(sizes)
        duration = max(timestamps) - min(timestamps) if timestamps else 0.0

        flows.append({
            "flow_id": flow_id,
            "src_ip": data["src_ip"],
            "dst_ip": data["dst_ip"],
            "src_port": data["src_port"],
            "dst_port": data["dst_port"],
            "protocol": data["protocol"],
            "packet_count": packet_count,
            "total_bytes": total_bytes,
            "duration": duration,
            "packet_rate": packet_count / duration if duration > 0 else 0.0,
            "byte_rate": total_bytes / duration if duration > 0 else 0.0,
            "average_packet_size": total_bytes / packet_count if packet_count else 0.0,
            "min_packet_size": min(sizes) if sizes else 0,
            "max_packet_size": max(sizes) if sizes else 0,
            "forward_packets": data["forward_packets"],
            "backward_packets": data["backward_packets"],
            "forward_bytes": data["forward_bytes"],
            "backward_bytes": data["backward_bytes"],
        })

    return {
        "total_packets": total_packets,
        "total_flows": len(flows),
        "flows": flows,
    }

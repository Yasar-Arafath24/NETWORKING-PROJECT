from pathlib import Path

from flow_engine import analyze_pcap


PROJECT_ROOT = Path(__file__).resolve().parent.parent

PCAP_FILE = (
    PROJECT_ROOT
    / "datasets"
    / "raw"
    / "phase1_test_capture.pcapng"
)


def main():

    print("=" * 60)
    print("NetSentry AI - Flow Engine Test")
    print("=" * 60)

    print(f"PCAP: {PCAP_FILE}")
    print()

    if not PCAP_FILE.exists():
        print("ERROR: PCAP file not found.")
        return

    result = analyze_pcap(PCAP_FILE)

    print(f"Total packets : {result['total_packets']}")
    print(f"Total flows   : {result['total_flows']}")
    print()

    for flow in result["flows"][:10]:

        print("-" * 60)

        print(
            f"Flow {flow['flow_id']}: "
            f"{flow['src_ip']}:{flow['src_port']} "
            f"-> "
            f"{flow['dst_ip']}:{flow['dst_port']}"
        )

        print(f"Protocol           : {flow['protocol']}")
        print(f"Packets            : {flow['packet_count']}")
        print(f"Total bytes        : {flow['total_bytes']}")
        print(f"Duration           : {flow['duration']}")
        print(f"Packet rate        : {flow['packet_rate']}")
        print(f"Byte rate          : {flow['byte_rate']}")
        print(
            f"Average packet     : "
            f"{flow['average_packet_size']}"
        )

        print(
            f"Forward packets    : "
            f"{flow['forward_packets']}"
        )

        print(
            f"Backward packets   : "
            f"{flow['backward_packets']}"
        )

        print(
            f"Forward bytes      : "
            f"{flow['forward_bytes']}"
        )

        print(
            f"Backward bytes     : "
            f"{flow['backward_bytes']}"
        )

    print()
    print("=" * 60)
    print("Flow Engine: SUCCESS")
    print("=" * 60)


if __name__ == "__main__":
    main()
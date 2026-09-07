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

    if not PCAP_FILE.exists():
        print("ERROR: PCAP file not found.")
        return

    result = analyze_pcap(PCAP_FILE)

    print()
    print(f"Total packets : {result['total_packets']}")
    print(f"Total flows   : {result['total_flows']}")

    print()
    print("First 10 flows:")
    print("-" * 60)

    for flow in result["flows"][:10]:

        print(
            f"{flow['src_ip']}:{flow['src_port']} "
            f"→ "
            f"{flow['dst_ip']}:{flow['dst_port']} "
            f"| {flow['protocol']} "
            f"| packets={flow['packet_count']} "
            f"| bytes={flow['total_bytes']} "
            f"| duration={flow['duration']}s"
        )

    print()
    print("Flow Engine: SUCCESS")


if __name__ == "__main__":
    main()
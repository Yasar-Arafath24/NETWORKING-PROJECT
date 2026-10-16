
import sys
from pathlib import Path


# Locate the project root
PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from network.flow_engine import analyze_pcap  # noqa: E402


# Find any available PCAP or PCAPNG file
RAW_DIR = PROJECT_ROOT / "datasets" / "raw"


def find_capture() -> Path:
    captures = sorted(
        path
        for path in RAW_DIR.rglob("*")
        if path.is_file()
        and path.suffix.lower() in {".pcap", ".pcapng"}
    )

    if not captures:
        raise FileNotFoundError(
            f"No .pcap or .pcapng files found in: {RAW_DIR}"
        )

    return captures[0]


def main():
    print("=" * 60)
    print("NetSentry AI - Flow Engine Test")
    print("=" * 60)

    try:
        pcap_file = find_capture()
    except FileNotFoundError as exc:
        print(f"\nERROR: {exc}")
        raise SystemExit(1) from exc

    print(f"PCAP: {pcap_file}")
    print()

    try:
        result = analyze_pcap(pcap_file)

        print(f"Total packets : {result['total_packets']}")
        print(f"Total flows   : {result['total_flows']}")
        print()

        for flow in result.get("flows", [])[:10]:
            print("-" * 60)

            print(
                f"Flow {flow.get('flow_id', 'N/A')}: "
                f"{flow.get('src_ip', 'N/A')}:"
                f"{flow.get('src_port', 'N/A')} -> "
                f"{flow.get('dst_ip', 'N/A')}:"
                f"{flow.get('dst_port', 'N/A')}"
            )

            fields = [
                ("Protocol", "protocol"),
                ("Packets", "packet_count"),
                ("Total bytes", "total_bytes"),
                ("Duration", "duration"),
                ("Packet rate", "packet_rate"),
                ("Byte rate", "byte_rate"),
                ("Average packet size", "average_packet_size"),
                ("Forward packets", "forward_packets"),
                ("Backward packets", "backward_packets"),
                ("Forward bytes", "forward_bytes"),
                ("Backward bytes", "backward_bytes"),
            ]

            for label, key in fields:
                print(f"{label:<22}: {flow.get(key, 'N/A')}")

        print()
        print("=" * 60)
        print("Flow Engine: SUCCESS")
        print("=" * 60)

    except Exception as exc:
        print(f"\nERROR: Flow analysis failed: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

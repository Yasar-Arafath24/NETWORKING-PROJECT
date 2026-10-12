
"""Extract machine-learning features from PCAP network flows."""

import argparse
import csv
from pathlib import Path

from network.flow_engine import analyze_pcap


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "datasets" / "processed" / "flow_features.csv"


CSV_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "duration",
    "packet_count",
    "total_bytes",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "min_packet_size",
    "max_packet_size",
]



def extract_features(pcap_path: Path) -> list[dict]:
    """Convert flow-engine results into feature rows."""
    result = analyze_pcap(Path(pcap_path))
    flows = result.get("flows", [])

    rows = []
    for flow in flows:
        row = {column: flow.get(column) for column in CSV_COLUMNS}
        rows.append(row)

    return rows


def save_features(rows: list[dict], output_path: Path) -> None:
    """Save extracted features as a CSV file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract network flow features from a PCAP file."
    )
    parser.add_argument(
        "pcap",
        type=Path,
        help="Path to a .pcap or .pcapng file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output CSV path",
    )
    args = parser.parse_args()

    if not args.pcap.is_file():
        parser.error(f"PCAP file does not exist: {args.pcap}")

    rows = extract_features(args.pcap)
    save_features(rows, args.output)

    print("=" * 55)
    print("NetSentry AI - Feature Extraction")
    print("=" * 55)
    print(f"Input PCAP:      {args.pcap}")
    print(f"Flows extracted: {len(rows)}")
    print(f"Output CSV:      {args.output}")

    if not rows:
        print("WARNING: No flows were extracted. Check the PCAP and flow engine.")


if __name__ == "__main__":
    main()

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

    
import pandas as pd

from network.flow_engine import analyze_pcap


PROJECT_ROOT = Path(__file__).resolve().parent.parent

RAW_DIR = PROJECT_ROOT / "datasets" / "raw"
OUTPUT_DIR = PROJECT_ROOT / "datasets" / "processed"

OUTPUT_FILE = OUTPUT_DIR / "flow_features.csv"


FEATURE_COLUMNS = [
    "protocol",
    "packet_count",
    "total_bytes",
    "duration",
    "packet_rate",
    "byte_rate",
    "average_packet_size",
    "min_packet_size",
    "max_packet_size",
    "forward_packets",
    "backward_packets",
    "forward_bytes",
    "backward_bytes",
]


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    pcap_files = list(RAW_DIR.glob("*.pcap")) + list(
        RAW_DIR.glob("*.pcapng")
    )

    if not pcap_files:
        print("ERROR: No PCAP files found.")
        return

    all_rows = []

    for pcap_file in pcap_files:
        print(f"Processing: {pcap_file.name}")

        result = analyze_pcap(pcap_file)

        for flow in result["flows"]:
            row = {
                column: flow.get(column)
                for column in FEATURE_COLUMNS
            }

            row["source_file"] = pcap_file.name

            all_rows.append(row)

    if not all_rows:
        print("ERROR: No flows were extracted.")
        return

    dataframe = pd.DataFrame(all_rows)

    dataframe.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print()
    print("=" * 60)
    print("NetSentry AI - Dataset Builder")
    print("=" * 60)

    print(f"PCAP files processed : {len(pcap_files)}")
    print(f"Flows extracted      : {len(dataframe)}")
    print(f"Features             : {len(FEATURE_COLUMNS)}")
    print(f"Output               : {OUTPUT_FILE}")

    print()
    print("Dataset preview:")
    print(dataframe.head())

    print()
    print("Dataset shape:")
    print(dataframe.shape)

    print()
    print("Dataset builder: SUCCESS")


if __name__ == "__main__":
    main()
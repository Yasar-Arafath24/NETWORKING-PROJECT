import pandas as pd
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT
    / "datasets"
    / "processed"
    / "flow_features.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "datasets"
    / "processed"
    / "ml_ready_flows.csv"
)


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


def normalize_protocol(value):
    """
    Convert protocol representations into consistent names.
    """

    value = str(value).upper()

    if value == "1":
        return "ICMP"

    if value == "6":
        return "TCP"

    if value == "17":
        return "UDP"

    return value


def main():

    print("=" * 60)
    print("NetSentry AI - Dataset Preparation")
    print("=" * 60)

    if not INPUT_FILE.exists():
        print(f"ERROR: Dataset not found: {INPUT_FILE}")
        return

    dataframe = pd.read_csv(INPUT_FILE)

    print(f"Original rows: {len(dataframe)}")

    # Normalize protocol values
    dataframe["protocol"] = dataframe["protocol"].apply(
        normalize_protocol
    )

    # Remove duplicate flow records
    dataframe = dataframe.drop_duplicates(
        subset=FEATURE_COLUMNS
    ).reset_index(drop=True)

    print(f"Rows after deduplication: {len(dataframe)}")

    # Check required columns
    missing_columns = [
        column
        for column in FEATURE_COLUMNS
        if column not in dataframe.columns
    ]

    if missing_columns:
        print("ERROR: Missing columns:")
        for column in missing_columns:
            print(f"  - {column}")
        return

    # Check missing values
    missing_values = dataframe[FEATURE_COLUMNS].isnull().sum()

    print()
    print("Missing values:")
    print(missing_values)

    # Save clean dataset
    dataframe.to_csv(
        OUTPUT_FILE,
        index=False,
    )

    print()
    print("Protocol distribution:")
    print(dataframe["protocol"].value_counts())

    print()
    print(f"Output: {OUTPUT_FILE}")
    print(f"Final dataset shape: {dataframe.shape}")

    print()
    print("Dataset preparation: SUCCESS")


if __name__ == "__main__":
    main()
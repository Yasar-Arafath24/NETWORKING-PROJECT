
import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT / "datasets" / "processed" / "flow_features.csv"
)

OUTPUT_FILE = (
    PROJECT_ROOT / "datasets" / "processed" / "ml_ready_flows.csv"
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
    value = str(value).strip().upper()

    return {
        "1": "ICMP",
        "6": "TCP",
        "17": "UDP",
    }.get(value, value)


def main():
    print("=" * 60)
    print("NetSentry AI - Dataset Preparation")
    print("=" * 60)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Dataset not found: {INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    print(f"Original rows: {len(df)}")

    # Validate the schema before accessing feature columns.
    missing_columns = [
        col for col in FEATURE_COLUMNS if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    if "source_file" in df.columns:
        print("\nFlows by source file:")
        print(df.groupby("source_file").size())

    # Normalize protocol labels.
    df["protocol"] = df["protocol"].apply(normalize_protocol)

    # Convert numeric features and mark invalid values as missing.
    numeric_columns = [
        col for col in FEATURE_COLUMNS if col != "protocol"
    ]

    for col in numeric_columns:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Remove records with missing or invalid feature values.
    before_cleaning = len(df)
    df = df.dropna(subset=FEATURE_COLUMNS).copy()

    print(f"Rows removed for invalid/missing features: "
          f"{before_cleaning - len(df)}")

    # Report repeated feature vectors; do not silently remove them.
    duplicate_mask = df.duplicated(
        subset=FEATURE_COLUMNS,
        keep=False,
    )

    print(
        "Rows belonging to repeated feature vectors: "
        f"{int(duplicate_mask.sum())}"
    )

    # Preserve source_file and other available metadata.
    # Investigate repeated records before deciding whether to remove them.
    df = df.reset_index(drop=True)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print("\nProtocol distribution:")
    print(df["protocol"].value_counts())

    print(f"\nOutput: {OUTPUT_FILE}")
    print(f"Final dataset shape: {df.shape}")
    print("\nDataset preparation: SUCCESS")


if __name__ == "__main__":
    main()

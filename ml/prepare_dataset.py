
"""Prepare a clean feature dataset for NetSentry AI."""

from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent

INPUT_FILE = (
    PROJECT_ROOT / "datasets" / "processed" / "training_features.csv"
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

NUMERIC_COLUMNS = [
    col for col in FEATURE_COLUMNS if col != "protocol"
]


def normalize_protocol(value):
    """Normalize common numeric and textual protocol identifiers."""

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

    if not INPUT_FILE.is_file():
        raise FileNotFoundError(
            f"Training dataset not found: {INPUT_FILE}\n"
            "Run ml.collect_dataset first."
        )

    df = pd.read_csv(INPUT_FILE)

    print(f"Input file: {INPUT_FILE.name}")
    print(f"Original rows: {len(df)}")

    if df.empty:
        raise ValueError("The training dataset is empty.")

    missing_columns = [
        col for col in FEATURE_COLUMNS if col not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {missing_columns}"
        )

    if "source_file" in df.columns:
        print("\nRows by source CSV:")
        print(df["source_file"].value_counts(dropna=False))

    # Normalize protocol values.
    df["protocol"] = df["protocol"].apply(normalize_protocol)

    # Convert features to numeric values.
    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Remove invalid numbers, including positive and negative infinity.
    df[NUMERIC_COLUMNS] = df[NUMERIC_COLUMNS].replace(
        [float("inf"), float("-inf")],
        float("nan"),
    )

    # Keep only rows with valid values for every required feature.
    before_cleaning = len(df)
    df = df.dropna(subset=FEATURE_COLUMNS).copy()

    print(
        "\nRows removed for invalid/missing features: "
        f"{before_cleaning - len(df)}"
    )

    # Report duplicates, but retain them until their provenance is checked.
    duplicate_mask = df.duplicated(
        subset=FEATURE_COLUMNS,
        keep=False,
    )

    print(
        "Rows belonging to repeated feature vectors: "
        f"{int(duplicate_mask.sum())}"
    )

    if "source_file" in df.columns:
        print("\nRows retained by source CSV:")
        print(df["source_file"].value_counts(dropna=False))

    df = df.reset_index(drop=True)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT_FILE, index=False)

    print("\nProtocol distribution:")
    print(df["protocol"].value_counts())

    print(f"\nOutput file: {OUTPUT_FILE}")
    print(f"Final dataset shape: {df.shape}")
    print("\nDataset preparation: SUCCESS")


if __name__ == "__main__":
    main()

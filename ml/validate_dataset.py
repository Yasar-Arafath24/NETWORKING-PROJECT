
"""Validate NetSentry AI flow-feature datasets."""

from pathlib import Path

import pandas as pd


DATASET = (
    Path(__file__).resolve().parent.parent
    / "datasets"
    / "processed"
    / "training_features.csv"
)

REQUIRED_COLUMNS = [
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


def main():
    if not DATASET.is_file():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET}. Run ml.collect_dataset first."
        )

    df = pd.read_csv(DATASET)

    print("=" * 55)
    print("NetSentry AI - Dataset Validation")
    print("=" * 55)
    print(f"Dataset: {DATASET}")
    print(f"Rows: {len(df)}")

    missing = [column for column in REQUIRED_COLUMNS if column not in df.columns]
    if missing:
        print(f"FAIL: Missing required columns: {missing}")
        return

    numeric_columns = [c for c in REQUIRED_COLUMNS if c != "protocol"]
    numeric = df[numeric_columns].apply(pd.to_numeric, errors="coerce")

    print(f"Protocols: {df['protocol'].nunique(dropna=True)}")
    print(f"Rows with missing numeric values: {numeric.isna().any(axis=1).sum()}")

    invalid = (numeric < 0).any(axis=1)
    print(f"Rows with negative numeric values: {invalid.sum()}")

    if len(df) < 20:
        print("WARNING: Fewer than 20 flows; training is not recommended yet.")
    else:
        print("Flow count meets the initial 20-row check.")
        print("This does not guarantee model quality.")

    if missing:
        print("Dataset validation failed.")
    elif numeric.isna().any().any() or invalid.any():
        print("Review missing or negative values before training.")
    else:
        print("Basic dataset validation passed.")


if __name__ == "__main__":
    main()

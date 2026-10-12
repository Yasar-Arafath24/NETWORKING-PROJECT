
"""Combine feature CSV files into one training dataset."""

import argparse
from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = PROJECT_ROOT / "datasets" / "processed" / "flow_features.csv"


def collect_datasets(inputs: list[Path], output: Path) -> pd.DataFrame:
    frames = []

    for path in inputs:
        if not path.is_file():
            print(f"Skipping missing file: {path}")
            continue

        if path.resolve() == output.resolve():
            print(f"Skipping output file: {path}")
            continue

        try:
            frame = pd.read_csv(path)
        except (OSError, pd.errors.ParserError) as exc:
            print(f"Skipping unreadable CSV {path}: {exc}")
            continue

        if frame.empty:
            print(f"Skipping empty dataset: {path}")
            continue

        frame["source_file"] = path.name
        frames.append(frame)
        print(f"Loaded {len(frame)} rows from {path}")

    if not frames:
        raise ValueError("No usable feature CSV files were found.")

    combined = pd.concat(frames, ignore_index=True, sort=False)
    output.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(output, index=False)

    print(f"\nCombined rows: {len(combined)}")
    print(f"Saved dataset: {output}")
    return combined


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Combine feature CSV files for NetSentry AI."
    )
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Feature CSV files to combine",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output CSV path",
    )
    args = parser.parse_args()

    collect_datasets(args.inputs, args.output)


if __name__ == "__main__":
    main()

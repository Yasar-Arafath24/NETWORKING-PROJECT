import pandas as pd
from pathlib import Path

files = [
    Path("datasets/processed/flow_features.csv"),
    Path("datasets/processed/ml_ready_flows.csv"),
]

for file in files:
    print("\n" + "=" * 65)
    print(f"FILE: {file}")

    if not file.exists():
        print("File not found.")
        continue

    df = pd.read_csv(file)

    print(f"Rows: {len(df)}")
    print(f"Columns: {len(df.columns)}")
    print("\nColumn names:")
    print(df.columns.tolist())

    print("\nData types:")
    print(df.dtypes.to_string())

    print("\nMissing values:")
    print(df.isnull().sum().to_string())

    label_columns = [
        col for col in df.columns
        if any(word in col.lower()
               for word in ["label", "class", "target", "attack", "anomaly"])
    ]

    if label_columns:
        print("\nPossible label distributions:")
        for col in label_columns:
            print(f"\n{col}:")
            print(df[col].value_counts(dropna=False).to_string())

    print("\nFirst 5 rows:")
    print(df.head().to_string(index=False))

from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATASET_FILE = (
    PROJECT_ROOT
    / "datasets"
    / "processed"
    / "ml_ready_flows.csv"
)

MODEL_DIR = PROJECT_ROOT / "models"
MODEL_FILE = MODEL_DIR / "traffic_classifier.joblib"
LABEL_FILE = MODEL_DIR / "label_encoder.joblib"


# Features produced by our Flow Engine
FEATURE_COLUMNS = [
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

    print("=" * 60)
    print("NetSentry AI - Traffic Classification Model")
    print("=" * 60)

    # --------------------------------------------------
    # Check dataset
    # --------------------------------------------------

    if not DATASET_FILE.exists():
        print(f"ERROR: Dataset not found:")
        print(DATASET_FILE)
        return

    df = pd.read_csv(DATASET_FILE)

    print(f"Dataset rows    : {len(df)}")
    print(f"Dataset columns : {len(df.columns)}")
    print()

    # --------------------------------------------------
    # Check required columns
    # --------------------------------------------------

    missing_columns = [
        column
        for column in FEATURE_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        print("ERROR: Missing feature columns:")
        for column in missing_columns:
            print(f"  - {column}")
        return

    # --------------------------------------------------
    # Temporary label
    # --------------------------------------------------
    #
    # IMPORTANT:
    # We are using protocol only as a temporary
    # development label.
    #
    # This is NOT our final application classifier.
    #
    # Later we will replace this with proper
    # application/threat labels.
    # --------------------------------------------------

    if "protocol" not in df.columns:
        print("ERROR: protocol column not found.")
        return

    df = df.dropna(
        subset=FEATURE_COLUMNS + ["protocol"]
    )

    X = df[FEATURE_COLUMNS]
    y = df["protocol"].astype(str)

    print("Classes:")
    print(y.value_counts())
    print()

    # --------------------------------------------------
    # Check whether enough classes exist
    # --------------------------------------------------

    if y.nunique() < 2:
        print(
            "ERROR: At least two classes are required "
            "for classification."
        )
        return

    # --------------------------------------------------
    # Encode labels
    # --------------------------------------------------

    label_encoder = LabelEncoder()

    y_encoded = label_encoder.fit_transform(y)

    # --------------------------------------------------
    # Train Random Forest
    # --------------------------------------------------

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X, y_encoded)

    # --------------------------------------------------
    # Save model
    # --------------------------------------------------

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_FILE,
    )

    joblib.dump(
        label_encoder,
        LABEL_FILE,
    )

    print("Model training: SUCCESS")
    print()
    print(f"Model saved : {MODEL_FILE}")
    print(f"Labels saved: {LABEL_FILE}")
    print()

    print("Feature importance:")

    importance = sorted(
        zip(
            FEATURE_COLUMNS,
            model.feature_importances_,
        ),
        key=lambda item: item[1],
        reverse=True,
    )

    for feature, score in importance:
        print(
            f"{feature:25s} "
            f"{score:.4f}"
        )

    print()
    print("=" * 60)


if __name__ == "__main__":
    main()
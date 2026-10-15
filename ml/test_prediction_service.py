
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.prediction_service import classifier


features = {
    "packet_count": 10,
    "total_bytes": 980,
    "duration": 1.0,
    "packet_rate": 10.0,
    "byte_rate": 980.0,
    "average_packet_size": 98.0,
    "min_packet_size": 98,
    "max_packet_size": 98,
    "forward_packets": 5,
    "backward_packets": 5,
    "forward_bytes": 490,
    "backward_bytes": 490,
}


def main():
    result = classifier.predict(features)
    print("Prediction test: SUCCESS")
    print(result)


if __name__ == "__main__":
    main()

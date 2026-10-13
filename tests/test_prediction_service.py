import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent

# When a script is run directly (python tests/test_prediction_service.py),
# Python puts the script's own folder on sys.path, not the project root.
# Add the project root so the "backend" package can be imported.
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.services.prediction_service import (  # noqa: E402
    prediction_service,
)


def main():
    sample_flow = {
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

    result = prediction_service.predict_flow(sample_flow)
    print("Prediction result:")
    print(result)


if __name__ == "__main__":
    main()
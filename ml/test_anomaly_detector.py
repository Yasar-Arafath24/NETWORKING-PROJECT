
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ml.anomaly_detector import predict_anomalies  # noqa: E402

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

try:
    results = predict_anomalies([sample_flow])
    print("Prediction result:")
    print(results)
except (FileNotFoundError, ValueError) as exc:
    print(f"Test could not run: {exc}")


from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "datasets" / "processed" / "demo_flows.csv"

rng = np.random.default_rng(42)
rows = []

# Synthetic normal-flow examples for pipeline testing only.
for i in range(100):
    protocol = rng.choice(["TCP", "UDP", "ICMP"], p=[0.65, 0.25, 0.10])
    packet_count = int(rng.integers(5, 150))
    average_size = int(rng.integers(60, 1200))
    total_bytes = packet_count * average_size
    duration = float(rng.uniform(0.1, 30.0))
    forward_packets = int(rng.integers(1, packet_count + 1))
    backward_packets = packet_count - forward_packets
    forward_bytes = int(total_bytes * forward_packets / packet_count)
    backward_bytes = total_bytes - forward_bytes

    rows.append({
        "protocol": protocol,
        "packet_count": packet_count,
        "total_bytes": total_bytes,
        "duration": duration,
        "packet_rate": packet_count / duration,
        "byte_rate": total_bytes / duration,
        "average_packet_size": average_size,
        "min_packet_size": max(40, average_size - int(rng.integers(0, 30))),
        "max_packet_size": average_size + int(rng.integers(0, 100)),
        "forward_packets": forward_packets,
        "backward_packets": backward_packets,
        "forward_bytes": forward_bytes,
        "backward_bytes": backward_bytes,
        "source_file": "SYNTHETIC_DEMO_NOT_REAL_CAPTURE",
    })

OUTPUT.parent.mkdir(parents=True, exist_ok=True)
pd.DataFrame(rows).to_csv(OUTPUT, index=False)

print(f"Created {len(rows)} synthetic demo rows: {OUTPUT}")
print("These rows are for pipeline testing, not real network evidence.")

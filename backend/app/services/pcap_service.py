
from pathlib import Path

from network.flow_engine import analyze_pcap as analyze_flows


def analyze_pcap(file_path: Path | str) -> dict:
    """Extract flow statistics from a PCAP or PCAPNG file."""
    path = Path(file_path)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    result = analyze_flows(path)

    if not isinstance(result, dict):
        raise TypeError(
            "Expected flow analysis to return a dictionary, "
            f"received {type(result).__name__}"
        )

    flows = result.get("flows", [])

    if not isinstance(flows, list):
        raise TypeError("Flow analysis result must contain a list of flows")

    return {
        "total_packets": result.get("total_packets", 0),
        "total_flows": result.get("total_flows", len(flows)),
        "flows": flows[:100],
        "flows_returned": min(len(flows), 100),
    }

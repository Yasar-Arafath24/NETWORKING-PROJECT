
from pathlib import Path

from network.flow_engine import analyze_pcap as analyze_flows


MAX_FLOWS_RETURNED = 100


def analyze_pcap(file_path: Path | str) -> dict:
    """Extract and validate flow statistics from a PCAP or PCAPNG file."""

    path = Path(file_path)

    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"PCAP file not found: {path}")

    result = analyze_flows(path)

    if not isinstance(result, dict):
        raise TypeError(
            "Expected flow analysis to return a dictionary, "
            f"received {type(result).__name__}",
        )

    flows = result.get("flows", [])

    if not isinstance(flows, list):
        raise TypeError(
            "Flow analysis result must contain a list of flows",
        )

    # Validate individual records before returning them.
    valid_flows = []

    for index, flow in enumerate(flows):
        if not isinstance(flow, dict):
            raise TypeError(
                f"Flow at index {index} must be a dictionary",
            )

        valid_flows.append(flow)

    # Remove only exact duplicate dictionaries.
    # Distinct flows with different fields remain separate.
    unique_flows = []
    seen = set()

    for flow in valid_flows:
        try:
            fingerprint = repr(
                sorted(
                    (key, repr(value))
                    for key, value in flow.items()
                )
            )
        except Exception:
            # Keep the record if a stable fingerprint cannot be built.
            unique_flows.append(flow)
            continue

        if fingerprint not in seen:
            seen.add(fingerprint)
            unique_flows.append(flow)

    total_packets = int(result.get("total_packets", 0) or 0)

    return {
        "total_packets": total_packets,
        "total_flows": len(unique_flows),
        "flows": unique_flows[:MAX_FLOWS_RETURNED],
        "flows_returned": min(
            len(unique_flows),
            MAX_FLOWS_RETURNED,
        ),
        "duplicate_flow_records_removed": (
            len(valid_flows) - len(unique_flows)
        ),
    }

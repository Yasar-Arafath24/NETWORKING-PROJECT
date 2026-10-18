
from copy import deepcopy
from datetime import datetime, timezone
from threading import Lock
from typing import Any

_lock = Lock()
_latest_analysis: dict[str, Any] | None = None


def save_analysis(analysis: dict[str, Any]) -> None:
    """Save the latest analysis safely in application memory."""
    global _latest_analysis

    record = deepcopy(analysis)
    record["stored_at"] = datetime.now(timezone.utc).isoformat()

    with _lock:
        _latest_analysis = record


def get_latest_analysis() -> dict[str, Any] | None:
    """Return a copy of the latest analysis, if available."""
    with _lock:
        if _latest_analysis is None:
            return None
        return deepcopy(_latest_analysis)

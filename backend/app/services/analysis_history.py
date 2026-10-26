
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = ROOT / "data"
DB_PATH = DATA_DIR / "netsentry_history.db"


def get_connection() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        DB_PATH,
        timeout=10,
    )
    connection.row_factory = sqlite3.Row
    return connection


def initialize_history_db() -> None:
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                total_packets INTEGER NOT NULL DEFAULT 0,
                total_flows INTEGER NOT NULL DEFAULT 0,
                suspicious_flows INTEGER NOT NULL DEFAULT 0,
                result_json TEXT NOT NULL
            )
        """)
        connection.commit()


def save_analysis(
    filename: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Persist a completed analysis and return its history metadata."""
    if not isinstance(result, dict):
        raise ValueError("Analysis result must be a dictionary.")

    created_at = datetime.now(timezone.utc).isoformat()

    total_packets = int(result.get("total_packets", 0) or 0)
    total_flows = int(result.get("total_flows", 0) or 0)
    suspicious_flows = int(
        result.get(
            "suspicious_flows",
            result.get("anomalies_detected", 0),
        ) or 0
    )

    if min(total_packets, total_flows, suspicious_flows) < 0:
        raise ValueError("Analysis counts cannot be negative.")

    result_json = json.dumps(result, allow_nan=False)

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO analysis_history (
                created_at,
                filename,
                total_packets,
                total_flows,
                suspicious_flows,
                result_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                created_at,
                Path(filename).name,
                total_packets,
                total_flows,
                suspicious_flows,
                result_json,
            ),
        )
        record_id = cursor.lastrowid
        connection.commit()

    return {
        "id": record_id,
        "created_at": created_at,
        "filename": Path(filename).name,
        "total_packets": total_packets,
        "total_flows": total_flows,
        "suspicious_flows": suspicious_flows,
    }


def list_analyses(limit: int = 50) -> list[dict[str, Any]]:
    """Return the newest analysis summaries first."""
    limit = max(1, min(int(limit), 200))

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, filename, total_packets,
                   total_flows, suspicious_flows
            FROM analysis_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_analysis(record_id: int) -> dict[str, Any] | None:
    """Return one stored analysis, including its original result."""
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT id, created_at, filename, total_packets,
                   total_flows, suspicious_flows, result_json
            FROM analysis_history
            WHERE id = ?
            """,
            (record_id,),
        ).fetchone()

    if row is None:
        return None

    record = dict(row)
    record["result"] = json.loads(record.pop("result_json"))
    return record

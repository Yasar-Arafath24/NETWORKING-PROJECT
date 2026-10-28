"""Tail JSON-lines web access logs and forward request metadata to NetSentry.

Required environment:
  NETSENTRY_ACCESS_LOG   Path to the authorized site's JSON-lines access log
  NETSENTRY_INGEST_URL   Full site event endpoint URL shown in the dashboard
  NETSENTRY_INGEST_KEY   Private site ingestion key

The log file must contain one JSON object per line with at least status_code.
"""

import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


LOG_PATH = os.environ.get("NETSENTRY_ACCESS_LOG", "")
INGEST_URL = os.environ.get("NETSENTRY_INGEST_URL", "")
INGEST_KEY = os.environ.get("NETSENTRY_INGEST_KEY", "")
FIELDS = (
    "path",
    "method",
    "status_code",
    "duration_ms",
    "response_bytes",
    "source_ip",
    "user_agent",
)


def forward(record):
    payload = {key: record[key] for key in FIELDS if key in record}
    if "status_code" not in payload:
        return
    request = Request(
        INGEST_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + INGEST_KEY,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urlopen(request, timeout=10) as response:
        if response.status >= 300:
            raise RuntimeError("Ingestion returned HTTP " + str(response.status))


def main():
    if not LOG_PATH or not INGEST_URL or not INGEST_KEY:
        print("Set NETSENTRY_ACCESS_LOG, NETSENTRY_INGEST_URL, and NETSENTRY_INGEST_KEY.", file=sys.stderr)
        return 2

    print("Tailing authorized access log: " + LOG_PATH)
    print("Forwarding request metadata to NetSentry. Press Ctrl+C to stop.")
    with open(LOG_PATH, "r", encoding="utf-8") as log:
        log.seek(0, os.SEEK_END)
        while True:
            line = log.readline()
            if not line:
                time.sleep(0.25)
                continue
            try:
                forward(json.loads(line))
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                print("Skipping invalid JSON access-log record: " + str(exc), file=sys.stderr)
            except (HTTPError, URLError, TimeoutError, OSError, RuntimeError) as exc:
                print("Could not forward access-log record: " + str(exc), file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Tail an Apache access log and send one event per request to NetSentry."""

import argparse
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# Supports Apache Common Log Format and Combined Log Format.
ACCESS_RE = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^ ]+) (?P<protocol>[^\"]+)" '
    r'(?P<status_code>\d{3}) (?P<response_bytes>\d+|-)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

running = True


def stop_collector(_signum, _frame):
    global running
    running = False


def parse_access_line(line):
    match = ACCESS_RE.match(line.strip())
    if not match:
        return None

    values = match.groupdict()
    raw_path = values["path"]
    if raw_path.startswith("//"):
        raw_path = "/"

    try:
        status_code = int(values["status_code"])
        response_bytes = 0 if values["response_bytes"] == "-" else int(values["response_bytes"])
    except (TypeError, ValueError):
        return None

    return {
        "path": raw_path.split("?", 1)[0],
        "method": values["method"][:12],
        "status_code": status_code,
        "duration_ms": 0,
        "response_bytes": response_bytes,
        "source_ip": values["source_ip"],
        "user_agent": (values["user_agent"] or "")[:256],
    }


def send_event(api_url, site_id, token, event, timeout, retries):
    endpoint = f"{api_url.rstrip('/')}/api/v1/website-ingest/{site_id}/events"
    body = json.dumps(event).encode("utf-8")

    for attempt in range(retries + 1):
        request = Request(
            endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "NetSentry-Apache-Collector/1.0",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=timeout) as response:
                if response.status >= 300:
                    raise RuntimeError(f"HTTP {response.status}")
                return True
        except HTTPError as exc:
            if exc.code in (401, 404):
                raise RuntimeError(f"Ingestion rejected with HTTP {exc.code}: check the site ID and token") from exc
            if attempt == retries:
                print(f"Failed to send {event['path']}: HTTP {exc.code}", file=sys.stderr)
        except (URLError, TimeoutError, RuntimeError) as exc:
            if attempt == retries:
                print(f"Failed to send {event['path']}: {exc}", file=sys.stderr)

        if attempt < retries:
            time.sleep(min(2 ** attempt, 10))

    return False


def tail_file(path, api_url, site_id, token, timeout, retries, poll_interval, from_beginning):
    log_path = Path(path)
    if not log_path.is_file():
        raise FileNotFoundError(f"Apache log file not found: {log_path}")

    position = 0 if from_beginning else log_path.stat().st_size
    print(f"Watching {log_path} and sending events to NetSentry site {site_id}", flush=True)

    while running:
        try:
            size = log_path.stat().st_size
            if size < position:
                position = 0

            with log_path.open("r", encoding="utf-8", errors="replace") as log:
                log.seek(position)
                for line in log:
                    if not running:
                        break
                    event = parse_access_line(line)
                    if event:
                        send_event(api_url, site_id, token, event, timeout, retries)
                position = log.tell()
        except FileNotFoundError:
            pass

        time.sleep(poll_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-id", required=True, type=int, help="NetSentry monitored website ID")
    parser.add_argument("--token", default=os.getenv("NETSENTRY_INGEST_TOKEN"), help="Website ingestion token, or use NETSENTRY_INGEST_TOKEN")
    parser.add_argument("--api-url", default=os.getenv("NETSENTRY_API_URL", "http://127.0.0.1:8000"), help="NetSentry backend base URL")
    parser.add_argument("--log-file", required=True, help="Apache combined/common access log path")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--from-beginning", action="store_true", help="Process existing log entries instead of starting at the end")
    args = parser.parse_args()

    if not args.token:
        parser.error("Provide --token or set NETSENTRY_INGEST_TOKEN")

    signal.signal(signal.SIGINT, stop_collector)
    signal.signal(signal.SIGTERM, stop_collector)

    try:
        tail_file(
            args.log_file,
            args.api_url,
            args.site_id,
            args.token,
            args.timeout,
            args.retries,
            args.poll_interval,
            args.from_beginning,
        )
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"Collector stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)

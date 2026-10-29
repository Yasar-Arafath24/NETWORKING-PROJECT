#!/usr/bin/env python3
"""Collect web-server access records and ingest normalized events into NetSentry."""

import argparse
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


running = True

APACHE_RE = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^ ]+) [^"]+" '
    r'(?P<status_code>\d{3}) (?P<response_bytes>\d+|-)(?: .*?)?$'
)

NGINX_RE = re.compile(
    r'^(?P<source_ip>\S+) .* "(?P<method>[A-Z]+) (?P<path>[^ ]+) [^"]+" '
    r'(?P<status_code>\d{3}) (?P<response_bytes>\d+|-)(?:\s+(?P<duration_ms>\d+(?:\.\d+)?))?'
)

IIS_RE = re.compile(r'^(?P<source_ip>\S+) (?P<path>\S+) (?P<method>\S+) (?P<status_code>\d{3})')


def stop_collector(_signum, _frame):
    global running
    running = False


def normalize_event(data, parser=None, default_status=200):
    if isinstance(data, str):
        if parser == "apache":
            return parse_apache_line(data)
        if parser == "nginx":
            return parse_nginx_line(data)
        if parser == "iis":
            return parse_iis_line(data)
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            return None

    if not isinstance(data, dict):
        return None

    status_code = data.get("status_code", data.get("status", data.get("statusCode", default_status)))
    try:
        status_code = int(status_code)
    except (TypeError, ValueError):
        return None
    if status_code < 100 or status_code > 599:
        return None

    path = str(data.get("path", data.get("request_path", data.get("uri", data.get("url", "/")))))
    if not path.startswith("/") or path.startswith("//"):
        path = "/"
    path = path.split("?", 1)[0].split("#", 1)[0]

    method = str(data.get("method", data.get("request_method", "GET"))).upper()[:12]
    if not re.fullmatch(r"[A-Z]{1,12}", method):
        method = "GET"

    def numeric(name, alternative_names=(), default=0):
        value = data.get(name)
        for alternative in alternative_names:
            if value is None:
                value = data.get(alternative)
        try:
            return float(value) if name == "duration_ms" else int(value)
        except (TypeError, ValueError):
            return default

    event = {
        "path": path,
        "method": method,
        "status_code": status_code,
        "duration_ms": max(0, numeric("duration_ms", ("duration", "request_time_ms"))),
        "response_bytes": max(0, numeric("response_bytes", ("bytes", "body_bytes_sent", "bytes_sent", "content_length"))),
        "source_ip": str(data.get("source_ip", data.get("client_ip", data.get("remote_addr", ""))))[:64],
        "user_agent": str(data.get("user_agent", data.get("userAgent", data.get("http_user_agent", ""))))[:256],
    }
    timestamp = data.get("request_timestamp", data.get("timestamp", data.get("time")))
    if timestamp:
        if isinstance(timestamp, datetime):
            event["request_timestamp"] = timestamp.isoformat()
        else:
            value = str(timestamp).strip()
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                try:
                    parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
                except ValueError:
                    parsed = None
            if parsed is not None:
                event["request_timestamp"] = parsed.isoformat()
    return event


def parse_apache_line(line):
    match = APACHE_RE.match(line.strip())
    if not match:
        return None
    values = match.groupdict()
    return normalize_event({
        "source_ip": values["source_ip"],
        "request_timestamp": values["timestamp"],
        "method": values["method"],
        "path": values["path"],
        "status_code": values["status_code"],
        "response_bytes": 0 if values["response_bytes"] == "-" else values["response_bytes"],
    }, parser="json")


def parse_nginx_line(line):
    match = NGINX_RE.match(line.strip())
    if not match:
        return None
    values = match.groupdict()
    duration = float(values["duration_ms"]) * 1000 if values["duration_ms"] else 0
    return normalize_event({
        "source_ip": values["source_ip"],
        "method": values["method"],
        "path": values["path"],
        "status_code": values["status_code"],
        "response_bytes": 0 if values["response_bytes"] == "-" else values["response_bytes"],
        "duration_ms": duration,
    }, parser="json")


def parse_iis_line(line):
    fields = line.strip().split()
    if fields and fields[0].startswith("#"):
        return None
    match = IIS_RE.match(line.strip())
    if not match:
        return None
    values = match.groupdict()
    return normalize_event({
        "source_ip": values["source_ip"],
        "method": values["method"],
        "path": values["path"],
        "status_code": values["status_code"],
    }, parser="json")


def send_event(api_url, site_id, token, event, timeout, retries):
    endpoint = f"{api_url.rstrip('/')}/api/v1/website-ingest/{site_id}/events"
    body = json.dumps(event).encode("utf-8")

    for attempt in range(retries + 1):
        request = Request(endpoint, data=body, headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "NetSentry-Generic-Collector/1.0",
        }, method="POST")
        try:
            with urlopen(request, timeout=timeout) as response:
                if response.status >= 300:
                    raise RuntimeError(f"HTTP {response.status}")
                return True
        except HTTPError as exc:
            if exc.code in (401, 404):
                raise RuntimeError(f"Ingestion rejected with HTTP {exc.code}: check the site ID and token") from exc
            print(f"Failed to send {event['path']}: HTTP {exc.code}", file=sys.stderr)
        except (URLError, TimeoutError, RuntimeError) as exc:
            print(f"Failed to send {event['path']}: {exc}", file=sys.stderr)
        if attempt < retries:
            time.sleep(min(2 ** attempt, 10))
    return False


def process_line(line, parser):
    event = normalize_event(line, parser=parser)
    if event:
        return event
    return None


def tail_file(path, api_url, site_id, token, parser, timeout, retries, poll_interval, from_beginning):
    log_path = Path(path)
    if not log_path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    position = 0 if from_beginning else log_path.stat().st_size
    print(f"Watching {log_path} with the {parser} parser and sending events to site {site_id}", flush=True)

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
                    event = process_line(line, parser)
                    if event:
                        send_event(api_url, site_id, token, event, timeout, retries)
                position = log.tell()
        except FileNotFoundError:
            pass
        time.sleep(poll_interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-id", required=True, type=int)
    parser.add_argument("--token", default=os.getenv("NETSENTRY_INGEST_TOKEN"))
    parser.add_argument("--api-url", default=os.getenv("NETSENTRY_API_URL", "http://127.0.0.1:8000"))
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--format", choices=("jsonl", "apache", "nginx", "iis"), default="jsonl")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--from-beginning", action="store_true")
    args = parser.parse_args()

    if not args.token:
        parser.error("Provide --token or set NETSENTRY_INGEST_TOKEN")

    signal.signal(signal.SIGINT, stop_collector)
    signal.signal(signal.SIGTERM, stop_collector)

    try:
        tail_file(args.log_file, args.api_url, args.site_id, args.token, args.format, args.timeout, args.retries, args.poll_interval, args.from_beginning)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"Collector stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)

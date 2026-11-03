#!/usr/bin/env python3
"""Collect web-server access records and ingest normalized events into NetSentry."""

import argparse
import hashlib
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


running = True

APACHE_RE = re.compile(
    r'^(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^ ]+) [^"]+" '
    r'(?P<status_code>\d{3}) (?P<response_bytes>\d+|-)'
    r'(?:\s+(?P<duration_us>\d+(?:\.\d+)?))?(?:\s+.*)?$'
)

NGINX_RE = re.compile(
    r'^(?P<source_ip>\S+) .* "(?P<method>[A-Z]+) (?P<path>[^ ]+) [^"]+" '
    r'(?P<status_code>\d{3}) (?P<response_bytes>\d+|-)(?:\s+(?P<duration_ms>\d+(?:\.\d+)?))?'
)

IIS_RE = re.compile(r'^(?P<source_ip>\S+) (?P<path>\S+) (?P<method>\S+) (?P<status_code>\d{3})')
IIS_DEFAULT_FIELDS = ["date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query", "s-port", "cs-username", "c-ip", "cs(User-Agent)", "cs(Referer)", "sc-status", "sc-substatus", "sc-win32-status", "time-taken"]
_iis_fields = list(IIS_DEFAULT_FIELDS)


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

    event = {
        "path": path,
        "method": method,
        "status_code": status_code,
        "response_bytes": max(0, numeric_value(data, "response_bytes", ("bytes", "body_bytes_sent", "bytes_sent", "content_length"), integer=True)),
        "source_ip": str(data.get("source_ip", data.get("client_ip", data.get("remote_addr", ""))))[:64],
        "user_agent": str(data.get("user_agent", data.get("userAgent", data.get("http_user_agent", ""))))[:256],
    }
    duration_value = data.get("duration_ms", data.get("duration", data.get("request_time_ms")))
    if duration_value is not None:
        try:
            event["duration_ms"] = max(0, float(duration_value))
        except (TypeError, ValueError):
            pass
    event_id = data.get("event_id")
    if event_id:
        event["event_id"] = str(event_id)[:128]
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


def numeric_value(data, name, alternative_names=(), default=0, integer=False):
    value = data.get(name)
    for alternative in alternative_names:
        if value is None:
            value = data.get(alternative)
    try:
        return int(value) if integer else float(value)
    except (TypeError, ValueError):
        return default


def parse_apache_line(line):
    match = APACHE_RE.match(line.strip())
    if not match:
        return None
    values = match.groupdict()
    data = {
        "source_ip": values["source_ip"],
        "request_timestamp": values["timestamp"],
        "method": values["method"],
        "path": values["path"],
        "status_code": values["status_code"],
        "response_bytes": 0 if values["response_bytes"] == "-" else values["response_bytes"],
    }
    if values["duration_us"] is not None:
        data["duration_ms"] = float(values["duration_us"]) / 1000
    return normalize_event(data, parser="json")


def parse_nginx_line(line):
    match = NGINX_RE.match(line.strip())
    if not match:
        return None
    values = match.groupdict()
    data = {
        "source_ip": values["source_ip"],
        "method": values["method"],
        "path": values["path"],
        "status_code": values["status_code"],
        "response_bytes": 0 if values["response_bytes"] == "-" else values["response_bytes"],
    }
    if values["duration_ms"] is not None:
        data["duration_ms"] = float(values["duration_ms"]) * 1000
    return normalize_event(data, parser="json")


def parse_iis_line(line):
    global _iis_fields
    stripped = line.strip()
    if stripped.lower().startswith("#fields:"):
        _iis_fields = stripped.split(":", 1)[1].strip().split()
        return None
    if stripped.startswith("#"):
        return None
    fields = stripped.split()
    if "c-ip" in _iis_fields and "cs-uri-stem" in _iis_fields and "cs-method" in _iis_fields and "sc-status" in _iis_fields:
        if len(fields) < len(_iis_fields):
            return None
        values = dict(zip(_iis_fields, fields))
        try:
            status = int(values["sc-status"])
        except (KeyError, ValueError):
            return None
        path = values.get("cs-uri-stem", "/")
        query = values.get("cs-uri-query", "-")
        if query not in {"", "-"}:
            path += "?" + query
        timestamp = None
        if values.get("date") and values.get("time"):
            timestamp = values["date"] + "T" + values["time"]
        event_data = {
            "source_ip": values.get("c-ip", ""), "method": values.get("cs-method", "GET"),
            "path": path, "status_code": status,
            "user_agent": values.get("cs(User-Agent)", ""), "request_timestamp": timestamp,
        }
        duration_value = values.get("time-taken")
        if duration_value is not None:
            try:
                event_data["duration_ms"] = max(0, int(duration_value))
            except ValueError:
                pass
        return normalize_event(event_data)
    match = IIS_RE.match(stripped)
    if not match:
        return None
    values = match.groupdict()
    return normalize_event({
        "source_ip": values["source_ip"],
        "method": values["method"],
        "path": values["path"],
        "status_code": values["status_code"],
    }, parser="json")


def _api_host(api_url):
    try:
        parsed = urlsplit(api_url)
        if not parsed.hostname:
            return "the configured API"
        host = parsed.hostname
        if parsed.port:
            host = f"{host}:{parsed.port}"
        return host
    except ValueError:
        return "the configured API"


def _invalid_token_message(api_url, site_id):
    return (
        f"TOKEN_INVALID: the API at {_api_host(api_url)} rejected the key for website ID {site_id}. "
        "Confirm the key is current, belongs to this website ID, and was generated by the same "
        "NetSentry deployment/database that serves this API origin."
    )


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
            if exc.code == 401:
                raise RuntimeError(_invalid_token_message(api_url, site_id)) from exc
            if exc.code == 404:
                raise RuntimeError(
                    f"SITE_NOT_FOUND: the API at {_api_host(api_url)} could not find the ingestion endpoint "
                    f"for website ID {site_id}. Check the API origin and website ID."
                ) from exc
            print(f"Event delivery failed with HTTP {exc.code}.", file=sys.stderr)
        except (URLError, TimeoutError, RuntimeError) as exc:
            print(f"Event delivery failed: {exc}", file=sys.stderr)
        if attempt < retries:
            time.sleep(min(2 ** attempt, 10))
    return False


def send_collector_health(api_url, site_id, token, status, timeout=5, error=""):
    """Report real collector process state without creating a traffic event."""
    endpoint = f"{api_url.rstrip('/')}/api/v1/website-ingest/{site_id}/health"
    body = json.dumps({"status": status, "error": error[:1000]}).encode("utf-8")
    request = Request(endpoint, data=body, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "NetSentry-Generic-Collector/1.0",
    }, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status < 300
    except HTTPError as exc:
        if exc.code in (401, 403):
            raise RuntimeError(_invalid_token_message(api_url, site_id)) from exc
        raise


def process_line(line, parser):
    event = normalize_event(line, parser=parser)
    if event:
        return event
    return None


def tail_file(path, api_url, site_id, token, parser, timeout, retries, poll_interval, from_beginning, heartbeat_interval=15):
    log_path = Path(path)
    if not log_path.is_file():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    position = 0 if from_beginning else log_path.stat().st_size
    file_identity = None
    if position:
        print(f"Starting at the end of {log_path}; older lines will not be sent.", flush=True)
    else:
        print(f"Reading {log_path} from its beginning.", flush=True)
    print(f"Watching site {site_id} with the {parser} parser. New matching events are sent to NetSentry.", flush=True)
    last_heartbeat = 0.0
    sent_events = 0
    warned_about_format = False
    send_collector_health(api_url, site_id, token, "RUNNING", timeout=timeout)

    while running:
        now = time.monotonic()
        if now - last_heartbeat >= heartbeat_interval:
            try:
                send_collector_health(api_url, site_id, token, "RUNNING", timeout=timeout)
            except (HTTPError, URLError, TimeoutError) as exc:
                print(f"Collector heartbeat failed: {exc}", file=sys.stderr)
            last_heartbeat = now
        try:
            file_stat = log_path.stat()
            identity = (file_stat.st_dev, file_stat.st_ino)
            if file_identity is not None and identity != file_identity:
                position = 0
            file_identity = identity
            size = file_stat.st_size
            if size < position:
                position = 0

            with log_path.open("r", encoding="utf-8", errors="replace") as log:
                log.seek(position)
                while running:
                    line_offset = log.tell()
                    line = log.readline()
                    if not line:
                        break
                    if not running:
                        break
                    event = process_line(line, parser)
                    if event:
                        file_stat = log_path.stat()
                        identity = f"{log_path.resolve()}:{file_stat.st_dev}:{file_stat.st_ino}:{line_offset}:{line.rstrip()}"
                        event.setdefault("event_id", hashlib.sha256(identity.encode("utf-8", errors="replace")).hexdigest())
                        if not send_event(api_url, site_id, token, event, timeout, retries):
                            log.seek(line_offset)
                            try:
                                send_collector_health(api_url, site_id, token, "ERROR", timeout=timeout,
                                                      error="One or more traffic events could not be delivered. Check API reachability.")
                            except Exception as exc:
                                print(f"Unable to report collector delivery error: {exc}", file=sys.stderr)
                            break
                        sent_events += 1
                        print(f"Sent event {sent_events} for site {site_id}.", flush=True)
                    elif line.strip() and not line.lstrip().startswith("#") and not warned_about_format:
                        print(
                            "A new log line did not match the selected format; no event was sent. "
                            "Check the selected parser and access-log configuration.",
                            file=sys.stderr,
                        )
                        warned_about_format = True
                position = log.tell()
        except FileNotFoundError:
            pass
        time.sleep(poll_interval)

    try:
        send_collector_health(api_url, site_id, token, "STOPPED", timeout=timeout)
    except Exception as exc:
        print(f"Unable to report collector stop: {exc}", file=sys.stderr)


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
        stop_collector(None, None)
    except Exception as exc:
        print(f"Collector stopped: {exc}", file=sys.stderr)
        try:
            send_collector_health(args.api_url, args.site_id, args.token, "ERROR", timeout=args.timeout, error=str(exc))
        except Exception as health_exc:
            print(f"Unable to report collector error: {health_exc}", file=sys.stderr)
        raise SystemExit(1)

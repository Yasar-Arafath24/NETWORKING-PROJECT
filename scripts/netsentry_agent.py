#!/usr/bin/env python3
"""Interactive, token-safe launcher for the customer-side NetSentry collector."""

import getpass
import json
import os
from pathlib import Path
import subprocess
import sys
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
COLLECTOR = ROOT / "generic_traffic_collector.py"
CONFIG = ROOT / "config.json"


def main():
    try:
        raw_config = CONFIG.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        print("config.json is missing. Extract the complete NetSentry ZIP again.", file=sys.stderr)
        raise SystemExit(2) from exc
    except OSError as exc:
        print("config.json could not be read. Check the package folder permissions.", file=sys.stderr)
        raise SystemExit(2) from exc

    try:
        config = json.loads(raw_config)
    except json.JSONDecodeError as exc:
        print("config.json is not valid JSON. Download and extract a fresh package.", file=sys.stderr)
        raise SystemExit(2) from exc

    try:
        site_id = int(config["site_id"])
        api_url = str(config["api_url"]).rstrip("/")
        log_format = config["log_format"]
    except (KeyError, TypeError, ValueError) as exc:
        print("config.json has missing or invalid website settings. Download a fresh package.", file=sys.stderr)
        raise SystemExit(2) from exc

    if site_id < 1 or log_format not in {"jsonl", "apache", "nginx", "iis"}:
        print("config.json has an invalid website ID or log format. Download a fresh package.", file=sys.stderr)
        raise SystemExit(2)
    try:
        parsed = urlsplit(api_url)
        port = parsed.port
    except ValueError as exc:
        print("config.json has an invalid API origin. Download a fresh package.", file=sys.stderr)
        raise SystemExit(2) from exc
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or (port is not None and not 1 <= port <= 65535)
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        print("config.json has an invalid API origin. Download a fresh package.", file=sys.stderr)
        raise SystemExit(2)
    if parsed.scheme != "https" and parsed.hostname.lower() not in {"localhost", "127.0.0.1", "::1"}:
        print("The API origin must use HTTPS. HTTP is allowed only for a local development API.", file=sys.stderr)
        raise SystemExit(2)

    if not COLLECTOR.is_file():
        print("generic_traffic_collector.py is missing. Extract the complete NetSentry ZIP again.", file=sys.stderr)
        raise SystemExit(2)

    print(f"NetSentry Agent - website {site_id} ({log_format.upper()})")
    print("Enter the full path to an existing, authorized access log. No website files will be changed.")
    try:
        log_path = input("Full access-log path: ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        print("\nSetup cancelled.", file=sys.stderr)
        raise SystemExit(130)
    if not log_path:
        print("No access-log path was entered.", file=sys.stderr)
        raise SystemExit(2)
    if not Path(log_path).is_file():
        print("Access-log file not found. Enter the full path to an existing log file.", file=sys.stderr)
        raise SystemExit(2)
    if not os.access(log_path, os.R_OK):
        print("Access denied. Ask the administrator for read access to this log file.", file=sys.stderr)
        raise SystemExit(2)

    if not sys.stdin.isatty():
        print("A secure interactive terminal is required to enter the collector key.", file=sys.stderr)
        print("Run this installer from an open PowerShell or Linux terminal.", file=sys.stderr)
        raise SystemExit(2)
    try:
        token = getpass.getpass("One-time NetSentry collector key (input hidden): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nSetup cancelled.", file=sys.stderr)
        raise SystemExit(130)
    if not token:
        print("A collector key is required.", file=sys.stderr)
        raise SystemExit(2)

    environment = os.environ.copy()
    environment["NETSENTRY_INGEST_TOKEN"] = token
    print(f"Starting the collector for site {site_id}. Keep this terminal open; press Ctrl+C to stop.")
    try:
        return subprocess.call(
            [
                sys.executable, str(COLLECTOR),
                "--site-id", str(site_id),
                "--api-url", api_url,
                "--log-file", str(Path(log_path).resolve()),
                "--format", log_format,
            ],
            env=environment,
            cwd=str(ROOT),
        )
    finally:
        environment.pop("NETSENTRY_INGEST_TOKEN", None)
        token = ""


if __name__ == "__main__":
    raise SystemExit(main())

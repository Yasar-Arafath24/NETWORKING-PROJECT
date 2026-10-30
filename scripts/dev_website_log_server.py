#!/usr/bin/env python3
"""Local-only HTTP site that writes real requests to a JSONL access log for NetSentry testing."""

import argparse
import json
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.parse import urlsplit


def make_handler(log_path: Path):
    lock = Lock()

    class DevSiteHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            started = time.perf_counter()
            path = urlsplit(self.path).path or "/"
            if path in {"/.env", "/.git/config"}:
                status, body = 403, b"Forbidden\n"
            elif path in {"/missing", "/404"}:
                status, body = 404, b"Not found\n"
            elif path == "/server-error":
                status, body = 500, b"Test server error\n"
            elif path == "/rate-limit":
                status, body = 429, b"Rate limited\n"
            else:
                status, body = 200, b"NetSentry local website test server\n"
            duration_ms = round((time.perf_counter() - started) * 1000, 2)
            record = {
                "request_timestamp": datetime.now(timezone.utc).isoformat(),
                "method": self.command,
                "path": path,
                "status_code": status,
                "duration_ms": duration_ms,
                "response_bytes": len(body),
                "source_ip": self.client_address[0],
                "user_agent": self.headers.get("User-Agent", "")[:256],
            }
            with lock, log_path.open("a", encoding="utf-8") as access_log:
                access_log.write(json.dumps(record, separators=(",", ":")) + "\n")
                access_log.flush()
            self.send_response(status)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            pass

    return DevSiteHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="Bind locally by default; do not expose this test server publicly.")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--log-file", default="datasets/dev-website-access.jsonl")
    args = parser.parse_args()
    log_path = Path(args.log_file).resolve()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((args.host, args.port), make_handler(log_path))
    print(f"Local test site: http://{args.host}:{server.server_port}", flush=True)
    print(f"Writing actual request metadata to: {log_path}", flush=True)
    print("Try /, /.env, /missing, /rate-limit, and /server-error. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()

import json

from scripts import generic_traffic_collector
from scripts.generic_traffic_collector import normalize_event, parse_apache_line, parse_iis_line


def test_normalize_json_event_preserves_request_time_and_strips_query():
    event = normalize_event({
        "path": "/login?next=%2Fadmin",
        "method": "post",
        "status_code": 401,
        "request_timestamp": "2026-10-29T10:12:30Z",
    })

    assert event["path"] == "/login"
    assert event["method"] == "POST"
    assert event["request_timestamp"].endswith("+00:00")
    assert "duration_ms" not in event


def test_apache_collector_parser_includes_access_timestamp():
    event = parse_apache_line(
        '192.0.2.8 - - [29/Oct/2026:10:12:30 +0000] "GET /health?source=probe HTTP/1.1" 200 17'
    )

    assert event is not None
    assert event["source_ip"] == "192.0.2.8"
    assert event["path"] == "/health"
    assert event["status_code"] == 200
    assert event["request_timestamp"].startswith("2026-10-29T10:12:30")
    assert "duration_ms" not in event


def test_apache_collector_parses_microsecond_duration_and_nginx_request_time():
    apache_event = parse_apache_line(
        '192.0.2.8 - - [29/Oct/2026:10:12:30 +0000] "GET /health HTTP/1.1" 200 17 14500'
    )
    nginx_event = generic_traffic_collector.parse_nginx_line(
        '192.0.2.8 - - [29/Oct/2026:10:12:30 +0000] "GET /health HTTP/1.1" 200 17 0.0145'
    )

    assert apache_event["duration_ms"] == 14.5
    assert nginx_event["duration_ms"] == 14.5


def test_iis_collector_parses_w3c_fields_and_duration():
    assert parse_iis_line("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken") is None
    event = parse_iis_line("2026-10-30 10:20:30 192.0.2.10 GET /account - 443 - 198.51.100.8 Mozilla/5.0 - 401 0 0 125")
    assert event["source_ip"] == "198.51.100.8"
    assert event["method"] == "GET"
    assert event["path"] == "/account"
    assert event["status_code"] == 401
    assert event["duration_ms"] == 125
    no_duration = parse_iis_line("2026-10-30 10:20:30 192.0.2.10 GET /account - 443 - 198.51.100.8 Mozilla/5.0 - 401 0 0 -")
    assert "duration_ms" not in no_duration


def test_tail_file_retries_an_event_after_delivery_failure(tmp_path, monkeypatch):
    log_path = tmp_path / "access.jsonl"
    log_path.write_text('{"path":"/retry","status_code":200}\n', encoding="utf-8")
    attempts = []
    health_statuses = []

    def send_event(_api_url, _site_id, _token, event, _timeout, _retries):
        attempts.append(event["event_id"])
        if len(attempts) == 2:
            generic_traffic_collector.running = False
            return True
        return False

    monkeypatch.setattr(generic_traffic_collector, "send_event", send_event)
    monkeypatch.setattr(
        generic_traffic_collector,
        "send_collector_health",
        lambda _api_url, _site_id, _token, status, **_kwargs: health_statuses.append(status) or True,
    )
    monkeypatch.setattr(generic_traffic_collector.time, "sleep", lambda _seconds: None)
    generic_traffic_collector.running = True

    generic_traffic_collector.tail_file(
        str(log_path), "http://127.0.0.1:8000", 1, "test-token", "jsonl", 1, 0, 0, True,
    )

    assert len(attempts) == 2
    assert attempts[0] == attempts[1]
    assert "ERROR" in health_statuses
    assert health_statuses[-1] == "STOPPED"


def test_collector_health_reports_only_process_state(monkeypatch):
    captured = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["payload"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(generic_traffic_collector, "urlopen", fake_urlopen)
    assert generic_traffic_collector.send_collector_health("https://api.example", 42, "private-key", "ERROR", error="log denied")
    assert captured["url"] == "https://api.example/api/v1/website-ingest/42/health"
    assert captured["authorization"] == "Bearer private-key"
    assert captured["payload"] == {"status": "ERROR", "error": "log denied"}

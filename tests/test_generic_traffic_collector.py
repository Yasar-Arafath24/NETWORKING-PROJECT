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


def test_apache_collector_parser_includes_access_timestamp():
    event = parse_apache_line(
        '192.0.2.8 - - [29/Oct/2026:10:12:30 +0000] "GET /health?source=probe HTTP/1.1" 200 17'
    )

    assert event is not None
    assert event["source_ip"] == "192.0.2.8"
    assert event["path"] == "/health"
    assert event["status_code"] == 200
    assert event["request_timestamp"].startswith("2026-10-29T10:12:30")


def test_iis_collector_parses_w3c_fields_and_duration():
    assert parse_iis_line("#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken") is None
    event = parse_iis_line("2026-10-30 10:20:30 192.0.2.10 GET /account - 443 - 198.51.100.8 Mozilla/5.0 - 401 0 0 125")
    assert event["source_ip"] == "198.51.100.8"
    assert event["method"] == "GET"
    assert event["path"] == "/account"
    assert event["status_code"] == 401
    assert event["duration_ms"] == 125

"""Deterministic, explainable rules for authorized website access-log events."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.models.website_monitor import WebsiteTrafficEvent


SENSITIVE_PATHS = tuple(filter(None, (
    "/.env", "/.git/config", "/config.php", "/backup.zip", "/database.sql",
    "/admin", "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/phpmyadmin",
    "/server-status", "/etc/passwd", "/actuator/env", "/cgi-bin/",
)))
SCANNER_SIGNATURES = ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "acunetix", "nessus")
LOGIN_PATH = re.compile(r"(?:^|/)(?:login|signin|sign-in|authenticate|auth)(?:/|$)", re.I)


def _int_setting(name: str, default: int, minimum: int = 1, maximum: int = 100_000) -> int:
    try:
        return max(minimum, min(int(os.getenv(name, str(default))), maximum))
    except (TypeError, ValueError):
        return default


def _float_setting(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
        if not value == value or value in {float("inf"), float("-inf")}:
            return default
        return max(minimum, min(value, maximum))
    except (TypeError, ValueError):
        return default


def _path_matches(path: str, configured: tuple[str, ...]) -> bool:
    return any(path == prefix or path.startswith(prefix.rstrip("/") + "/") for prefix in configured)


def _severity(score: int) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def analyze_website_event(db: Session, site_id: int, item) -> dict:
    """Classify a real event using a bounded recent-event window.

    This is a rule-based heuristic, not a trained website ML model or attack verdict.
    """
    now = datetime.now(timezone.utc)
    path = (item.path.split("?", 1)[0].split("#", 1)[0] or "/").lower()
    method = item.method.upper()
    ip = item.source_ip.strip()
    ua = item.user_agent.strip().lower()
    recent_since = now - timedelta(minutes=5)
    if ip:
        query = db.query(WebsiteTrafficEvent).filter(
            WebsiteTrafficEvent.site_id == site_id,
            WebsiteTrafficEvent.source_ip == ip,
            WebsiteTrafficEvent.created_at >= recent_since,
        )
        recent = query.order_by(WebsiteTrafficEvent.id.desc()).limit(1000).all()
    else:
        # Do not aggregate unrelated requests when the log has no client IP.
        recent = []
    reasons: list[dict] = []

    sensitive_paths = tuple(filter(None, (part.strip().lower() for part in os.getenv(
        "NETSENTRY_SENSITIVE_PATHS", ",".join(SENSITIVE_PATHS)
    ).split(","))))
    if _path_matches(path, sensitive_paths):
        reasons.append({"category": "sensitive_path", "weight": 55,
                        "message": f"Request targeted a configured sensitive path: {path[:160]}."})

    probed_paths = {event.request_path.lower().split("?", 1)[0] for event in recent
                    if _path_matches(event.request_path.lower(), sensitive_paths)}
    if _path_matches(path, sensitive_paths):
        probed_paths.add(path)
    scan_threshold = _int_setting("NETSENTRY_WEBSITE_SCAN_PATHS", 3, 2, 50)
    if len(probed_paths) >= scan_threshold:
        reasons.append({"category": "directory_scan", "weight": 25,
                        "message": f"One source probed {len(probed_paths)} distinct sensitive paths in five minutes: {', '.join(sorted(probed_paths)[:8])}."})

    failed_login_statuses = {401, 403}
    login_failures = sum(1 for event in recent if event.method.upper() == "POST"
                         and LOGIN_PATH.search(event.request_path) and event.status_code in failed_login_statuses)
    is_failed_login = method == "POST" and bool(LOGIN_PATH.search(path)) and item.status_code in failed_login_statuses
    login_failures += int(is_failed_login)
    login_threshold = _int_setting("NETSENTRY_WEBSITE_LOGIN_FAILURES", 5, 2, 1000)
    if login_failures >= login_threshold:
        reasons.append({"category": "auth_bruteforce", "weight": 35,
                        "message": f"{login_failures} failed POST login attempts from this source were observed in five minutes."})

    minute_ago = now - timedelta(minutes=1)
    source_rate = 0
    if ip:
        source_query = db.query(func.count(WebsiteTrafficEvent.id)).filter(
            WebsiteTrafficEvent.site_id == site_id,
            WebsiteTrafficEvent.source_ip == ip,
            WebsiteTrafficEvent.created_at >= minute_ago,
        )
        source_rate = int(source_query.scalar() or 0) + 1
    source_rate_threshold = _int_setting("NETSENTRY_WEBSITE_SOURCE_RPM", 60)
    if source_rate >= source_rate_threshold:
        reasons.append({"category": "request_rate", "weight": 30,
                        "message": f"This source sent {source_rate} requests in the last minute (threshold {source_rate_threshold})."})
    baseline_per_minute = 0.0
    if ip:
        baseline_query = db.query(func.count(WebsiteTrafficEvent.id)).filter(
            WebsiteTrafficEvent.site_id == site_id,
            WebsiteTrafficEvent.created_at >= recent_since,
            WebsiteTrafficEvent.created_at < minute_ago,
        )
        baseline_query = baseline_query.filter(WebsiteTrafficEvent.source_ip == ip)
        baseline_per_minute = int(baseline_query.scalar() or 0) / 4.0
    surge_ratio = _float_setting("NETSENTRY_WEBSITE_RATE_SURGE_RATIO", 4.0, 1.0, 1000.0)
    surge_minimum = _int_setting("NETSENTRY_WEBSITE_RATE_SURGE_MINIMUM", 20)
    if baseline_per_minute > 0 and source_rate >= surge_minimum and source_rate >= baseline_per_minute * surge_ratio:
        reasons.append({"category": "rate_surge", "weight": 20,
                        "message": f"Source request rate rose to {source_rate}/min from a recent baseline of about {baseline_per_minute:.1f}/min (surge ratio {surge_ratio:g})."})
    site_rate = int(db.query(func.count(WebsiteTrafficEvent.id)).filter(
        WebsiteTrafficEvent.site_id == site_id, WebsiteTrafficEvent.created_at >= minute_ago,
    ).scalar() or 0) + 1
    site_threshold = _int_setting("NETSENTRY_WEBSITE_SITE_RPM", 120)
    if site_rate >= site_threshold and source_rate < source_rate_threshold:
        reasons.append({"category": "site_request_rate", "weight": 25,
                        "message": f"The website received {site_rate} requests in the last minute (threshold {site_threshold})."})
    endpoint_count = int(db.query(func.count(WebsiteTrafficEvent.id)).filter(
        WebsiteTrafficEvent.site_id == site_id, WebsiteTrafficEvent.request_path == path,
        WebsiteTrafficEvent.created_at >= minute_ago,
    ).scalar() or 0)
    endpoint_threshold = _int_setting("NETSENTRY_WEBSITE_ENDPOINT_RPM", 40)
    if endpoint_count + 1 >= endpoint_threshold:
        reasons.append({"category": "endpoint_request_rate", "weight": 20,
                        "message": f"Endpoint {path[:120]} received {endpoint_count + 1} requests from this source in five minutes."})

    same_status_errors = sum(1 for event in recent if event.status_code == item.status_code and item.status_code in {400, 401, 403, 404, 429, 500, 502, 503})
    same_status_errors += int(item.status_code in {400, 401, 403, 404, 429, 500, 502, 503})
    error_threshold = _int_setting("NETSENTRY_WEBSITE_ERROR_BURST", 10)
    if same_status_errors >= error_threshold:
        if item.status_code >= 500:
            category, desc = "server_error_burst", "server-side failures"
        elif item.status_code == 429:
            category, desc = "rate_limit_burst", "rate-limit responses"
        elif item.status_code in {401, 403}:
            category, desc = "auth_error_burst", "authentication or authorization failures"
        else:
            category, desc = "client_error_burst", f"HTTP {item.status_code} responses"
        reasons.append({"category": category, "weight": 20,
                        "message": f"{same_status_errors} {desc} from this source were observed in five minutes; this can indicate an application issue and is not by itself an attack verdict."})

    slow_threshold = _int_setting("NETSENTRY_WEBSITE_SLOW_MS", 5000, 1, 600_000)
    slow_count = sum(1 for event in recent if event.duration_ms >= slow_threshold)
    slow_count += int(item.duration_ms >= slow_threshold)
    slow_repeat = _int_setting("NETSENTRY_WEBSITE_SLOW_REPEAT", 3, 2, 1000)
    if item.duration_ms >= slow_threshold and slow_count >= slow_repeat:
        reasons.append({"category": "slow_request_burst", "weight": 20,
                        "message": f"{slow_count} requests from this source exceeded {slow_threshold} ms in five minutes."})

    policies = {}
    try:
        policies = json.loads(os.getenv("NETSENTRY_WEBSITE_METHOD_POLICIES", "{}"))
        if not isinstance(policies, dict):
            policies = {}
    except (TypeError, ValueError):
        policies = {}
    allowed = policies.get(path)
    if allowed is None and method in {"TRACE", "CONNECT"}:
        reasons.append({"category": "unusual_method", "weight": 35,
                        "message": f"HTTP method {method} is unusual for this endpoint; review the site's policy and request context."})
    elif isinstance(allowed, list) and method not in {str(value).upper() for value in allowed}:
        reasons.append({"category": "method_policy", "weight": 25,
                        "message": f"HTTP method {method} is not in the configured method policy for {path[:120]}."})

    signatures = tuple(filter(None, (value.strip().lower() for value in os.getenv(
        "NETSENTRY_SCANNER_USER_AGENTS", ",".join(SCANNER_SIGNATURES)
    ).split(","))))
    matched_signature = next((signature for signature in signatures if signature in ua), None)
    if matched_signature:
        reasons.append({"category": "scanner_user_agent", "weight": 20,
                        "message": f"User-agent contains the configured scanner signature {matched_signature!r}; user-agent text is supporting evidence only."})
    repeated_agent_threshold = _int_setting("NETSENTRY_WEBSITE_REPEATED_UA", 20)
    repeated_agent_count = sum(1 for event in recent if ua and event.user_agent.strip().lower() == ua) + int(bool(ua))
    if ua and repeated_agent_count >= repeated_agent_threshold and source_rate >= source_rate_threshold:
        reasons.append({"category": "automated_user_agent_burst", "weight": 10,
                        "message": f"The same user-agent generated {repeated_agent_count} requests during a high-rate source window; this is supporting automation evidence."})

    # Allow site operators to tune category weights without editing code.
    for reason in reasons:
        variable = "NETSENTRY_RISK_WEIGHT_" + reason["category"].upper()
        reason["weight"] = _int_setting(variable, reason["weight"], 0, 100)
    # Sum one maximum weight per category: repeated evidence doesn't double-count.
    unique = {}
    for reason in reasons:
        unique[reason["category"]] = reason
    reasons = list(unique.values())
    score = min(100, sum(reason["weight"] for reason in reasons))
    categories = [reason["category"] for reason in reasons]
    classification = "NORMAL" if score == 0 else ("SUSPICIOUS" if score < 75 else "ANOMALOUS")
    return {
        "detection_type": "HEURISTIC" if reasons else "NONE",
        "ml_status": "unavailable_incompatible_features",
        "classification": classification,
        "risk_score": score,
        "severity": _severity(score),
        "categories": categories,
        "reasons": reasons,
        "supporting_signals": ["missing_user_agent"] if not ua else [],
        "source_request_rate": source_rate,
    }


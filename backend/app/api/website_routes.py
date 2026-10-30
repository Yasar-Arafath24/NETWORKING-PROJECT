from collections import defaultdict
from collections import deque
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from backend.app.api.auth_routes import get_current_user
from backend.app.models.user import User, UserSession
from backend.app.models.website_monitor import MonitoredWebsite, WebsiteTrafficEvent, WebsiteSecurityAlert, WebsiteAlertStatusChange
from backend.app.services.database import SessionLocal, get_db
from backend.app.services.website_detection import analyze_website_event

router = APIRouter(prefix="/api/v1/websites", tags=["Website monitoring"])
ingest_router = APIRouter(prefix="/api/v1/website-ingest", tags=["Website traffic ingestion"])
_clients: dict[int, set[WebSocket]] = defaultdict(set)
_ingest_times: dict[int, deque[float]] = defaultdict(deque)
_ingest_lock = threading.Lock()
_rotation_times: dict[int, deque[float]] = defaultdict(deque)
logger = logging.getLogger(__name__)
WEBSITE_PLATFORMS = ("custom", "nodejs", "python", "php", "wordpress", "nginx", "apache", "iis")


class WebsiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
    platform: str = Field(default="custom", pattern="^(custom|nodejs|python|php|wordpress|nginx|apache|iis)$")
    authorization_confirmed: bool


class WebsiteEventInput(BaseModel):
    path: str = Field(default="/", max_length=512)
    method: str = Field(default="GET", max_length=12)
    status_code: int = Field(ge=100, le=599)
    duration_ms: float = Field(default=0, ge=0, le=600000)
    response_bytes: int = Field(default=0, ge=0, le=2_147_483_647)
    source_ip: str = Field(default="", max_length=64)
    user_agent: str = Field(default="", max_length=256)
    request_timestamp: datetime | None = None


class WebsiteAlertStatusInput(BaseModel):
    status: str = Field(pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")


def _site_json(site: MonitoredWebsite, *, token: str | None = None) -> dict:
    payload = {"id": site.id, "name": site.name, "url": site.url, "platform": getattr(site, "platform", "custom"), "enabled": site.enabled, "collector_revoked": bool(site.collector_revoked_at), "created_at": site.created_at}
    if token:
        payload["ingest_token"] = token
    return payload


def _owned_site(db: Session, site_id: int, user_id: int) -> MonitoredWebsite:
    site = db.query(MonitoredWebsite).filter_by(id=site_id, owner_id=user_id).first()
    if not site:
        raise HTTPException(404, "Website monitor not found.")
    return site


def _connection_state(enabled: bool, last_event: datetime | None, now: datetime | None = None, revoked_at: datetime | None = None) -> str:
    if revoked_at:
        return "REVOKED"
    if not enabled:
        return "DISCONNECTED"
    if last_event is None:
        return "WAITING_FOR_EVENTS"
    now = now or datetime.now(timezone.utc)
    if last_event.tzinfo is None:
        last_event = last_event.replace(tzinfo=timezone.utc)
    age = max(0.0, (now - last_event).total_seconds())
    try:
        connected_seconds = max(10, min(int(os.getenv("NETSENTRY_WEBSITE_CONNECTED_SECONDS", "120")), 86400))
    except ValueError:
        connected_seconds = 120
    if age <= min(15, connected_seconds):
        return "RECEIVING"
    if age <= connected_seconds:
        return "CONNECTED"
    return "IDLE"


def _website_connection_status(db: Session, site: MonitoredWebsite) -> dict:
    now = datetime.now(timezone.utc)
    row = db.query(
        func.count(WebsiteTrafficEvent.id),
        func.max(WebsiteTrafficEvent.created_at),
        func.sum(case((WebsiteTrafficEvent.severity == "HEURISTIC", 1), else_=0)),
        func.coalesce(func.sum(WebsiteTrafficEvent.response_bytes), 0),
        func.avg(WebsiteTrafficEvent.duration_ms),
    ).filter(WebsiteTrafficEvent.site_id == site.id).one()
    total_events, last_event, anomaly_count, response_bytes, average_duration = row
    last_event_aware = last_event
    if last_event_aware and last_event_aware.tzinfo is None:
        last_event_aware = last_event_aware.replace(tzinfo=timezone.utc)
    recent_since = now - timedelta(minutes=1)
    requests_per_minute = db.query(func.count(WebsiteTrafficEvent.id)).filter(
        WebsiteTrafficEvent.site_id == site.id,
        WebsiteTrafficEvent.created_at >= recent_since,
    ).scalar() or 0
    status_rows = db.query(
        WebsiteTrafficEvent.status_code,
        func.count(WebsiteTrafficEvent.id),
    ).filter(WebsiteTrafficEvent.site_id == site.id).group_by(WebsiteTrafficEvent.status_code).all()
    status_distribution = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    for status_code, count in status_rows:
        status_distribution[f"{status_code // 100}xx"] += count
    return {
        "site_id": site.id,
        "status": _connection_state(site.enabled, last_event_aware, now, site.collector_revoked_at),
        "enabled": site.enabled,
        "verified": bool(total_events),
        "total_events": int(total_events or 0),
        "anomaly_count": int(anomaly_count or 0),
        "last_event_received": last_event_aware.isoformat() if last_event_aware else None,
        "collector_last_seen": last_event_aware.isoformat() if last_event_aware else None,
        "requests_per_minute": int(requests_per_minute),
        "status_distribution": status_distribution,
        "response_bytes": int(response_bytes or 0),
        "average_duration_ms": round(float(average_duration or 0), 2),
        "source": "accepted_website_traffic_events",
    }


def _check_token_operation_rate(user_id: int) -> None:
    now = time.monotonic()
    with _ingest_lock:
        recent = _rotation_times[user_id]
        while recent and recent[0] <= now - 60:
            recent.popleft()
        if len(recent) >= 5:
            raise HTTPException(429, "Website token operation rate limit exceeded. Try again in one minute.")
        recent.append(now)


@router.post("", status_code=201)
def add_website(payload: WebsiteCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    name = payload.name.strip()
    parsed = urlsplit(payload.url.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(422, "Enter a valid http:// or https:// website URL.")
    if not payload.authorization_confirmed:
        raise HTTPException(422, "Confirm that you own or are authorized to monitor this website.")
    normalized_url = parsed.scheme.lower() + "://" + parsed.netloc.lower()
    duplicate = db.query(MonitoredWebsite.id).filter_by(owner_id=user.id, url=normalized_url).first()
    if duplicate:
        raise HTTPException(409, "This website is already registered in your account.")
    _check_token_operation_rate(user.id)
    token = secrets.token_urlsafe(36)
    site = MonitoredWebsite(name=name, url=normalized_url, platform=payload.platform, token_hash=hashlib.sha256(token.encode()).hexdigest(), owner_id=user.id, authorization_confirmed=True)
    db.add(site)
    db.commit()
    db.refresh(site)
    return _site_json(site, token=token)


@router.get("")
def list_websites(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sites = db.query(MonitoredWebsite).filter_by(owner_id=user.id).order_by(MonitoredWebsite.id.desc()).all()
    if not sites:
        return {"websites": []}
    site_ids = [site.id for site in sites]
    rows = db.query(
        WebsiteTrafficEvent.site_id,
        func.count(WebsiteTrafficEvent.id),
        func.max(WebsiteTrafficEvent.created_at),
        func.sum(case((WebsiteTrafficEvent.severity == "HEURISTIC", 1), else_=0)),
    ).filter(WebsiteTrafficEvent.site_id.in_(site_ids)).group_by(WebsiteTrafficEvent.site_id).all()
    stats = {site_id: {"total_events": int(count), "last_event_received": last_event,
                       "anomaly_count": int(anomalies or 0)}
             for site_id, count, last_event, anomalies in rows}
    now = datetime.now(timezone.utc)
    payloads = []
    for site in sites:
        data = _site_json(site)
        site_stats = stats.get(site.id, {"total_events": 0, "last_event_received": None, "anomaly_count": 0})
        last_event = site_stats["last_event_received"]
        if last_event and last_event.tzinfo is None:
            last_event = last_event.replace(tzinfo=timezone.utc)
        status = _connection_state(site.enabled, last_event, now, site.collector_revoked_at)
        data.update(site_stats)
        data["last_event_received"] = last_event.isoformat() if last_event else None
        data["collector_last_seen"] = last_event.isoformat() if last_event else None
        data["verified"] = bool(site_stats["total_events"])
        data["collector_revoked"] = bool(site.collector_revoked_at)
        data["integration_status"] = status
        data["collector_status"] = status
        payloads.append(data)
    return {"websites": payloads}


@router.get("/{site_id}/status")
def get_website_connection_status(
    site_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    site = _owned_site(db, site_id, user.id)
    return _website_connection_status(db, site)


@router.post("/{site_id}/test-connection")
def test_website_connection(
    site_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Check actual accepted ingestion records; this does not send a fake event."""
    site = _owned_site(db, site_id, user.id)
    status = _website_connection_status(db, site)
    status["message"] = (
        "An authenticated event from this website has been stored."
        if status["verified"] else
        "No authenticated event has been stored yet. Start the collector and generate a real request on the monitored site."
    )
    return status


@router.patch("/{site_id}")
async def set_website_enabled(
    site_id: int,
    enabled: bool | None = None,
    platform: str | None = Query(default=None, pattern="^(custom|nodejs|python|php|wordpress|nginx|apache|iis)$"),
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    site = _owned_site(db, site_id, user.id)
    if enabled is None and platform is None:
        raise HTTPException(422, "Provide an enabled state or platform.")
    if enabled is not None:
        if enabled and site.collector_revoked_at:
            raise HTTPException(409, "The collector key was revoked. Generate a replacement key before reconnecting.")
        site.enabled = enabled
    if platform is not None:
        site.platform = platform
    db.commit()
    if enabled is False:
        for socket in tuple(_clients.get(site_id, set())):
            try:
                await socket.close(code=1000)
            except Exception:
                pass
        _clients.pop(site_id, None)
    return _site_json(site)


@router.post("/{site_id}/rotate-token")
def rotate_website_token(site_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Replace an owned site's collector key and return the new key once."""
    _check_token_operation_rate(user.id)
    site = _owned_site(db, site_id, user.id)
    token = secrets.token_urlsafe(36)
    site.token_hash = hashlib.sha256(token.encode()).hexdigest()
    site.collector_revoked_at = None
    site.enabled = True
    db.commit()
    db.refresh(site)
    return _site_json(site, token=token)


@router.post("/{site_id}/revoke-token")
async def revoke_website_token(site_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Revoke the collector credential and stop accepting events for this site."""
    _check_token_operation_rate(user.id)
    site = _owned_site(db, site_id, user.id)
    site.token_hash = hashlib.sha256(secrets.token_bytes(48)).hexdigest()
    site.enabled = False
    site.collector_revoked_at = datetime.now(timezone.utc)
    db.commit()
    for socket in tuple(_clients.get(site_id, set())):
        try:
            await socket.close(code=1000)
        except Exception:
            pass
    _clients.pop(site_id, None)
    return {"site": _site_json(site), "status": "REVOKED"}


@router.delete("/{site_id}", status_code=204)
def delete_website(site_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    site = _owned_site(db, site_id, user.id)
    db.delete(site)
    db.commit()


@router.get("/{site_id}/events")
def list_website_events(
    site_id: int,
    skip: int = Query(default=0, ge=0, le=1_000_000),
    limit: int = Query(default=50, ge=1, le=100),
    search: str = Query(default="", max_length=100),
    method: str | None = Query(default=None, min_length=1, max_length=12),
    status_code: int | None = Query(default=None, ge=100, le=599),
    classification: str = Query(default="all", pattern="^(all|heuristic|unassessed|normal|suspicious|anomalous)$"),
    severity: str | None = Query(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _owned_site(db, site_id, user.id)
    if since and until and since > until:
        raise HTTPException(422, "The start time must be earlier than the end time.")
    base_query = db.query(WebsiteTrafficEvent).filter(WebsiteTrafficEvent.site_id == site_id)
    if since:
        base_query = base_query.filter(WebsiteTrafficEvent.created_at >= since)
    if until:
        base_query = base_query.filter(WebsiteTrafficEvent.created_at <= until)
    filtered_query = base_query
    if method:
        filtered_query = filtered_query.filter(WebsiteTrafficEvent.method == method.upper())
    if status_code is not None:
        filtered_query = filtered_query.filter(WebsiteTrafficEvent.status_code == status_code)
    if classification == "heuristic":
        filtered_query = filtered_query.filter(WebsiteTrafficEvent.severity == "HEURISTIC")
    elif classification == "unassessed":
        filtered_query = filtered_query.filter(WebsiteTrafficEvent.event_data["detection_type"].as_string() == "NONE")
    elif classification in {"normal", "suspicious", "anomalous"}:
        filtered_query = filtered_query.filter(func.lower(WebsiteTrafficEvent.event_data["classification"].as_string()) == classification)
    if severity:
        filtered_query = filtered_query.filter(WebsiteTrafficEvent.event_data["risk_severity"].as_string() == severity)
    if search.strip():
        pattern = "%" + search.strip().replace("%", r"\%").replace("_", r"\_") + "%"
        filtered_query = filtered_query.filter(or_(
            WebsiteTrafficEvent.request_path.ilike(pattern, escape="\\"),
            WebsiteTrafficEvent.source_ip.ilike(pattern, escape="\\"),
            WebsiteTrafficEvent.user_agent.ilike(pattern, escape="\\"),
        ))
    total = filtered_query.count()
    events = (
        filtered_query.order_by(WebsiteTrafficEvent.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    selected_total = base_query.count()
    status_rows = (
        base_query.with_entities(
            WebsiteTrafficEvent.status_code,
            func.count(WebsiteTrafficEvent.id),
        )
        .group_by(WebsiteTrafficEvent.status_code)
        .all()
    )
    status_distribution = {"1xx": 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
    for status, count in status_rows:
        status_distribution[str(status // 100) + "xx"] += count
    traffic_bytes = base_query.with_entities(
        func.coalesce(func.sum(WebsiteTrafficEvent.response_bytes), 0)
    ).scalar() or 0
    heuristic_count = base_query.filter(WebsiteTrafficEvent.severity == "HEURISTIC").count()
    recent_since = datetime.now(timezone.utc) - timedelta(minutes=1)
    recent_count = db.query(func.count(WebsiteTrafficEvent.id)).filter(
        WebsiteTrafficEvent.site_id == site_id,
        WebsiteTrafficEvent.created_at >= recent_since,
    ).scalar() or 0
    return {
        "events": [_event_json(event) for event in events],
        "total": total,
        "skip": skip,
        "limit": limit,
        "summary": {
            "total_requests": selected_total,
            "requests_per_minute": recent_count,
            "response_bytes": int(traffic_bytes),
            "heuristic_flags": heuristic_count,
            "ml_status": "unavailable_incompatible_features",
            "status_distribution": status_distribution,
        },
    }


def _event_json(event: WebsiteTrafficEvent) -> dict:
    received_at = event.created_at.isoformat()
    detection = event.event_data or {}
    return {
        "id": event.id, "path": event.request_path, "method": event.method, "status_code": event.status_code,
        "duration_ms": event.duration_ms, "response_bytes": event.response_bytes, "source_ip": event.source_ip,
        "user_agent": event.user_agent, "severity": event.severity, "reason": event.reason,
        "request_timestamp": event.request_timestamp.isoformat() if event.request_timestamp else received_at,
        "received_at": received_at,
        "created_at": received_at,
        "detection_status": "heuristic_flag" if event.severity == "HEURISTIC" else "unassessed",
        "detection_type": detection.get("detection_type", "HEURISTIC" if event.severity == "HEURISTIC" else "NONE"),
        "ml_status": detection.get("ml_status", "unavailable_incompatible_features"),
        "classification": detection.get("classification", "SUSPICIOUS" if event.severity == "HEURISTIC" else "UNASSESSED"),
        "risk_score": detection.get("risk_score", 0),
        "risk_severity": detection.get("risk_severity", "LOW"),
        "detection_categories": detection.get("categories", []),
        "detection_reasons": detection.get("reasons", ([{"category": "legacy_heuristic", "message": event.reason}] if event.reason else [])),
        "supporting_signals": detection.get("supporting_signals", []),
        "alert_ids": detection.get("alert_ids", []),
    }


def _create_or_update_alert(db: Session, site_id: int, event: WebsiteTrafficEvent, detection: dict, reason: dict) -> WebsiteSecurityAlert:
    now = datetime.now(timezone.utc)
    category = reason["category"]
    alert = db.query(WebsiteSecurityAlert).filter(
        WebsiteSecurityAlert.site_id == site_id,
        WebsiteSecurityAlert.category == category,
        WebsiteSecurityAlert.source_ip == event.source_ip,
        WebsiteSecurityAlert.status.in_(("OPEN", "INVESTIGATING")),
        WebsiteSecurityAlert.last_seen >= now - timedelta(minutes=30),
    ).order_by(WebsiteSecurityAlert.last_seen.desc()).first()
    if alert:
        alert.last_seen = now
        alert.related_event_count += 1
        previous_risk = alert.risk_score
        alert.risk_score = max(alert.risk_score, detection["risk_score"])
        if detection["risk_score"] > previous_risk:
            alert.severity = detection["severity"]
        if reason["message"] not in alert.explanation:
            alert.explanation = (alert.explanation + " " + reason["message"])[:2000]
    else:
        alert = WebsiteSecurityAlert(
            site_id=site_id, category=category, title=category.replace("_", " ").title(),
            severity=detection["severity"], risk_score=detection["risk_score"], source_ip=event.source_ip,
            endpoint=event.request_path, explanation=reason["message"], status="OPEN",
            related_event_count=1, first_seen=now, last_seen=now,
        )
        db.add(alert)
        db.flush()
    return alert


def _allow_ingest(site_id: int) -> bool:
    try:
        limit = max(1, min(int(os.getenv("NETSENTRY_SITE_INGEST_PER_MINUTE", "1200")), 100_000))
    except ValueError:
        limit = 1200
    now = time.monotonic()
    cutoff = now - 60
    with _ingest_lock:
        recent = _ingest_times[site_id]
        while recent and recent[0] <= cutoff:
            recent.popleft()
        if len(recent) >= limit:
            return False
        recent.append(now)
    return True


@ingest_router.post("/{site_id}/events", status_code=202)
async def ingest_website_event(
    site_id: int,
    item: WebsiteEventInput,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    supplied = authorization.removeprefix("Bearer ").strip() if authorization else ""
    site = db.query(MonitoredWebsite).filter_by(id=site_id).first()
    if not site or not site.enabled or not supplied or not hmac.compare_digest(
        hashlib.sha256(supplied.encode()).hexdigest(), site.token_hash
    ):
        raise HTTPException(401, "Invalid website ingestion credential.")
    if not _allow_ingest(site.id):
        raise HTTPException(429, "Website telemetry ingestion rate limit exceeded.")
    path = item.path.split("?", 1)[0].split("#", 1)[0]
    path = path if path.startswith("/") and not path.startswith("//") else "/"
    method = item.method.upper()
    if not re.fullmatch(r"[A-Z]{1,12}", method):
        raise HTTPException(422, "Invalid HTTP method.")
    try:
        detection = analyze_website_event(db, site.id, item)
    except Exception:
        # Preserve valid telemetry even if optional detection logic encounters a DB/config issue.
        logger.exception("Website event detection failed for site_id=%s", site.id)
        db.rollback()
        detection = {
            "detection_type": "NONE", "ml_status": "unavailable_incompatible_features",
            "classification": "UNASSESSED", "risk_score": 0, "severity": "LOW",
            "categories": [], "reasons": [],
            "supporting_signals": [],
        }
    severity = "HEURISTIC" if detection["reasons"] else "INFO"
    reason = "; ".join(item["message"] for item in detection["reasons"])
    event_data = item.model_dump(mode="json")
    event_data["path"] = path
    event_data.update({
        "detection_type": detection["detection_type"], "ml_status": detection["ml_status"],
        "classification": detection["classification"], "risk_score": detection["risk_score"],
        "risk_severity": detection["severity"], "categories": detection["categories"],
        "reasons": detection["reasons"],
        "supporting_signals": detection.get("supporting_signals", []),
    })
    event = WebsiteTrafficEvent(
        site_id=site.id, request_path=path, method=method, status_code=item.status_code,
        duration_ms=item.duration_ms, response_bytes=item.response_bytes, source_ip=item.source_ip,
        user_agent=item.user_agent[:256], severity=severity, reason=reason, event_data=event_data,
        request_timestamp=item.request_timestamp,
    )
    db.add(event)
    db.flush()
    alerts = []
    try:
        alert_minimum = max(0, min(int(os.getenv("NETSENTRY_WEBSITE_ALERT_MINIMUM_SCORE", "20")), 100))
    except ValueError:
        alert_minimum = 20
    if detection["risk_score"] >= alert_minimum and detection["risk_score"] > 0:
        for detection_reason in detection["reasons"]:
            alerts.append(_create_or_update_alert(db, site.id, event, detection, detection_reason))
    event_data["alert_ids"] = [alert.id for alert in alerts]
    event.event_data = event_data
    db.commit()
    db.refresh(event)
    result = _event_json(event)
    result["type"] = "traffic_event"
    result["alerts"] = [_alert_json(alert) for alert in alerts]
    await _publish(site.id, result)
    return {"accepted": True, "event": result}


def _alert_json(alert: WebsiteSecurityAlert, site_name: str | None = None) -> dict:
    return {
        "id": alert.id, "event_type": "website_traffic", "site_id": alert.site_id,
        "site_name": site_name, "category": alert.category, "title": alert.title,
        "severity": alert.severity, "risk_score": alert.risk_score,
        "source_ip": alert.source_ip or None, "endpoint": alert.endpoint,
        "request_path": alert.endpoint, "explanation": alert.explanation,
        "description": alert.explanation, "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(), "related_event_count": alert.related_event_count,
        "status": alert.status, "created_at": alert.created_at.isoformat(),
    }


@router.get("/{site_id}/alerts")
def list_website_alerts(
    site_id: int,
    skip: int = Query(default=0, ge=0, le=1_000_000),
    limit: int = Query(default=50, ge=1, le=100),
    status: str | None = Query(default=None, pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$"),
    severity: str | None = Query(default=None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$"),
    category: str | None = Query(default=None, min_length=1, max_length=64),
    since: datetime | None = None,
    until: datetime | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _owned_site(db, site_id, user.id)
    if since and until and since > until:
        raise HTTPException(422, "The start time must be earlier than the end time.")
    query = db.query(WebsiteSecurityAlert).filter(WebsiteSecurityAlert.site_id == site_id)
    if status:
        query = query.filter(WebsiteSecurityAlert.status == status)
    if severity:
        query = query.filter(WebsiteSecurityAlert.severity == severity)
    if category:
        query = query.filter(WebsiteSecurityAlert.category == category)
    if since:
        query = query.filter(WebsiteSecurityAlert.created_at >= since)
    if until:
        query = query.filter(WebsiteSecurityAlert.created_at <= until)
    total = query.count()
    alerts = query.order_by(WebsiteSecurityAlert.last_seen.desc()).offset(skip).limit(limit).all()
    return {"alerts": [_alert_json(alert) for alert in alerts], "total": total, "skip": skip, "limit": limit}


@router.get("/{site_id}/alerts/{alert_id}")
def get_website_alert(site_id: int, alert_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    _owned_site(db, site_id, user.id)
    alert = db.query(WebsiteSecurityAlert).filter_by(id=alert_id, site_id=site_id).first()
    if not alert:
        raise HTTPException(404, "Website alert not found.")
    payload = _alert_json(alert)
    payload["status_history"] = [
        {"previous_status": change.previous_status, "new_status": change.new_status,
         "changed_at": change.changed_at.isoformat()}
        for change in db.query(WebsiteAlertStatusChange).filter_by(alert_id=alert.id)
        .order_by(WebsiteAlertStatusChange.changed_at.asc()).all()
    ]
    return payload


@router.patch("/{site_id}/alerts/{alert_id}")
def update_website_alert_status(
    site_id: int, alert_id: int, payload: WebsiteAlertStatusInput,
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    _owned_site(db, site_id, user.id)
    alert = db.query(WebsiteSecurityAlert).filter_by(id=alert_id, site_id=site_id).first()
    if not alert:
        raise HTTPException(404, "Website alert not found.")
    if alert.status != payload.status:
        db.add(WebsiteAlertStatusChange(alert_id=alert.id, user_id=user.id, previous_status=alert.status, new_status=payload.status))
        alert.status = payload.status
        db.commit()
        db.refresh(alert)
    return _alert_json(alert)


@router.get("/analytics")
def website_analytics(
    site_id: int | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    user: User = Depends(get_current_user), db: Session = Depends(get_db),
):
    if since and until and since > until:
        raise HTTPException(422, "The start time must be earlier than the end time.")
    sites_query = db.query(MonitoredWebsite.id).filter(MonitoredWebsite.owner_id == user.id)
    if site_id is not None:
        _owned_site(db, site_id, user.id)
        sites_query = sites_query.filter(MonitoredWebsite.id == site_id)
    site_ids = [row[0] for row in sites_query.all()]
    query = db.query(WebsiteTrafficEvent).filter(WebsiteTrafficEvent.site_id.in_(site_ids)) if site_ids else db.query(WebsiteTrafficEvent).filter(False)
    if since:
        query = query.filter(WebsiteTrafficEvent.created_at >= since)
    if until:
        query = query.filter(WebsiteTrafficEvent.created_at <= until)
    records = query.order_by(WebsiteTrafficEvent.created_at.desc()).limit(10000).all()
    categories, severities, sources, endpoints, trends = {}, {}, {}, {}, {}
    normal = suspicious = 0
    for event in records:
        data = event.event_data or {}
        classification = data.get("classification", "UNASSESSED")
        if classification == "NORMAL": normal += 1
        elif classification in {"SUSPICIOUS", "ANOMALOUS"}: suspicious += 1
        for category in data.get("categories", []): categories[category] = categories.get(category, 0) + 1
        severity = data.get("risk_severity", "LOW")
        severities[severity] = severities.get(severity, 0) + 1
        if event.source_ip and data.get("risk_score", 0) >= 25: sources[event.source_ip] = sources.get(event.source_ip, 0) + 1
        if data.get("risk_score", 0) >= 25: endpoints[event.request_path] = endpoints.get(event.request_path, 0) + 1
        minute = event.created_at.astimezone(timezone.utc).replace(second=0, microsecond=0).isoformat()
        trends[minute] = trends.get(minute, 0) + 1
    return {
        "event_count": len(records), "normal_count": normal, "suspicious_count": suspicious,
        "ml_status": "unavailable_incompatible_features",
        "category_distribution": categories, "severity_distribution": severities,
        "anomalies_over_time": [{"minute": key, "count": value} for key, value in sorted(trends.items())],
        "top_suspicious_sources": sorted(({"source_ip": key, "count": value} for key, value in sources.items()), key=lambda row: row["count"], reverse=True)[:10],
        "top_flagged_endpoints": sorted(({"endpoint": key, "count": value} for key, value in endpoints.items()), key=lambda row: row["count"], reverse=True)[:10],
        "truncated": len(records) == 10000,
    }


async def _publish(site_id: int, payload: dict) -> None:
    dead = []
    for socket in tuple(_clients.get(site_id, set())):
        try:
            await socket.send_json(payload)
        except Exception:
            dead.append(socket)
    for socket in dead:
        _clients[site_id].discard(socket)


@router.websocket("/{site_id}/live")
async def website_live_socket(websocket: WebSocket, site_id: int):
    allowed = {origin.strip() for origin in os.getenv("NETSENTRY_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(",")}
    if websocket.headers.get("origin") not in allowed:
        await websocket.close(code=1008)
        return
    session_token = websocket.cookies.get("netsentry_session", "")
    if not session_token:
        await websocket.close(code=1008)
        return
    db = SessionLocal()
    try:
        token_hash = hashlib.sha256(session_token.encode()).hexdigest()
        session = db.query(UserSession).filter(
            UserSession.token_hash == token_hash,
            UserSession.revoked_at.is_(None),
            UserSession.expires_at > datetime.now(timezone.utc),
        ).first()
        site = db.query(MonitoredWebsite).filter_by(id=site_id, owner_id=session.user_id).first() if session else None
        if not site or not site.enabled:
            await websocket.close(code=1008)
            return
    finally:
        db.close()
    await websocket.accept()
    _clients[site_id].add(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        _clients[site_id].discard(websocket)

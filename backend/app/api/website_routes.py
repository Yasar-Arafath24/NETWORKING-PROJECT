from collections import defaultdict
from collections import deque
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend.app.api.auth_routes import get_current_user
from backend.app.models.user import User, UserSession
from backend.app.models.website_monitor import MonitoredWebsite, WebsiteTrafficEvent
from backend.app.services.database import SessionLocal, get_db

router = APIRouter(prefix="/api/v1/websites", tags=["Website monitoring"])
ingest_router = APIRouter(prefix="/api/v1/website-ingest", tags=["Website traffic ingestion"])
_clients: dict[int, set[WebSocket]] = defaultdict(set)
_ingest_times: dict[int, deque[float]] = defaultdict(deque)
_ingest_lock = threading.Lock()


class WebsiteCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=8, max_length=2048)
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


def _site_json(site: MonitoredWebsite, *, token: str | None = None) -> dict:
    payload = {"id": site.id, "name": site.name, "url": site.url, "enabled": site.enabled, "created_at": site.created_at}
    if token:
        payload["ingest_token"] = token
    return payload


def _owned_site(db: Session, site_id: int, user_id: int) -> MonitoredWebsite:
    site = db.query(MonitoredWebsite).filter_by(id=site_id, owner_id=user_id).first()
    if not site:
        raise HTTPException(404, "Website monitor not found.")
    return site


@router.post("", status_code=201)
def add_website(payload: WebsiteCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    name = payload.name.strip()
    parsed = urlsplit(payload.url.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise HTTPException(422, "Enter a valid http:// or https:// website URL.")
    if not payload.authorization_confirmed:
        raise HTTPException(422, "Confirm that you own or are authorized to monitor this website.")
    normalized_url = parsed.scheme.lower() + "://" + parsed.netloc.lower()
    token = secrets.token_urlsafe(36)
    site = MonitoredWebsite(name=name, url=normalized_url, token_hash=hashlib.sha256(token.encode()).hexdigest(), owner_id=user.id, authorization_confirmed=True)
    db.add(site)
    db.commit()
    db.refresh(site)
    return _site_json(site, token=token)


@router.get("")
def list_websites(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sites = db.query(MonitoredWebsite).filter_by(owner_id=user.id).order_by(MonitoredWebsite.id.desc()).all()
    return {"websites": [_site_json(site) for site in sites]}


@router.patch("/{site_id}")
async def set_website_enabled(site_id: int, enabled: bool, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    site = _owned_site(db, site_id, user.id)
    site.enabled = enabled
    db.commit()
    if not enabled:
        for socket in tuple(_clients.get(site_id, set())):
            try:
                await socket.close(code=1000)
            except Exception:
                pass
        _clients.pop(site_id, None)
    return _site_json(site)


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
    classification: str = Query(default="all", pattern="^(all|heuristic|unassessed)$"),
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
        filtered_query = filtered_query.filter(WebsiteTrafficEvent.severity != "HEURISTIC")
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
            "status_distribution": status_distribution,
        },
    }


def _event_json(event: WebsiteTrafficEvent) -> dict:
    received_at = event.created_at.isoformat()
    return {
        "id": event.id, "path": event.request_path, "method": event.method, "status_code": event.status_code,
        "duration_ms": event.duration_ms, "response_bytes": event.response_bytes, "source_ip": event.source_ip,
        "user_agent": event.user_agent, "severity": event.severity, "reason": event.reason,
        "request_timestamp": event.request_timestamp.isoformat() if event.request_timestamp else received_at,
        "received_at": received_at,
        "created_at": received_at,
        "detection_status": "heuristic_flag" if event.severity == "HEURISTIC" else "unassessed",
    }


def _risk(db: Session, site_id: int, item: WebsiteEventInput) -> tuple[str, str]:
    since = datetime.now(timezone.utc) - timedelta(minutes=1)
    recent = db.query(func.count(WebsiteTrafficEvent.id)).filter(
        WebsiteTrafficEvent.site_id == site_id,
        WebsiteTrafficEvent.created_at >= since,
    ).scalar() or 0
    if recent >= 120:
        return "HEURISTIC", "Request volume exceeded the provisional threshold of 120 requests per minute; this is a rate heuristic, not an attack verdict."
    return "INFO", ""


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
    severity, reason = _risk(db, site.id, item)
    event_data = item.model_dump(mode="json")
    event_data["path"] = path
    event = WebsiteTrafficEvent(
        site_id=site.id, request_path=path, method=method, status_code=item.status_code,
        duration_ms=item.duration_ms, response_bytes=item.response_bytes, source_ip=item.source_ip,
        user_agent=item.user_agent[:256], severity=severity, reason=reason, event_data=event_data,
        request_timestamp=item.request_timestamp,
    )
    db.add(event)
    db.commit()
    db.refresh(event)
    result = _event_json(event)
    result["type"] = "traffic_event"
    await _publish(site.id, result)
    return {"accepted": True, "event": result}


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

from collections import defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.api.auth_routes import get_current_user
from backend.app.models.user import User, UserSession
from backend.app.models.website_monitor import MonitoredWebsite, WebsiteTrafficEvent
from backend.app.services.database import SessionLocal, get_db

router = APIRouter(prefix="/api/v1/websites", tags=["Website monitoring"])
ingest_router = APIRouter(prefix="/api/v1/website-ingest", tags=["Website traffic ingestion"])
_clients: dict[int, set[WebSocket]] = defaultdict(set)


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
    limit: int = Query(default=100, ge=1, le=500),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _owned_site(db, site_id, user.id)
    events = db.query(WebsiteTrafficEvent).filter_by(site_id=site_id).order_by(WebsiteTrafficEvent.id.desc()).limit(limit).all()
    recent_since = datetime.now(timezone.utc) - timedelta(minutes=1)
    recent_count = db.query(func.count(WebsiteTrafficEvent.id)).filter(
        WebsiteTrafficEvent.site_id == site_id,
        WebsiteTrafficEvent.created_at >= recent_since,
    ).scalar() or 0
    return {"events": [_event_json(event) for event in reversed(events)], "requests_per_minute": recent_count}


def _event_json(event: WebsiteTrafficEvent) -> dict:
    return {
        "id": event.id, "path": event.request_path, "method": event.method, "status_code": event.status_code,
        "duration_ms": event.duration_ms, "response_bytes": event.response_bytes, "source_ip": event.source_ip,
        "user_agent": event.user_agent, "severity": event.severity, "reason": event.reason,
        "created_at": event.created_at.isoformat(),
    }


def _risk(db: Session, site_id: int, item: WebsiteEventInput) -> tuple[str, str]:
    if item.status_code >= 500:
        return "HIGH", "Server returned an error response (5xx)."
    if item.status_code >= 400:
        return "MEDIUM", "Client or authorization failure response (4xx)."
    since = datetime.now(timezone.utc) - timedelta(minutes=1)
    recent = db.query(func.count(WebsiteTrafficEvent.id)).filter(
        WebsiteTrafficEvent.site_id == site_id,
        WebsiteTrafficEvent.created_at >= since,
    ).scalar() or 0
    if recent >= 120:
        return "HIGH", "Request volume exceeded the demo threshold of 120 requests per minute."
    return "INFO", ""


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
    path = item.path.split("?", 1)[0].split("#", 1)[0]
    path = path if path.startswith("/") and not path.startswith("//") else "/"
    method = item.method.upper()
    if not re.fullmatch(r"[A-Z]{1,12}", method):
        raise HTTPException(422, "Invalid HTTP method.")
    severity, reason = _risk(db, site.id, item)
    event_data = item.model_dump()
    event_data["path"] = path
    event = WebsiteTrafficEvent(
        site_id=site.id, request_path=path, method=method, status_code=item.status_code,
        duration_ms=item.duration_ms, response_bytes=item.response_bytes, source_ip=item.source_ip,
        user_agent=item.user_agent[:256], severity=severity, reason=reason, event_data=event_data,
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

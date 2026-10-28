from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.models.user import User, UserSession
from backend.app.services.database import get_db

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
SESSION_COOKIE = "netsentry_session"
CSRF_COOKIE = "netsentry_csrf"
SESSION_DAYS = 7


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=1, max_length=128)


def _password_hash(password: str) -> str:
    salt = secrets.token_bytes(16)
    value = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + salt.hex() + "$" + value.hex()


def _password_matches(password: str, stored: str) -> bool:
    try:
        scheme, salt_hex, expected = stored.split("$", 2)
        if scheme != "scrypt":
            return False
        value = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(value.hex(), expected)
    except (ValueError, TypeError):
        return False


def user_json(user: User) -> dict:
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role, "created_at": user.created_at}


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(401, "Please log in to continue.")
    digest = hashlib.sha256(token.encode()).hexdigest()
    session = db.query(UserSession).filter(
        UserSession.token_hash == digest,
        UserSession.revoked_at.is_(None),
        UserSession.expires_at > datetime.now(timezone.utc),
    ).first()
    if not session:
        raise HTTPException(401, "Your session has expired. Please log in again.")
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        csrf = request.cookies.get(CSRF_COOKIE, "")
        header = request.headers.get("x-csrf-token", "")
        if not csrf or not hmac.compare_digest(csrf, header) or not hmac.compare_digest(csrf, session.csrf_token):
            raise HTTPException(403, "CSRF token validation failed.")
    user = db.get(User, session.user_id)
    if not user or not user.is_active:
        raise HTTPException(401, "This account is unavailable.")
    return user


def _issue_session(user: User, response: Response, db: Session) -> None:
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    expiry = datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)
    db.add(UserSession(token_hash=hashlib.sha256(token.encode()).hexdigest(), csrf_token=csrf, user_id=user.id, expires_at=expiry))
    db.commit()
    secure = os.getenv("NETSENTRY_COOKIE_SECURE", "false").lower() == "true"
    age = SESSION_DAYS * 86400
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=secure, samesite="lax", path="/", max_age=age)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite="lax", path="/", max_age=age)


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    name, email = payload.name.strip(), payload.email.strip().lower()
    if not name or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(422, "Enter a valid name and email address.")
    if not re.search(r"[a-z]", payload.password) or not re.search(r"[A-Z]", payload.password) or not re.search(r"\d", payload.password):
        raise HTTPException(422, "Password must include an uppercase letter, a lowercase letter, and a number.")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "An account with this email already exists.")
    user = User(name=name, email=email, password_hash=_password_hash(payload.password))
    db.add(user)
    db.commit()
    db.refresh(user)
    _issue_session(user, response, db)
    return {"user": user_json(user)}


@router.post("/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email.strip().lower()).first()
    if not user or not _password_matches(payload.password, user.password_hash) or not user.is_active:
        raise HTTPException(401, "Email or password is incorrect.")
    _issue_session(user, response, db)
    return {"user": user_json(user)}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"user": user_json(user)}


@router.post("/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        session = db.query(UserSession).filter(UserSession.token_hash == hashlib.sha256(token.encode()).hexdigest()).first()
        if session and session.revoked_at is None:
            csrf, header = request.cookies.get(CSRF_COOKIE, ""), request.headers.get("x-csrf-token", "")
            if not csrf or not hmac.compare_digest(csrf, header) or not hmac.compare_digest(csrf, session.csrf_token):
                raise HTTPException(403, "CSRF token validation failed.")
            session.revoked_at = datetime.now(timezone.utc)
            db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, samesite="lax")
    response.delete_cookie(CSRF_COOKIE, path="/", samesite="lax")
    return {"status": "signed_out"}

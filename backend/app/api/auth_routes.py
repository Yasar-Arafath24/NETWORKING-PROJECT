from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
import re
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
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


class GoogleAuthRequest(BaseModel):
    credential: str = Field(min_length=100, max_length=8192)
    nonce: str = Field(min_length=32, max_length=128)


def verify_google_credential(credential: str, client_id: str) -> dict:
    """Verify a Google Identity Services ID token using Google's auth library."""
    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2 import id_token

    return id_token.verify_oauth2_token(credential, GoogleRequest(), audience=client_id)


def _normalize_gmail(value: str) -> str:
    email = value.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(422, "Enter a valid Gmail address ending in @gmail.com.")
    if not email.endswith("@gmail.com"):
        raise HTTPException(422, "Only Gmail addresses ending in @gmail.com are allowed.")
    return email


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
    same_site = os.getenv("NETSENTRY_COOKIE_SAMESITE", "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"
    response.set_cookie(SESSION_COOKIE, token, httponly=True, secure=secure, samesite=same_site, path="/", max_age=age)
    response.set_cookie(CSRF_COOKIE, csrf, httponly=False, secure=secure, samesite=same_site, path="/", max_age=age)


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, response: Response, db: Session = Depends(get_db)):
    name, email = payload.name.strip(), _normalize_gmail(payload.email)
    if not name:
        raise HTTPException(422, "Enter your name.")
    if not re.search(r"[a-z]", payload.password) or not re.search(r"[A-Z]", payload.password) or not re.search(r"\d", payload.password):
        raise HTTPException(422, "Password must include an uppercase letter, a lowercase letter, and a number.")
    user = User(name=name, email=email, password_hash=_password_hash(payload.password))
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        if db.query(User).filter(User.email == email).first():
            raise HTTPException(409, "An account with this email already exists.") from exc
        raise
    db.refresh(user)
    _issue_session(user, response, db)
    return {"user": user_json(user)}


@router.post("/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    email = _normalize_gmail(payload.email)
    user = db.query(User).filter(User.email == email).first()
    if not user or not _password_matches(payload.password, user.password_hash) or not user.is_active:
        raise HTTPException(401, "Email or password is incorrect.")
    _issue_session(user, response, db)
    return {"user": user_json(user)}


@router.get("/google/config")
def google_sign_in_config(response: Response):
    # A Google OAuth web client ID is public; client secrets never belong in the browser.
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    nonce = secrets.token_urlsafe(32) if client_id else ""
    if nonce:
        secure = os.getenv("NETSENTRY_COOKIE_SECURE", "false").lower() == "true"
        same_site = os.getenv("NETSENTRY_COOKIE_SAMESITE", "lax").lower()
        if same_site not in {"lax", "strict", "none"}:
            same_site = "lax"
        response.set_cookie(
            "netsentry_google_nonce", nonce, httponly=True, secure=secure,
            samesite=same_site, path="/", max_age=300,
        )
    return {"client_id": client_id, "nonce": nonce}


@router.post("/google")
def login_with_google(payload: GoogleAuthRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip()
    if not client_id:
        raise HTTPException(503, "Google sign-in is not configured. Set GOOGLE_CLIENT_ID on the backend.")
    expected_nonce = request.cookies.get("netsentry_google_nonce", "")
    if not expected_nonce or not hmac.compare_digest(expected_nonce, payload.nonce):
        raise HTTPException(401, "Google sign-in expired. Please try again.")

    try:
        claims = verify_google_credential(payload.credential, client_id)
    except Exception as exc:
        # Do not log or return the credential or provider exception; it may contain token material.
        raise HTTPException(401, "Google sign-in could not verify this credential. Please try again.") from exc

    subject = claims.get("sub")
    email = claims.get("email")
    if not isinstance(subject, str) or not subject or claims.get("nonce") != expected_nonce:
        raise HTTPException(401, "Google sign-in response could not be verified. Please try again.")
    if claims.get("email_verified") is not True:
        raise HTTPException(403, "Google must verify your email address before you can sign in.")

    email = _normalize_gmail(email if isinstance(email, str) else "")
    user = db.query(User).filter(User.google_subject == subject).first()
    if user and user.email != email:
        # Google subjects are stable; an email can change, but account identity remains the subject.
        user.email = email
    elif not user:
        user = db.query(User).filter(User.email == email).first()
        if user:
            # This is a verified Google email assertion, not an email string supplied by the browser.
            user.google_subject = subject
        else:
            name = claims.get("name")
            name = name.strip()[:120] if isinstance(name, str) else ""
            user = User(
                name=name or email.split("@", 1)[0][:120],
                email=email,
                # Google-only accounts receive an unknown random local password.
                password_hash=_password_hash(secrets.token_urlsafe(48)),
                google_subject=subject,
                is_active=True,
            )
            db.add(user)

    if not user.is_active:
        raise HTTPException(403, "This NetSentry account is unavailable.")
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "This Google account is already linked to another NetSentry account.") from exc

    _issue_session(user, response, db)
    secure = os.getenv("NETSENTRY_COOKIE_SECURE", "false").lower() == "true"
    same_site = os.getenv("NETSENTRY_COOKIE_SAMESITE", "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"
    response.delete_cookie("netsentry_google_nonce", path="/", httponly=True, secure=secure, samesite=same_site)
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
    same_site = os.getenv("NETSENTRY_COOKIE_SAMESITE", "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"
    secure = os.getenv("NETSENTRY_COOKIE_SECURE", "false").lower() == "true"
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=secure, samesite=same_site)
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, samesite=same_site)
    return {"status": "signed_out"}

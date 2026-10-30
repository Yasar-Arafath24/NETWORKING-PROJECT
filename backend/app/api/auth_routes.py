from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.models.user import EmailVerification, User, UserSession
from backend.app.services.database import get_db

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)
SESSION_COOKIE = "netsentry_session"
CSRF_COOKIE = "netsentry_csrf"
SESSION_DAYS = 7
EMAIL_CODE_MINUTES = 10
EMAIL_CODE_RESEND_SECONDS = 60
EMAIL_CODE_MAX_ATTEMPTS = 5


class RegisterRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=6, max_length=128)


class VerifyEmailRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ResendVerificationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


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


def _verification_secret() -> bytes:
    secret = os.getenv("NETSENTRY_OTP_SECRET", "").strip()
    if len(secret) < 32:
        raise HTTPException(503, "Email verification is not configured. Set NETSENTRY_OTP_SECRET on the backend.")
    return secret.encode()


def _email_delivery_mode() -> str:
    mode = os.getenv("NETSENTRY_EMAIL_DELIVERY", "smtp").strip().lower()
    if mode not in {"smtp", "console"}:
        raise HTTPException(503, "Email verification delivery must be set to smtp or console.")
    if mode == "console" and os.getenv("NETSENTRY_ENV", "").strip().lower() != "development":
        raise HTTPException(503, "Console OTP delivery is only allowed when NETSENTRY_ENV=development.")
    return mode


def _validate_email_delivery_config() -> str:
    _verification_secret()
    mode = _email_delivery_mode()
    if mode == "smtp" and (
        not os.getenv("NETSENTRY_SMTP_HOST", "").strip()
        or not os.getenv("NETSENTRY_SMTP_FROM", "").strip()
    ):
        raise HTTPException(
            503,
            "Email verification cannot send codes: configure NETSENTRY_SMTP_HOST and NETSENTRY_SMTP_FROM, or use NETSENTRY_EMAIL_DELIVERY=console with NETSENTRY_ENV=development for local testing.",
        )
    return mode


def send_verification_email(email: str, name: str, code: str) -> None:
    """Deliver a signup code through configured SMTP; never return it to the browser."""
    if _email_delivery_mode() == "console":
        logger.warning("Development OTP for %s (%s): %s", email, name, code)
        return

    host = os.getenv("NETSENTRY_SMTP_HOST", "").strip()
    sender = os.getenv("NETSENTRY_SMTP_FROM", "").strip()
    username = os.getenv("NETSENTRY_SMTP_USERNAME", "").strip()
    password = os.getenv("NETSENTRY_SMTP_PASSWORD", "")
    if not host or not sender:
        raise HTTPException(503, "Email verification is not configured. Set NETSENTRY_SMTP_HOST and NETSENTRY_SMTP_FROM on the backend.")

    message = EmailMessage()
    message["Subject"] = "Your NetSentry verification code"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Hello {name},\n\nYour NetSentry verification code is {code}. "
        f"It expires in {EMAIL_CODE_MINUTES} minutes.\n\n"
        "If you did not create this account, you can ignore this message."
    )

    port = int(os.getenv("NETSENTRY_SMTP_PORT", "587"))
    use_ssl = os.getenv("NETSENTRY_SMTP_USE_SSL", "false").lower() == "true"
    use_starttls = os.getenv("NETSENTRY_SMTP_STARTTLS", "true").lower() == "true"
    smtp_factory = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    try:
        with smtp_factory(host, port, timeout=15) as smtp:
            if use_starttls and not use_ssl:
                smtp.starttls()
            if username:
                smtp.login(username, password)
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise HTTPException(503, "Could not send the verification email. Check the SMTP settings and try again.") from exc


def _create_email_verification(user: User, db: Session) -> str:
    delivery_mode = _validate_email_delivery_config()
    secret = _verification_secret()
    code = f"{secrets.randbelow(1_000_000):06d}"
    now = datetime.now(timezone.utc)
    record = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first()
    digest = hmac.new(secret, f"{user.id}:{code}".encode(), hashlib.sha256).hexdigest()
    if record:
        record.code_hash = digest
        record.expires_at = now + timedelta(minutes=EMAIL_CODE_MINUTES)
        record.created_at = now
        record.attempts = 0
    else:
        db.add(EmailVerification(
            user_id=user.id,
            code_hash=digest,
            expires_at=now + timedelta(minutes=EMAIL_CODE_MINUTES),
            created_at=now,
            attempts=0,
        ))
    db.commit()
    try:
        send_verification_email(user.email, user.name, code)
    except Exception:
        logger.exception("Could not deliver account verification email")
        raise
    return delivery_mode


def _enforce_resend_cooldown(user: User, db: Session) -> None:
    record = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first()
    if not record:
        return
    created = record.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    wait = EMAIL_CODE_RESEND_SECONDS - (datetime.now(timezone.utc) - created).total_seconds()
    if wait > 0:
        raise HTTPException(429, f"Please wait {int(wait) + 1} seconds before requesting another code.")


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
    if len(payload.password) < 6:
        raise HTTPException(422, "Password must be at least 6 characters.")
    _validate_email_delivery_config()
    user = User(name=name, email=email, password_hash=_password_hash(payload.password), email_verified=False)
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        existing = db.query(User).filter(User.email == email).first()
        if existing and not existing.email_verified:
            _enforce_resend_cooldown(existing, db)
            delivery_mode = _create_email_verification(existing, db)
            message = "A new code was written to the backend console for local development." if delivery_mode == "console" else "A new verification code has been sent to your email."
            return {"verification_required": True, "email": email, "delivery": delivery_mode, "message": message}
        if existing:
            raise HTTPException(409, "An account with this email already exists.") from exc
        raise
    db.refresh(user)
    delivery_mode = _create_email_verification(user, db)
    message = "A six-digit code was written to the backend console. Enter it here to finish local development signup." if delivery_mode == "console" else "Enter the six-digit code sent to your email to finish creating your account."
    return {"verification_required": True, "email": email, "delivery": delivery_mode, "message": message}


@router.post("/verify-email")
def verify_email(payload: VerifyEmailRequest, response: Response, db: Session = Depends(get_db)):
    email = _normalize_gmail(payload.email)
    user = db.query(User).filter(User.email == email, User.email_verified.is_(False)).first()
    if not user:
        raise HTTPException(400, "This verification code is invalid or expired. Request a new code and try again.")
    record = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first()
    if not record:
        raise HTTPException(400, "This verification code is invalid or expired. Request a new code and try again.")
    now = datetime.now(timezone.utc)
    expiry = record.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= now:
        raise HTTPException(400, "This verification code has expired. Request a new code.")
    if record.attempts >= EMAIL_CODE_MAX_ATTEMPTS:
        raise HTTPException(429, "Too many incorrect codes. Request a new code.")
    secret = _verification_secret()
    submitted = hmac.new(secret, f"{user.id}:{payload.code}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(submitted, record.code_hash):
        record.attempts += 1
        db.commit()
        raise HTTPException(400, "That code does not match. Check your email and try again.")

    user.email_verified = True
    db.delete(record)
    db.commit()
    if not user.is_active:
        raise HTTPException(403, "This NetSentry account is unavailable.")
    _issue_session(user, response, db)
    return {"user": user_json(user)}


@router.post("/verification/resend", status_code=202)
def resend_verification(payload: ResendVerificationRequest, db: Session = Depends(get_db)):
    email = _normalize_gmail(payload.email)
    user = db.query(User).filter(User.email == email, User.email_verified.is_(False)).first()
    if user:
        _enforce_resend_cooldown(user, db)
        _create_email_verification(user, db)
    return {"message": "If an unverified account exists, a code was sent. For local console mode, check the backend terminal."}


@router.post("/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    email = _normalize_gmail(payload.email)
    user = db.query(User).filter(User.email == email).first()
    if user and not user.email_verified:
        raise HTTPException(403, "Verify your email before signing in. Check your inbox for the six-digit code.")
    if not user or not _password_matches(payload.password, user.password_hash):
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

    user.email_verified = True

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

from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr
from html import escape
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import smtplib
import ssl
from urllib import error as urllib_error
from urllib import request as urllib_request

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.app.models.user import AuthRateLimit, EmailVerification, PasswordResetOtp, User, UserSession
from backend.app.services.database import get_db

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)
SESSION_COOKIE = "netsentry_session"
CSRF_COOKIE = "netsentry_csrf"
SESSION_DAYS = 7
EMAIL_CODE_MINUTES = 5
EMAIL_CODE_RESEND_SECONDS = 60
EMAIL_CODE_MAX_ATTEMPTS = 5
PASSWORD_RESET_OTP_MINUTES = 5
PASSWORD_RESET_TOKEN_MINUTES = 10
RESET_RATE_LIMIT_WINDOW_SECONDS = 900
RESET_RATE_LIMIT_MAX_REQUESTS = 20


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


class ForgotPasswordRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)


class VerifyResetOtpRequest(ForgotPasswordRequest):
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class ResetPasswordRequest(BaseModel):
    password: str = Field(min_length=6, max_length=128)


class SupabaseSessionRequest(BaseModel):
    access_token: str = Field(min_length=1)
    name: str | None = Field(default=None, max_length=120)


def verify_google_credential(credential: str, client_id: str) -> dict:
    """Verify a Google Identity Services ID token using Google's auth library."""
    from google.auth.transport.requests import Request as GoogleRequest
    from google.oauth2 import id_token

    return id_token.verify_oauth2_token(credential, GoogleRequest(), audience=client_id)


def _normalize_email(value: str) -> str:
    email = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", email, re.IGNORECASE):
        raise HTTPException(422, "Enter a valid email address.")
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
    if mode != "smtp":
        raise HTTPException(503, "Email delivery is disabled. Set NETSENTRY_EMAIL_DELIVERY=smtp in the backend .env file.")
    return mode


def _mail_value(name: str, smtp_name: str, legacy_name: str, default: str = "") -> str:
    value = os.getenv(name, "").strip()
    if value:
        return value
    value = os.getenv(smtp_name, "").strip()
    return value or os.getenv(legacy_name, default).strip()


def _mail_password() -> str:
    return (
        os.getenv("MAIL_PASSWORD", "").strip()
        or os.getenv("SMTP_PASSWORD", "").strip()
        or os.getenv("NETSENTRY_SMTP_PASSWORD", "").strip()
    )


def _validate_email_delivery_config() -> str:
    _verification_secret()
    mode = _email_delivery_mode()
    host = _mail_value("MAIL_HOST", "SMTP_HOST", "NETSENTRY_SMTP_HOST")
    sender = _mail_value("MAIL_FROM", "SMTP_FROM_EMAIL", "NETSENTRY_SMTP_FROM")
    username = _mail_value("MAIL_USERNAME", "SMTP_USERNAME", "NETSENTRY_SMTP_USERNAME")
    password = _mail_password()
    missing = [
        variable
        for variable, value in (("MAIL_HOST", host), ("MAIL_FROM", sender))
        if not value
    ]
    if missing:
        raise HTTPException(
            503,
            f"Email delivery is unavailable. Configure {', '.join(missing)} in the backend .env file.",
        )
    if bool(username) != bool(password):
        raise HTTPException(503, "Configure both MAIL_USERNAME and MAIL_PASSWORD.")
    if host.lower() == "smtp-relay.brevo.com" and not username:
        raise HTTPException(
            503,
            "Brevo SMTP requires MAIL_USERNAME and MAIL_PASSWORD. Use your Brevo SMTP login and SMTP key.",
        )
    if host.lower() in {"smtp.gmail.com", "smtp.googlemail.com"} and not username:
        raise HTTPException(
            503,
            "Gmail SMTP requires MAIL_USERNAME and MAIL_PASSWORD. Use the account email and a Google App Password.",
        )
    try:
        port = int(_mail_value("MAIL_PORT", "SMTP_PORT", "NETSENTRY_SMTP_PORT", "587"))
    except ValueError as exc:
        raise HTTPException(503, "MAIL_PORT must be a valid port number.") from exc
    use_ssl = _mail_value("MAIL_SSL_TLS", "SMTP_USE_SSL", "NETSENTRY_SMTP_USE_SSL", "false").lower() == "true"
    use_tls = _mail_value("MAIL_STARTTLS", "SMTP_USE_TLS", "NETSENTRY_SMTP_STARTTLS", "true").lower() == "true"
    if not 1 <= port <= 65535 or (use_ssl and use_tls) or not (use_ssl or use_tls):
        raise HTTPException(503, "Configure a valid mail port and exactly one of MAIL_STARTTLS or MAIL_SSL_TLS.")
    if host.lower() == "smtp-relay.brevo.com" and (port != 587 or not use_tls or use_ssl):
        raise HTTPException(503, "Brevo SMTP requires MAIL_PORT=587, MAIL_STARTTLS=true, and MAIL_SSL_TLS=false.")
    return mode


def _send_otp_email(email: str, name: str, code: str, subject: str, purpose: str, expiration_minutes: int) -> None:
    _validate_email_delivery_config()
    host = _mail_value("MAIL_HOST", "SMTP_HOST", "NETSENTRY_SMTP_HOST")
    sender = _mail_value("MAIL_FROM", "SMTP_FROM_EMAIL", "NETSENTRY_SMTP_FROM")
    sender_name = _mail_value("MAIL_FROM_NAME", "SMTP_FROM_NAME", "NETSENTRY_SMTP_FROM_NAME", "NetSentry AI")
    username = _mail_value("MAIL_USERNAME", "SMTP_USERNAME", "NETSENTRY_SMTP_USERNAME")
    password = _mail_password()
    port = int(_mail_value("MAIL_PORT", "SMTP_PORT", "NETSENTRY_SMTP_PORT", "587"))
    use_ssl = _mail_value("MAIL_SSL_TLS", "SMTP_USE_SSL", "NETSENTRY_SMTP_USE_SSL", "false").lower() == "true"
    use_tls = _mail_value("MAIL_STARTTLS", "SMTP_USE_TLS", "NETSENTRY_SMTP_STARTTLS", "true").lower() == "true"
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((sender_name, sender))
    message["To"] = email
    message.set_content(
        f"Hello {name},\n\nYour NetSentry {purpose} code is {code}. "
        f"It expires in {expiration_minutes} minutes.\n\n"
        "If you did not request this code, you can ignore this message."
    )
    message.add_alternative(
        f"""\
<!doctype html>
<html lang="en">
  <body style="margin:0;padding:32px;background:#f3f6fb;font-family:Arial,sans-serif;color:#172033">
    <table role="presentation" style="max-width:560px;margin:0 auto;background:#fff;border-radius:16px;padding:32px">
      <tr><td>
        <p style="margin:0 0 24px;color:#2457d6;font-size:13px;font-weight:700;letter-spacing:1px">NETSENTRY AI</p>
        <h1 style="margin:0 0 16px;font-size:24px">Your {escape(purpose)} code</h1>
        <p style="margin:0 0 20px">Hello {escape(name)}, use this one-time code to continue:</p>
        <p style="margin:0 0 20px;padding:16px;text-align:center;background:#f3f6fb;border-radius:10px;font-size:32px;font-weight:700;letter-spacing:8px">{escape(code)}</p>
        <p style="margin:0 0 24px;color:#526078">This code expires in {expiration_minutes} minutes. Never share it with anyone.</p>
        <hr style="border:0;border-top:1px solid #e5eaf2">
        <p style="margin:16px 0 0;color:#6b7485;font-size:13px">If you did not request this code, you can safely ignore this email.</p>
      </td></tr>
    </table>
  </body>
</html>
""",
        subtype="html",
    )
    smtp_factory = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    try:
        with (smtp_factory(host, port, timeout=15, context=ssl.create_default_context()) if use_ssl else smtp_factory(host, port, timeout=15)) as smtp:
            if use_tls:
                smtp.starttls(context=ssl.create_default_context())
            if username:
                smtp.login(username, password)
            refused = smtp.send_message(message)
            if refused:
                raise HTTPException(
                    503,
                    "The SMTP server rejected the recipient address. Verify the email address and sender permissions.",
                )
    except smtplib.SMTPAuthenticationError as exc:
        logger.warning("SMTP server rejected authentication (SMTP status %s).", exc.smtp_code)
        if host.lower() == "smtp-relay.brevo.com":
            detail = (
                "Brevo requires its SMTP login and SMTP key. "
                f"Brevo rejected SMTP authentication (status {exc.smtp_code}). Set MAIL_USERNAME "
                "to your Brevo SMTP login and MAIL_PASSWORD to a newly generated Brevo SMTP key "
                "(not an API key), then restart the backend."
            )
        elif host.lower() in {"smtp.gmail.com", "smtp.googlemail.com"}:
            detail = (
                f"Gmail rejected SMTP authentication (status {exc.smtp_code}). Set MAIL_USERNAME "
                "to the account email and MAIL_PASSWORD to its current Google App Password."
            )
        else:
            detail = (
                f"The SMTP server rejected authentication (status {exc.smtp_code}). "
                "Verify the configured mail username and password."
            )
        raise HTTPException(
            503,
            detail,
        ) from None
    except (TimeoutError, ConnectionError) as exc:
        logger.warning("SMTP connection failed (%s).", type(exc).__name__)
        raise HTTPException(
            503,
            "The SMTP connection timed out or failed. Check MAIL_HOST, MAIL_PORT, and TLS settings.",
        ) from None
    except (OSError, smtplib.SMTPException) as exc:
        logger.warning("SMTP delivery failed (%s).", type(exc).__name__)
        raise HTTPException(
            503,
            "SMTP email delivery failed. Check the mail server, TLS settings, sender address, and try again.",
        ) from None


def send_password_reset_email(email: str, name: str, code: str) -> None:
    _send_otp_email(email, name, code, "Reset your NetSentry password", "password reset", PASSWORD_RESET_OTP_MINUTES)


def send_verification_email(email: str, name: str, code: str) -> None:
    _send_otp_email(email, name, code, "Verify your NetSentry email", "email verification", EMAIL_CODE_MINUTES)


def _consume_auth_rate_limit(key: str, db: Session, limit: int, window_seconds: int) -> None:
    now = datetime.now(timezone.utc)
    db.query(AuthRateLimit).filter(
        AuthRateLimit.window_started_at < now - timedelta(days=1)
    ).delete(synchronize_session=False)
    digest = hmac.new(_verification_secret(), key.encode(), hashlib.sha256).hexdigest()
    record = db.get(AuthRateLimit, digest)
    if record:
        started = record.window_started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        if (now - started).total_seconds() >= window_seconds:
            record.window_started_at = now
            record.attempts = 1
        elif record.attempts >= limit:
            raise HTTPException(429, "Too many requests. Wait before trying again.")
        else:
            record.attempts += 1
    else:
        db.add(AuthRateLimit(key_hash=digest, window_started_at=now, attempts=1))
    db.commit()


def _rate_limit_reset_request(request: Request, email: str, db: Session) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _consume_auth_rate_limit(f"password-reset:ip:{client_ip}", db, RESET_RATE_LIMIT_MAX_REQUESTS, RESET_RATE_LIMIT_WINDOW_SECONDS)
    _consume_auth_rate_limit(f"password-reset:email:{email}", db, 1, EMAIL_CODE_RESEND_SECONDS)


def _rate_limit_email_verification(request: Request, email: str, db: Session) -> None:
    client_ip = request.client.host if request.client else "unknown"
    _consume_auth_rate_limit(
        f"email-verification:ip:{client_ip}",
        db,
        RESET_RATE_LIMIT_MAX_REQUESTS,
        RESET_RATE_LIMIT_WINDOW_SECONDS,
    )
    _consume_auth_rate_limit(
        f"email-verification:email:{email}",
        db,
        1,
        EMAIL_CODE_RESEND_SECONDS,
    )


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def _set_reset_cookies(response: Response, token: str) -> None:
    secure = os.getenv("NETSENTRY_COOKIE_SECURE", "false").lower() == "true"
    same_site = os.getenv("NETSENTRY_COOKIE_SAMESITE", "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"
    age = PASSWORD_RESET_TOKEN_MINUTES * 60
    response.set_cookie("netsentry_reset_token", token, httponly=True, secure=secure, samesite=same_site, path="/", max_age=age)
    response.set_cookie("netsentry_reset_csrf", secrets.token_urlsafe(32), httponly=False, secure=secure, samesite=same_site, path="/", max_age=age)


def _clear_reset_cookies(response: Response) -> None:
    secure = os.getenv("NETSENTRY_COOKIE_SECURE", "false").lower() == "true"
    same_site = os.getenv("NETSENTRY_COOKIE_SAMESITE", "lax").lower()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "lax"
    response.delete_cookie("netsentry_reset_token", httponly=True, secure=secure, samesite=same_site, path="/")
    response.delete_cookie("netsentry_reset_csrf", secure=secure, samesite=same_site, path="/")


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


def _enforce_resend_cooldown_for_login(user: User, db: Session) -> bool:
    record = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first()
    if not record:
        return False
    created = record.created_at
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return EMAIL_CODE_RESEND_SECONDS - (datetime.now(timezone.utc) - created).total_seconds() > 0


def _verification_code_hash(user_id: int, code: str) -> str:
    return hmac.new(_verification_secret(), f"email-verification:{user_id}:{code}".encode(), hashlib.sha256).hexdigest()


def _create_signup_verification(user: User, db: Session) -> str:
    code = f"{secrets.randbelow(1_000_000):06d}"
    now = datetime.now(timezone.utc)
    record = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first()
    if record:
        record.code_hash = _verification_code_hash(user.id, code)
        record.expires_at = now + timedelta(minutes=EMAIL_CODE_MINUTES)
        record.created_at = now
        record.attempts = 0
    else:
        db.add(EmailVerification(
            user_id=user.id,
            code_hash=_verification_code_hash(user.id, code),
            expires_at=now + timedelta(minutes=EMAIL_CODE_MINUTES),
            created_at=now,
            attempts=0,
        ))
    db.commit()
    return code


def user_json(user: User) -> dict:
    return {"id": user.id, "name": user.name, "email": user.email, "role": user.role, "created_at": user.created_at}


def _verify_supabase_access_token(access_token: str) -> dict:
    supabase_url = os.getenv("SUPABASE_URL", "").strip().rstrip("/")
    publishable_key = (
        os.getenv("SUPABASE_PUBLISHABLE_KEY", "").strip()
        or os.getenv("SUPABASE_ANON_KEY", "").strip()
    )
    if not supabase_url or not publishable_key:
        raise HTTPException(503, "Supabase Auth is not configured on the backend.")
    api_request = urllib_request.Request(
        f"{supabase_url}/auth/v1/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "apikey": publishable_key,
        },
        method="GET",
    )
    try:
        with urllib_request.urlopen(api_request, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib_error.HTTPError as exc:
        if exc.code in {401, 403}:
            raise HTTPException(401, "Your Supabase session has expired. Sign in again.") from None
        raise HTTPException(503, "Supabase Auth could not be reached.") from None
    except (urllib_error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        raise HTTPException(503, "Supabase Auth could not be reached.") from None


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


@router.post("/supabase/session")
def exchange_supabase_session(
    payload: SupabaseSessionRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    supabase_user = _verify_supabase_access_token(payload.access_token)
    email = supabase_user.get("email")
    if not isinstance(email, str):
        raise HTTPException(401, "The Supabase session does not contain a verified email.")
    email = _normalize_email(email)
    if not supabase_user.get("email_confirmed_at"):
        raise HTTPException(403, "Verify your email before signing in.")

    user = db.query(User).filter(User.email == email).first()
    metadata = supabase_user.get("user_metadata") if isinstance(supabase_user.get("user_metadata"), dict) else {}
    supplied_name = payload.name.strip()[:120] if payload.name else ""
    metadata_name = metadata.get("name")
    name = supplied_name or (metadata_name.strip()[:120] if isinstance(metadata_name, str) else "")

    if user:
        if name and not user.name.strip():
            user.name = name
        user.email_verified = True
    else:
        user = User(
            name=name or email.split("@", 1)[0][:120],
            email=email,
            password_hash=_password_hash(secrets.token_urlsafe(48)),
            email_verified=True,
            is_active=True,
        )
        db.add(user)

    try:
        db.commit()
        db.refresh(user)
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "This account is already linked to another NetSentry account.") from exc
    if not user.is_active:
        raise HTTPException(403, "This NetSentry account is unavailable.")

    _issue_session(user, response, db)
    return {"user": user_json(user)}


@router.post("/register", status_code=201)
def register(payload: RegisterRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    name = payload.name.strip()
    email = _normalize_email(payload.email)
    if not name:
        raise HTTPException(422, "Enter your name.")
    if not re.search(r"[a-z]", payload.password) or not re.search(r"[A-Z]", payload.password) or not re.search(r"\d", payload.password):
        raise HTTPException(422, "Password must include an uppercase letter, a lowercase letter, and a number.")

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        if existing.email_verified:
            raise HTTPException(409, "An account with this email already exists.")
        raise HTTPException(429, "This account is waiting for email verification.")

    user = User(
        name=name,
        email=email,
        password_hash=_password_hash(payload.password),
        email_verified=False,
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(409, "An account with this email already exists.") from exc

    db.refresh(user)
    code = _create_signup_verification(user, db)
    try:
        send_verification_email(user.email, user.name, code)
    except HTTPException:
        db.query(EmailVerification).filter(EmailVerification.user_id == user.id).delete(synchronize_session=False)
        db.delete(user)
        db.commit()
        logger.error("Signup verification email delivery failed.")
        raise
    return {"verification_required": True, "email": user.email}


@router.post("/verify-email")
def verify_email(payload: VerifyEmailRequest, response: Response, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    user = db.query(User).filter(User.email == email).first()
    record = db.query(EmailVerification).filter(EmailVerification.user_id == user.id).first() if user else None
    if not record or user.email_verified:
        raise HTTPException(400, "The verification code is invalid or expired.")
    if _aware(record.expires_at) <= datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        raise HTTPException(400, "The verification code is invalid or expired.")
    if record.attempts >= EMAIL_CODE_MAX_ATTEMPTS:
        raise HTTPException(429, "Too many attempts. Request a new verification code.")
    submitted = _verification_code_hash(user.id, payload.code)
    if not hmac.compare_digest(submitted, record.code_hash):
        record.attempts += 1
        db.commit()
        raise HTTPException(400, "The verification code is invalid or expired.")

    user.email_verified = True
    db.delete(record)
    db.commit()
    _issue_session(user, response, db)
    return {"user": user_json(user)}


@router.post("/verification/resend", status_code=202)
def resend_verification(payload: ResendVerificationRequest, request: Request, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    _validate_email_delivery_config()
    _rate_limit_email_verification(request, email, db)
    user = db.query(User).filter(User.email == email, User.email_verified.is_(False), User.is_active.is_(True)).first()
    if user:
        _enforce_resend_cooldown(user, db)
        code = _create_signup_verification(user, db)
        send_verification_email(user.email, user.name, code)
    return {"message": "If an unverified account matches that email, a new verification code will be sent."}


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    user = db.query(User).filter(User.email == email).first()
    if not user or not _password_matches(payload.password, user.password_hash):
        raise HTTPException(401, "Email or password is incorrect.")
    if not user.is_active:
        raise HTTPException(403, "This NetSentry account is unavailable.")
    if not user.email_verified:
        if not _enforce_resend_cooldown_for_login(user, db):
            code = _create_signup_verification(user, db)
            send_verification_email(user.email, user.name, code)
            message = "Verify your email before signing in. A new code was sent to your email."
        else:
            message = "Verify your email before signing in. Use the code already sent or request a new one shortly."
        raise HTTPException(403, message)
    _issue_session(user, response, db)
    return {"user": user_json(user)}


RESET_GENERIC_MESSAGE = "If an active account matches that email, a password reset code will be sent."
RESET_INVALID_MESSAGE = "The reset code is invalid or expired. Request a new code and try again."


@router.post("/forgot-password", status_code=202)
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    email = _normalize_email(payload.email)
    _validate_email_delivery_config()
    try:
        _rate_limit_reset_request(request, email, db)
        user = db.query(User).filter(User.email == email, User.email_verified.is_(True), User.is_active.is_(True)).first()
        if user:
            code = f"{secrets.randbelow(1_000_000):06d}"
            now = datetime.now(timezone.utc)
            record = db.query(PasswordResetOtp).filter(PasswordResetOtp.user_id == user.id).first()
            if record:
                record.code_hash = hmac.new(_verification_secret(), f"password-reset:{user.id}:{code}".encode(), hashlib.sha256).hexdigest()
                record.expires_at = now + timedelta(minutes=PASSWORD_RESET_OTP_MINUTES)
                record.created_at = now
                record.attempts = 0
                record.verified_at = None
                record.reset_token_hash = None
                record.reset_token_expires_at = None
            else:
                record = PasswordResetOtp(
                    user_id=user.id,
                    code_hash=hmac.new(_verification_secret(), f"password-reset:{user.id}:{code}".encode(), hashlib.sha256).hexdigest(),
                    expires_at=now + timedelta(minutes=PASSWORD_RESET_OTP_MINUTES),
                    created_at=now,
                    attempts=0,
                )
                db.add(record)
            db.commit()
            try:
                send_password_reset_email(user.email, user.name, code)
            except HTTPException:
                db.delete(record)
                db.commit()
                logger.error("Password reset email delivery failed.")
                raise
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Password reset request failed due to database error (%s).", type(exc).__name__)
        raise HTTPException(503, "Password reset is temporarily unavailable due to a database error.") from None
    return {"message": RESET_GENERIC_MESSAGE}


@router.post("/verify-reset-otp")
def verify_reset_otp(payload: VerifyResetOtpRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    _consume_auth_rate_limit(
        f"password-reset-verify:ip:{request.client.host if request.client else 'unknown'}",
        db,
        RESET_RATE_LIMIT_MAX_REQUESTS,
        RESET_RATE_LIMIT_WINDOW_SECONDS,
    )
    email = _normalize_email(payload.email)
    user = db.query(User).filter(User.email == email, User.email_verified.is_(True), User.is_active.is_(True)).first()
    record = db.query(PasswordResetOtp).filter(PasswordResetOtp.user_id == user.id).first() if user else None
    if record and _aware(record.expires_at) <= datetime.now(timezone.utc):
        db.delete(record)
        db.commit()
        raise HTTPException(400, RESET_INVALID_MESSAGE)
    if not record or record.verified_at or record.attempts >= EMAIL_CODE_MAX_ATTEMPTS:
        raise HTTPException(400, RESET_INVALID_MESSAGE)
    submitted = hmac.new(_verification_secret(), f"password-reset:{user.id}:{payload.code}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(submitted, record.code_hash):
        record.attempts += 1
        db.commit()
        raise HTTPException(400, RESET_INVALID_MESSAGE)

    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    record.code_hash = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
    record.verified_at = now
    record.reset_token_hash = hashlib.sha256(token.encode()).hexdigest()
    record.reset_token_expires_at = now + timedelta(minutes=PASSWORD_RESET_TOKEN_MINUTES)
    db.commit()
    _set_reset_cookies(response, token)
    return {"verified": True, "message": "Code verified. You can now choose a new password."}


@router.post("/reset-password")
def reset_password(payload: ResetPasswordRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    _consume_auth_rate_limit(
        f"password-reset-submit:ip:{request.client.host if request.client else 'unknown'}",
        db,
        RESET_RATE_LIMIT_MAX_REQUESTS,
        RESET_RATE_LIMIT_WINDOW_SECONDS,
    )
    if not re.search(r"[a-z]", payload.password) or not re.search(r"[A-Z]", payload.password) or not re.search(r"\d", payload.password):
        raise HTTPException(422, "Password must include an uppercase letter, a lowercase letter, and a number.")
    token = request.cookies.get("netsentry_reset_token", "")
    csrf_cookie = request.cookies.get("netsentry_reset_csrf", "")
    csrf_header = request.headers.get("x-csrf-token", "")
    if not token or not csrf_cookie or not hmac.compare_digest(csrf_cookie, csrf_header):
        raise HTTPException(401, RESET_INVALID_MESSAGE)
    record = db.query(PasswordResetOtp).filter(
        PasswordResetOtp.reset_token_hash == hashlib.sha256(token.encode()).hexdigest(),
        PasswordResetOtp.verified_at.is_not(None),
    ).first()
    if not record or not record.reset_token_expires_at or _aware(record.reset_token_expires_at) <= datetime.now(timezone.utc):
        raise HTTPException(401, RESET_INVALID_MESSAGE)
    user = db.get(User, record.user_id)
    if not user or not user.is_active:
        raise HTTPException(401, RESET_INVALID_MESSAGE)
    user.password_hash = _password_hash(payload.password)
    now = datetime.now(timezone.utc)
    db.query(UserSession).filter(UserSession.user_id == user.id, UserSession.revoked_at.is_(None)).update(
        {UserSession.revoked_at: now},
        synchronize_session=False,
    )
    db.delete(record)
    db.commit()
    _clear_reset_cookies(response)
    return {"message": "Password reset successfully. Sign in with your new password."}


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

    email = _normalize_email(email if isinstance(email, str) else "")
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

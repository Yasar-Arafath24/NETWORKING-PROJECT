"""Send one explicit test email through the Brevo SMTP relay."""

import argparse
from email.message import EmailMessage
from email.utils import formataddr
import os
from pathlib import Path
import smtplib
import ssl
import sys

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ENV = PROJECT_ROOT / "backend" / ".env"
ENV_FILE = BACKEND_ENV if BACKEND_ENV.is_file() else PROJECT_ROOT / ".env"


def _smtp_settings() -> tuple[str, str, str, str]:
    load_dotenv(ENV_FILE)
    host = os.getenv("MAIL_HOST", "").strip()
    port = os.getenv("MAIL_PORT", "").strip()
    username = os.getenv("MAIL_USERNAME", "").strip()
    password = os.getenv("MAIL_PASSWORD", "")
    sender = os.getenv("MAIL_FROM", "").strip()
    sender_name = os.getenv("MAIL_FROM_NAME", "NetSentry AI").strip()
    use_tls = os.getenv("MAIL_STARTTLS", "").strip().lower() == "true"

    if host != "smtp-relay.brevo.com":
        raise ValueError("Set MAIL_HOST=smtp-relay.brevo.com in the backend .env file.")
    if port != "587" or not use_tls:
        raise ValueError("Brevo SMTP requires MAIL_PORT=587 and MAIL_STARTTLS=true.")
    if not username or not password:
        raise ValueError("Set your Brevo SMTP login and SMTP key in MAIL_USERNAME and MAIL_PASSWORD.")
    if not sender:
        raise ValueError("Set MAIL_FROM to a sender address verified in Brevo.")
    return username, password, sender, sender_name


def send_test_email(recipient: str) -> None:
    username, password, sender, sender_name = _smtp_settings()
    message = EmailMessage()
    message["Subject"] = "NetSentry AI SMTP test"
    message["From"] = formataddr((sender_name, sender))
    message["To"] = recipient
    message.set_content(
        "This is a test email confirming that NetSentry AI can send mail through Brevo SMTP."
    )

    with smtplib.SMTP("smtp-relay.brevo.com", 587, timeout=15) as smtp:
        smtp.ehlo()
        smtp.starttls(context=ssl.create_default_context())
        smtp.ehlo()
        smtp.login(username, password)
        refused = smtp.send_message(message)
        if refused:
            raise smtplib.SMTPRecipientsRefused(refused)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send one test email through Brevo SMTP.")
    parser.add_argument("recipient", help="Email address authorized to receive the test email")
    args = parser.parse_args(argv)
    try:
        send_test_email(args.recipient)
    except ValueError as exc:
        print(f"Brevo SMTP configuration error: {exc}", file=sys.stderr)
        return 2
    except smtplib.SMTPAuthenticationError:
        print("Brevo SMTP authentication failed. Check MAIL_USERNAME and MAIL_PASSWORD.", file=sys.stderr)
        return 1
    except (TimeoutError, ConnectionError, OSError, smtplib.SMTPException):
        print("Brevo SMTP test failed during connection or delivery. Check settings and try again.", file=sys.stderr)
        return 1

    print(f"Brevo SMTP test email accepted for delivery to {args.recipient}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

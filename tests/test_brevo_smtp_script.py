import smtplib
from unittest.mock import patch

from scripts import test_brevo_smtp


def _configure_brevo(monkeypatch):
    monkeypatch.setenv("MAIL_HOST", "smtp-relay.brevo.com")
    monkeypatch.setenv("MAIL_PORT", "587")
    monkeypatch.setenv("MAIL_USERNAME", "brevo-smtp-login")
    monkeypatch.setenv("MAIL_PASSWORD", "private-test-smtp-key")
    monkeypatch.setenv("MAIL_FROM", "verified@example.com")
    monkeypatch.setenv("MAIL_FROM_NAME", "NetSentry AI")
    monkeypatch.setenv("MAIL_STARTTLS", "true")
    monkeypatch.setattr(test_brevo_smtp, "load_dotenv", lambda *_args, **_kwargs: None)


def test_brevo_test_script_sends_one_mocked_message_without_printing_credentials(monkeypatch, capsys):
    _configure_brevo(monkeypatch)
    state = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            state.update(host=host, port=port, timeout=timeout)

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def ehlo(self):
            state["ehlo"] = state.get("ehlo", 0) + 1

        def starttls(self, context):
            state["tls_context"] = context

        def login(self, username, password):
            state["credentials"] = (username, password)

        def send_message(self, message):
            state["message"] = message
            return {}

    with patch.object(test_brevo_smtp.smtplib, "SMTP", FakeSMTP):
        result = test_brevo_smtp.main(["authorized@example.com"])

    output = capsys.readouterr().out
    assert result == 0
    assert state["host"] == "smtp-relay.brevo.com"
    assert state["port"] == 587
    assert state["ehlo"] == 2
    assert state["credentials"] == ("brevo-smtp-login", "private-test-smtp-key")
    assert state["message"]["To"] == "authorized@example.com"
    assert "private-test-smtp-key" not in output
    assert "brevo-smtp-login" not in output
    assert "accepted for delivery" in output


def test_brevo_test_script_reports_authentication_failure_without_secret(monkeypatch, capsys):
    _configure_brevo(monkeypatch)

    class RejectingSMTP:
        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def ehlo(self):
            pass

        def starttls(self, **_kwargs):
            pass

        def login(self, *_args):
            raise smtplib.SMTPAuthenticationError(535, b"private-test-smtp-key rejected")

    with patch.object(test_brevo_smtp.smtplib, "SMTP", RejectingSMTP):
        result = test_brevo_smtp.main(["authorized@example.com"])

    output = capsys.readouterr().err
    assert result == 1
    assert "authentication failed" in output.lower()
    assert "private-test-smtp-key" not in output


def test_brevo_test_script_validates_settings_before_connecting(monkeypatch, capsys):
    _configure_brevo(monkeypatch)
    monkeypatch.setenv("MAIL_FROM", "")

    with patch.object(test_brevo_smtp.smtplib, "SMTP") as smtp:
        result = test_brevo_smtp.main(["authorized@example.com"])

    assert result == 2
    assert "verified in Brevo" in capsys.readouterr().err
    smtp.assert_not_called()

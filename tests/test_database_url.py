import pytest

from backend.app.services.database import _configured_database_url, _parse_database_url


def test_empty_database_environment_values_fall_back_to_sqlite(monkeypatch):
    for name in (
        "NETSENTRY_DATABASE_URL",
        "SUPABASE_DATABASE_URL",
        "SUPABASE_DB_URL",
        "DATABASE_URL",
    ):
        monkeypatch.setenv(name, "  ")

    assert _configured_database_url().startswith("sqlite:///")


def test_database_url_parser_reports_invalid_port_without_echoing_credentials():
    exposed_password = "must-not-appear-in-error"

    with pytest.raises(RuntimeError) as error:
        _parse_database_url(
            f"postgresql+psycopg2://postgres.project:{exposed_password}@://supabase.com"
        )

    assert "hostname and port syntax" in str(error.value)
    assert exposed_password not in str(error.value)


def test_database_url_parser_requires_a_postgres_hostname():
    with pytest.raises(RuntimeError, match="hostname is missing"):
        _parse_database_url("postgresql+psycopg2://postgres:password@/postgres")


def test_database_url_parser_accepts_valid_postgres_host_and_port():
    url = _parse_database_url(
        "postgresql+psycopg2://postgres.project:encoded%40password@db.example.supabase.co:5432/postgres"
    )

    assert url.host == "db.example.supabase.co"
    assert url.port == 5432

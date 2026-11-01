import pytest

from backend.app.services.database import get_database_url, normalize_supabase_url, validate_database_url


def test_empty_database_environment_values_fall_back_to_sqlite(monkeypatch):
    for name in (
        "NETSENTRY_DATABASE_URL",
        "SUPABASE_DATABASE_URL",
        "SUPABASE_DB_URL",
        "DATABASE_URL",
    ):
        monkeypatch.setenv(name, "  ")

    assert get_database_url().startswith("sqlite:///")


def test_database_url_parser_reports_invalid_port_without_echoing_credentials():
    exposed_password = "must-not-appear-in-error"

    with pytest.raises(RuntimeError) as error:
        validate_database_url(
            f"postgresql+psycopg2://postgres.project:{exposed_password}@://supabase.com"
        )

    assert "Invalid database URL configuration string" in str(error.value)
    assert exposed_password not in str(error.value)


def test_database_url_parser_requires_a_postgres_hostname():
    with pytest.raises(RuntimeError, match="hostname is missing"):
        validate_database_url("postgresql+psycopg2://postgres:password@/postgres")


def test_database_url_parser_accepts_valid_postgres_host_and_port():
    url = validate_database_url(
        "postgresql+psycopg2://postgres.project:encoded%40password@db.example.supabase.co:5432/postgres"
    )

    assert url.host == "db.example.supabase.co"
    assert url.port == 5432


def test_pooler_username_uses_configured_supabase_project_reference(monkeypatch):
    monkeypatch.setenv("SUPABASE_PROJECT_REF", "")
    monkeypatch.setenv("SUPABASE_URL", "https://exampleproject.supabase.co")

    url = normalize_supabase_url(
        "postgresql://postgres:example-password@aws-0-region.pooler.supabase.com:5432/postgres"
    )

    assert url.startswith("postgresql://postgres.exampleproject:")

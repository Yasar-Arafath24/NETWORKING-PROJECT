import os
from pathlib import Path

from dotenv import load_dotenv

# Load the project's local environment file regardless of the shell's cwd.
load_dotenv(Path(__file__).resolve().parents[2] / ".env")

# Make local development usable without SMTP credentials. Production still
# requires explicit verification configuration, so verification secrets and
# delivery methods are never silently weakened outside development.
if not os.getenv("NETSENTRY_ENV", "").strip():
    os.environ["NETSENTRY_ENV"] = "development"
if os.getenv("NETSENTRY_ENV", "").strip().lower() == "development":
    os.environ.setdefault(
        "NETSENTRY_OTP_SECRET",
        "netsentry-local-development-verification-secret-at-least-32-characters",
    )

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.history_routes import router as history_router
from backend.app.api.auth_routes import router as auth_router
from backend.app.api.website_routes import ingest_router as website_ingest_router, router as website_router
from backend.app.api.routes import health_check, router
from backend.app.services.database import Base, engine
from sqlalchemy import inspect, text
from backend.app.models.analysis import AnalysisReport
from backend.app.models.live_monitoring import LiveFlowRecord, NetworkAlert
from backend.app.models.user import EmailVerification, User, UserSession
from backend.app.models.website_monitor import MonitoredWebsite, WebsiteTrafficEvent
from backend.app.models.traffic_monitoring import AnalysisHistory, TrafficFlowRecord

if engine.dialect.name == "sqlite" and os.getenv("NETSENTRY_ENV", "").lower() == "production":
    raise RuntimeError(
        "Production requires NETSENTRY_DATABASE_URL, SUPABASE_DATABASE_URL, "
        "or SUPABASE_DB_URL to point to Supabase/PostgreSQL."
    )

Base.metadata.create_all(bind=engine)
with engine.begin() as connection:
    connection.execute(text("CREATE INDEX IF NOT EXISTS ix_website_events_site_created ON website_traffic_events (site_id, created_at)"))
for table_name in ("live_flow_records", "network_alerts"):
    columns = {column["name"] for column in inspect(engine).get_columns(table_name)}
    if "owner_id" not in columns:
        with engine.begin() as connection:
            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN owner_id INTEGER NULL REFERENCES users(id) ON DELETE CASCADE"))
    with engine.begin() as connection:
        connection.execute(text(f"CREATE INDEX IF NOT EXISTS ix_{table_name}_owner_id ON {table_name} (owner_id)"))
user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
if "email_verified" not in user_columns:
    default = "TRUE" if engine.dialect.name == "postgresql" else "1"
    with engine.begin() as connection:
        connection.execute(text(f"ALTER TABLE users ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT {default}"))
    user_columns.add("email_verified")
if "google_subject" not in user_columns:
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE users ADD COLUMN google_subject VARCHAR(255) NULL"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_google_subject ON users (google_subject)"))
if "owner_id" not in {column["name"] for column in inspect(engine).get_columns("analysis_reports")}:
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE analysis_reports ADD COLUMN owner_id INTEGER REFERENCES users(id)"))
        connection.execute(text("CREATE INDEX IF NOT EXISTS ix_analysis_reports_owner_id ON analysis_reports (owner_id)"))
website_columns = {column["name"] for column in inspect(engine).get_columns("monitored_websites")}
if "authorization_confirmed" not in website_columns:
    default = "FALSE" if engine.dialect.name == "postgresql" else "0"
    with engine.begin() as connection:
        connection.execute(text(
            "ALTER TABLE monitored_websites ADD COLUMN "
            f"authorization_confirmed BOOLEAN NOT NULL DEFAULT {default}"
        ))
    website_columns.add("authorization_confirmed")
if "platform" not in website_columns:
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE monitored_websites ADD COLUMN platform VARCHAR(20) NOT NULL DEFAULT 'custom'"))
if "collector_revoked_at" not in website_columns:
    timestamp_type = "TIMESTAMP WITH TIME ZONE" if engine.dialect.name == "postgresql" else "TIMESTAMP"
    with engine.begin() as connection:
        connection.execute(text(f"ALTER TABLE monitored_websites ADD COLUMN collector_revoked_at {timestamp_type} NULL"))
website_columns = {column["name"] for column in inspect(engine).get_columns("monitored_websites")}
if "integration_method" not in website_columns:
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE monitored_websites ADD COLUMN integration_method VARCHAR(32) NOT NULL DEFAULT 'generic_jsonl'"))
for column_name, column_type, default_sql in (
    ("collector_status", "VARCHAR(16)", "'UNKNOWN'"),
    ("collector_last_seen_at", "TIMESTAMP WITH TIME ZONE" if engine.dialect.name == "postgresql" else "TIMESTAMP", None),
    ("collector_last_error", "VARCHAR(1000)", "''"),
    ("collector_last_error_at", "TIMESTAMP WITH TIME ZONE" if engine.dialect.name == "postgresql" else "TIMESTAMP", None),
):
    if column_name not in website_columns:
        default_clause = f" NOT NULL DEFAULT {default_sql}" if default_sql is not None else " NULL"
        with engine.begin() as connection:
            connection.execute(text(f"ALTER TABLE monitored_websites ADD COLUMN {column_name} {column_type}{default_clause}"))
event_columns = {column["name"] for column in inspect(engine).get_columns("website_traffic_events")}
if "request_timestamp" not in event_columns:
    timestamp_type = "TIMESTAMP WITH TIME ZONE" if engine.dialect.name == "postgresql" else "TIMESTAMP"
    with engine.begin() as connection:
        connection.execute(text(f"ALTER TABLE website_traffic_events ADD COLUMN request_timestamp {timestamp_type} NULL"))
if "event_id" not in event_columns:
    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE website_traffic_events ADD COLUMN event_id VARCHAR(128) NULL"))
with engine.begin() as connection:
    connection.execute(text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_website_events_site_event_id "
        "ON website_traffic_events (site_id, event_id)"
    ))

app = FastAPI(
    title="NetSentry AI",
    description="Privacy-Preserving Intelligent Network Traffic Classification & Adaptive Threat Defense",
    version="0.1.0",
)


# Allow frontend communication later
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("NETSENTRY_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)
app.include_router(history_router)
app.include_router(auth_router)
app.include_router(website_router)
app.include_router(website_ingest_router)

app.add_api_route(
    "/health",
    health_check,
    methods=["GET"],
    include_in_schema=False,
)


@app.get("/")
def root():
    return {
        "name": "NetSentry AI",
        "status": "running",
        "version": "0.1.0",
    }
@app.get("/api/v1/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "NetSentry AI API",
        "version": "1.0.0",
    }

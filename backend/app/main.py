import os

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
from backend.app.models.user import User, UserSession
from backend.app.models.website_monitor import MonitoredWebsite, WebsiteTrafficEvent

Base.metadata.create_all(bind=engine)
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

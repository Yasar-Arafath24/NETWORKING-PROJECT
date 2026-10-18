from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.app.api.routes import health_check, router
from backend.app.services.database import Base, engine
from backend.app.models.analysis import AnalysisReport
from backend.app.models.live_monitoring import LiveFlowRecord, NetworkAlert

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="NetSentry AI",
    description="Privacy-Preserving Intelligent Network Traffic Classification & Adaptive Threat Defense",
    version="0.1.0",
)


# Allow frontend communication later
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(router)

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
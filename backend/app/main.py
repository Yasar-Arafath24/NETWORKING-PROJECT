from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes import router


app = FastAPI(
    title="NetSentry AI",
    description="Privacy-Preserving Intelligent Network Traffic Classification & Adaptive Threat Defense",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)


@app.get("/")
def root():
    return {
        "name": "NetSentry AI",
        "status": "running",
        "version": "0.1.0",
    }
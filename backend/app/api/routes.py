
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1", tags=["NetSentry"])


# -----------------------------
# Request model for prediction
# -----------------------------
class TrafficFeatures(BaseModel):
    packet_count: int = Field(ge=0)
    total_bytes: int = Field(ge=0)
    duration: float = Field(ge=0)
    packet_rate: float = Field(ge=0)
    byte_rate: float = Field(ge=0)
    average_packet_size: float = Field(ge=0)
    min_packet_size: int = Field(ge=0)
    max_packet_size: int = Field(ge=0)
    forward_packets: int = Field(ge=0)
    backward_packets: int = Field(ge=0)
    forward_bytes: int = Field(ge=0)
    backward_bytes: int = Field(ge=0)


# -----------------------------
# Health check
# -----------------------------
@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NetSentry AI Backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# -----------------------------
# System information
# -----------------------------
@router.get("/system/info")
def system_info():
    return {
        "project": "NetSentry AI",
        "backend": "FastAPI",
        "phase": "Backend Foundation",
        "status": "development",
    }


# -----------------------------
# Traffic prediction
# -----------------------------
@router.post("/predict")
def predict_traffic(features: TrafficFeatures):
    try:
        # Import inside the endpoint so the API can start even if
        # the prediction service is not configured yet.
        from backend.app.services.prediction_service import predict

        result = predict(features.model_dump())

        return {
            "status": "success",
            "prediction": result,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Prediction service is not configured. "
                "Check backend/app/services/prediction_service.py."
            ),
        ) from exc

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="Trained model files are missing. Train the traffic classifier first.",
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Traffic prediction failed: {str(exc)}",
        ) from exc

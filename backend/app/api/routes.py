
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import APIRouter, File, HTTPException, UploadFile
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1", tags=["NetSentry"])


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


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NetSentry AI Backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/system/info")
def system_info():
    return {
        "project": "NetSentry AI",
        "backend": "FastAPI",
        "phase": "PCAP Analysis and Anomaly Detection",
        "status": "development",
    }


@router.post("/predict")
def predict_traffic(features: TrafficFeatures):
    try:
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
            detail="Prediction service is not configured.",
        ) from exc
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="Trained model files are missing.",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Traffic prediction failed: {str(exc)}",
        ) from exc


@router.post("/pcap/analyze")
async def analyze_pcap_upload(file: UploadFile = File(...)):
    filename = (file.filename or "").lower()

    if not filename.endswith((".pcap", ".pcapng")):
        raise HTTPException(
            status_code=400,
            detail="Upload a .pcap or .pcapng file.",
        )

    temp_path = None

    try:
        # Save the upload temporarily so Scapy can read it.
        with NamedTemporaryFile(delete=False, suffix=Path(filename).suffix) as temp:
            temp_path = Path(temp.name)

            while chunk := await file.read(1024 * 1024):
                temp.write(chunk)

        if temp_path.stat().st_size == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        from backend.app.services.pcap_service import analyze_pcap
        from ml.anomaly_detector import predict_anomalies

        analysis = analyze_pcap(temp_path)
        flows = analysis["flows"]

        if not flows:
            return {
                "status": "success",
                **analysis,
                "anomaly_detection": {
                    "status": "no_flows",
                    "predictions": [],
                    "suspicious_flows": 0,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        predictions = predict_anomalies(flows)

        # Match predictions to flows using flow_index.
        indexed_predictions = {
            item["flow_index"]: item for item in predictions
        }

        enriched_flows = []
        for index, flow in enumerate(flows):
            prediction = indexed_predictions.get(index, {})
            enriched_flows.append({
                **flow,
                "anomaly": prediction.get("anomaly"),
                "label": prediction.get("label", "UNAVAILABLE"),
                "anomaly_score": prediction.get("anomaly_score"),
            })

        suspicious_count = sum(
            1 for flow in enriched_flows
            if flow["label"] == "SUSPICIOUS"
        )

        return {
            "status": "success",
            "total_packets": analysis["total_packets"],
            "total_flows": analysis["total_flows"],
            "flows_returned": len(enriched_flows),
            "flows": enriched_flows,
            "anomaly_detection": {
                "status": "completed",
                "model_note": (
                    "The current model was trained on synthetic demo data. "
                    "Predictions are experimental, not validated security findings."
                ),
                "suspicious_flows": suspicious_count,
                "normal_flows": len(enriched_flows) - suspicious_count,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except HTTPException:
        raise
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Required model or file is missing: {exc}",
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {str(exc)}",
        ) from exc
    finally:
        await file.close()
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

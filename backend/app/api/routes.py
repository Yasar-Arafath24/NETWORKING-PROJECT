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
        "phase": "PCAP Analysis, Anomaly Detection and Risk Assessment",
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
            detail=f"Traffic prediction failed: {exc}",
        ) from exc


def calculate_risk_assessment(
    total_flows: int,
    suspicious_flows: int,
) -> dict:
    """Calculate a provisional heuristic traffic risk indicator."""
    if total_flows <= 0:
        return {
            "risk_level": "UNAVAILABLE",
            "anomaly_rate_percent": 0.0,
            "risk_indicator_score": 0,
            "explanation": "No network flows were available for assessment.",
            "assessment_type": "heuristic",
            "validated_for_real_world_attacks": False,
        }

    anomaly_rate = round((suspicious_flows / total_flows) * 100, 2)

    if anomaly_rate >= 30:
        risk_level = "HIGH"
        explanation = (
            "At least 30% of analyzed flows were classified as "
            "suspicious by the experimental anomaly detector. "
            "This warrants further investigation, not a conclusion "
            "that an attack has occurred."
        )
    elif anomaly_rate >= 10:
        risk_level = "MEDIUM"
        explanation = (
            "At least 10% but less than 30% of analyzed flows were "
            "classified as suspicious by the experimental detector."
        )
    else:
        risk_level = "LOW"
        explanation = (
            "Fewer than 10% of analyzed flows were classified as "
            "suspicious. This does not establish that the traffic "
            "is safe."
        )

    return {
        "risk_level": risk_level,
        "anomaly_rate_percent": anomaly_rate,
        "risk_indicator_score": round(anomaly_rate),
        "explanation": explanation,
        "assessment_type": "heuristic",
        "validated_for_real_world_attacks": False,
    }


@router.post("/pcap/analyze")
async def analyze_pcap_upload(file: UploadFile = File(...)):
    filename = (file.filename or "").lower()
    if not filename.endswith((".pcap", ".pcapng")):
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="Upload a .pcap or .pcapng file.",
        )

    temp_path = None
    try:
        with NamedTemporaryFile(
            delete=False,
            suffix=Path(filename).suffix,
        ) as temp:
            temp_path = Path(temp.name)

            while chunk := await file.read(1024 * 1024):
                temp.write(chunk)

        if temp_path.stat().st_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty.",
            )

        from backend.app.services.pcap_service import analyze_pcap
        from ml.anomaly_detector import predict_anomalies

        analysis = analyze_pcap(temp_path)
        flows = analysis["flows"]

        if not flows:
            return {
                "status": "success",
                "total_packets": analysis["total_packets"],
                "total_flows": analysis["total_flows"],
                "flows_returned": 0,
                "flows": [],
                "risk_assessment": calculate_risk_assessment(0, 0),
                "anomaly_detection": {
                    "status": "no_flows",
                    "model_note": (
                        "No flows were available for anomaly detection."
                    ),
                    "suspicious_flows": 0,
                    "normal_flows": 0,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

        predictions = predict_anomalies(flows)
        indexed_predictions = {
            item["flow_index"]: item
            for item in predictions
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
            flow["label"] == "SUSPICIOUS"
            for flow in enriched_flows
        )
        normal_count = sum(
            flow["label"] == "NORMAL"
            for flow in enriched_flows
        )
        unavailable_count = (
            len(enriched_flows) - suspicious_count - normal_count
        )
        risk_assessment = calculate_risk_assessment(
            total_flows=len(enriched_flows),
            suspicious_flows=suspicious_count,
        )

        return {
            "status": "success",
            "total_packets": analysis["total_packets"],
            "total_flows": analysis["total_flows"],
            "flows_returned": len(enriched_flows),
            "flows": enriched_flows,
            "traffic_summary": {
                "total_flows_analyzed": len(enriched_flows),
                "normal_flows": normal_count,
                "suspicious_flows": suspicious_count,
                "unavailable_predictions": unavailable_count,
            },
            "risk_assessment": risk_assessment,
            "anomaly_detection": {
                "status": (
                    "completed" if unavailable_count == 0 else "partial"
                ),
                "model_note": (
                    "The current model was trained on synthetic demo "
                    "data. Predictions are experimental and have not "
                    "been validated as real-world security findings."
                ),
                "suspicious_flows": suspicious_count,
                "normal_flows": normal_count,
                "unavailable_predictions": unavailable_count,
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
            detail=f"PCAP analysis failed: {exc}",
        ) from exc
    finally:
        await file.close()
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)

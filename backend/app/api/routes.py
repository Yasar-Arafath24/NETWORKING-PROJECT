
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
import json

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
)
from fastapi.encoders import jsonable_encoder
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.services.analysis_store import (
    get_latest_analysis,
    save_analysis,
)
from backend.app.services.database import get_db
from backend.app.models.analysis import AnalysisReport
from backend.app.core.upload_validation import (
    MAX_UPLOAD_SIZE,
    validate_pcap_upload,
)

router = APIRouter(prefix="/api/v1", tags=["NetSentry"])


# --------------------------------------------------
# REQUEST SCHEMA
# --------------------------------------------------

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


# --------------------------------------------------
# DATABASE REPORT HELPER
# --------------------------------------------------

def persist_analysis(response: dict, db: Session) -> int:
    """Persist an analysis response and return its report ID."""
    report = AnalysisReport(
        total_packets=int(response.get("total_packets", 0)),
        total_flows=int(response.get("total_flows", 0)),
        report_data=jsonable_encoder(response),
    )

    try:
        db.add(report)
        db.commit()
        db.refresh(report)
        return report.id
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to save analysis report to the database.",
        ) from exc


# --------------------------------------------------
# HEALTH AND SYSTEM INFORMATION
# --------------------------------------------------

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
        "phase": (
            "PCAP Analysis, Anomaly Detection, "
            "Risk Assessment and Persistent Reports"
        ),
        "status": "development",
    }


# --------------------------------------------------
# SINGLE-FLOW PREDICTION
# --------------------------------------------------

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


# --------------------------------------------------
# RISK ASSESSMENT
# --------------------------------------------------

def calculate_risk_assessment(
    total_flows: int,
    suspicious_flows: int,
) -> dict:
    """Calculate a provisional heuristic risk indicator."""

    if total_flows <= 0:
        return {
            "risk_level": "UNAVAILABLE",
            "anomaly_rate_percent": 0.0,
            "risk_indicator_score": 0,
            "explanation": "No network flows were available.",
            "assessment_type": "heuristic",
            "validated_for_real_world_attacks": False,
        }

    anomaly_rate = round(
        suspicious_flows / total_flows * 100,
        2,
    )

    if anomaly_rate >= 30:
        level = "HIGH"
        explanation = (
            "At least 30% of analyzed flows were classified "
            "as suspicious. Further investigation is warranted."
        )
    elif anomaly_rate >= 10:
        level = "MEDIUM"
        explanation = (
            "At least 10% but less than 30% of flows were "
            "classified as suspicious."
        )
    else:
        level = "LOW"
        explanation = (
            "Fewer than 10% of flows were classified as "
            "suspicious. This does not establish that traffic is safe."
        )

    return {
        "risk_level": level,
        "anomaly_rate_percent": anomaly_rate,
        "risk_indicator_score": round(anomaly_rate),
        "explanation": explanation,
        "assessment_type": "heuristic",
        "validated_for_real_world_attacks": False,
    }


# --------------------------------------------------
# PCAP ANALYSIS AND SQLITE PERSISTENCE
# --------------------------------------------------

@router.post("/pcap/analyze")
async def analyze_pcap_upload(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    original_filename = file.filename or ""
    extension = Path(original_filename).suffix.lower()

    # Reject unsupported extensions before reading the upload.
    if extension not in {".pcap", ".pcapng"}:
        await file.close()
        raise HTTPException(
            status_code=400,
            detail="Upload a .pcap or .pcapng file.",
        )

    temp_path = None

    try:
        # Read incrementally to enforce the size limit while uploading.
        total_size = 0

        with NamedTemporaryFile(
            mode="wb",
            delete=False,
            suffix=extension,
        ) as temp:
            temp_path = Path(temp.name)

            while True:
                chunk = await file.read(1024 * 1024)

                if not chunk:
                    break

                total_size += len(chunk)

                if total_size > MAX_UPLOAD_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Upload exceeds the 20 MiB size limit.",
                    )

                temp.write(chunk)

        if total_size == 0:
            raise HTTPException(
                status_code=400,
                detail="Uploaded file is empty.",
            )

        # Validate signature and file format before invoking Scapy.
        try:
            content = temp_path.read_bytes()
            validate_pcap_upload(original_filename, content)
        except ValueError as exc:
            raise HTTPException(
                status_code=400,
                detail=str(exc),
            ) from exc

        from backend.app.services.pcap_service import analyze_pcap
        from ml.anomaly_detector import predict_anomalies

        # Analyze the packet capture.
        try:
            analysis = analyze_pcap(temp_path)
        except Exception as exc:
            raise HTTPException(
                status_code=400,
                detail="The uploaded capture could not be parsed.",
            ) from exc

        flows = analysis["flows"]

        # Handle a capture that contains no extracted flows.
        if not flows:
            response = {
                "status": "success",
                "total_packets": analysis["total_packets"],
                "total_flows": analysis["total_flows"],
                "flows_returned": 0,
                "flows": [],
                "traffic_summary": {
                    "total_flows_analyzed": 0,
                    "normal_flows": 0,
                    "suspicious_flows": 0,
                    "unavailable_predictions": 0,
                },
                "risk_assessment": calculate_risk_assessment(0, 0),
                "anomaly_detection": {
                    "status": "no_flows",
                    "model_note": "No flows were available for detection.",
                    "suspicious_flows": 0,
                    "normal_flows": 0,
                    "unavailable_predictions": 0,
                },
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            report_id = persist_analysis(response, db)
            response["report_id"] = report_id
            save_analysis(response)

            return response

        # Predict anomalies for extracted flows.
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
            len(enriched_flows)
            - suspicious_count
            - normal_count
        )

        response = {
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
            "risk_assessment": calculate_risk_assessment(
                len(enriched_flows),
                suspicious_count,
            ),
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

        # Persist the report in SQLite and update the monitoring store.
        report_id = persist_analysis(response, db)
        response["report_id"] = report_id
        save_analysis(response)

        return response

    except HTTPException:
        raise

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=503,
            detail="A required model or file is missing.",
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


# --------------------------------------------------
# EXISTING IN-MEMORY MONITORING ENDPOINTS
# --------------------------------------------------

@router.get("/monitoring/latest")
def get_latest_monitoring_report():
    report = get_latest_analysis()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No PCAP analysis available. Analyze a PCAP first.",
        )

    return report


@router.get("/monitoring/suspicious")
def get_suspicious_flows():
    report = get_latest_analysis()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No PCAP analysis available.",
        )

    suspicious = [
        flow
        for flow in report.get("flows", [])
        if flow.get("anomaly") is True
        or str(flow.get("label", "")).upper() == "SUSPICIOUS"
    ]

    return {
        "total_suspicious_flows": len(suspicious),
        "flows": suspicious,
    }


@router.get("/monitoring/flows")
def filter_flows(
    status: str = Query(
        default="all",
        pattern="^(all|normal|suspicious)$",
    ),
):
    report = get_latest_analysis()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No PCAP analysis available.",
        )

    flows = report.get("flows", [])

    if status == "suspicious":
        flows = [
            flow for flow in flows
            if flow.get("anomaly") is True
            or str(flow.get("label", "")).upper() == "SUSPICIOUS"
        ]
    elif status == "normal":
        flows = [
            flow for flow in flows
            if flow.get("anomaly") is False
            or str(flow.get("label", "")).upper() == "NORMAL"
        ]

    return {
        "filter": status,
        "total_flows": len(flows),
        "flows": flows,
    }


@router.get("/monitoring/export")
def export_latest_report():
    report = get_latest_analysis()

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="No PCAP analysis available to export.",
        )

    return Response(
        content=json.dumps(report, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition":
                'attachment; filename="netsentry_report.json"'
        },
    )


# --------------------------------------------------
# PERSISTENT REPORT HISTORY
# --------------------------------------------------

@router.get("/monitoring/history")
def get_analysis_history(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    query = db.query(AnalysisReport)

    reports = (
        query.order_by(AnalysisReport.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    return {
        "total_reports": query.count(),
        "skip": skip,
        "limit": limit,
        "reports": [
            {
                "id": report.id,
                "total_packets": report.total_packets,
                "total_flows": report.total_flows,
                "created_at": report.created_at,
            }
            for report in reports
        ],
    }


@router.get("/monitoring/history/{report_id}")
def get_analysis_history_item(
    report_id: int,
    db: Session = Depends(get_db),
):
    report = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.id == report_id)
        .first()
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis report not found.",
        )

    return {
        "id": report.id,
        "total_packets": report.total_packets,
        "total_flows": report.total_flows,
        "created_at": report.created_at,
        "report_data": report.report_data,
    }


# --------------------------------------------------
# MONITORING STATISTICS
# --------------------------------------------------

@router.get("/monitoring/statistics")
def get_monitoring_statistics(
    db: Session = Depends(get_db),
):
    """Summarize saved PCAP analysis reports."""

    reports = (
        db.query(AnalysisReport)
        .order_by(AnalysisReport.id.desc())
        .all()
    )

    total_packets = sum(r.total_packets for r in reports)
    total_flows = sum(r.total_flows for r in reports)

    suspicious_flows = 0
    normal_flows = 0
    unavailable_predictions = 0

    risk_levels = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNAVAILABLE": 0,
    }

    for report in reports:
        data = report.report_data or {}
        summary = data.get("traffic_summary", {})

        suspicious_flows += summary.get("suspicious_flows", 0)
        normal_flows += summary.get("normal_flows", 0)
        unavailable_predictions += summary.get(
            "unavailable_predictions", 0
        )

        assessment = data.get("risk_assessment", {})
        level = assessment.get("risk_level", "UNAVAILABLE")

        if level not in risk_levels:
            level = "UNAVAILABLE"

        risk_levels[level] += 1

    classified_flows = suspicious_flows + normal_flows

    suspicious_rate = (
        round(suspicious_flows / classified_flows * 100, 2)
        if classified_flows
        else 0.0
    )

    return {
        "total_reports": len(reports),
        "total_packets_processed": total_packets,
        "total_flows_recorded": total_flows,
        "total_suspicious_flows": suspicious_flows,
        "total_normal_flows": normal_flows,
        "unavailable_predictions": unavailable_predictions,
        "suspicious_rate_percent": suspicious_rate,
        "risk_level_counts": risk_levels,
        "latest_report_id": reports[0].id if reports else None,
        "statistics_note": (
            "Statistics summarize saved analyses. Repeated analysis "
            "of the same traffic is counted again. Risk levels are "
            "experimental heuristic indicators, not verified attacks."
        ),
    }

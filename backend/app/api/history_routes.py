from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from backend.app.models.analysis import AnalysisReport
from backend.app.services.database import get_db


router = APIRouter(
    prefix="/api/v1/history",
    tags=["Analysis History"],
)


@router.get("")
def get_history(
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    query = db.query(AnalysisReport)
    reports = (
        query.order_by(AnalysisReport.id.desc())
        .limit(limit)
        .all()
    )
    history = [
        {
            "id": report.id,
            "created_at": report.created_at,
            "total_packets": report.total_packets,
            "total_flows": report.total_flows,
            "suspicious_flows": report.report_data.get(
                "suspicious_flows",
                0,
            ),
        }
        for report in reports
    ]

    return {
        "status": "success",
        "count": len(history),
        "history": history,
    }


@router.get("/{analysis_id}")
def get_history_item(
    analysis_id: int,
    db: Session = Depends(get_db),
):
    report = (
        db.query(AnalysisReport)
        .filter(AnalysisReport.id == analysis_id)
        .first()
    )

    if report is None:
        raise HTTPException(
            status_code=404,
            detail="Analysis history record not found.",
        )

    return {
        "id": report.id,
        "created_at": report.created_at,
        "total_packets": report.total_packets,
        "total_flows": report.total_flows,
        "suspicious_flows": report.report_data.get(
            "suspicious_flows",
            0,
        ),
        "result": report.report_data,
    }

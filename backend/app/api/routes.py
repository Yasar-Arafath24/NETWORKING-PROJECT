from datetime import datetime
from pathlib import Path
import shutil
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile

from backend.app.services.pcap_service import analyze_pcap


router = APIRouter(prefix="/api/v1", tags=["NetSentry"])


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NetSentry AI Backend",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/system/info")
def system_info():
    return {
        "project": "NetSentry AI",
        "backend": "FastAPI",
        "phase": "PCAP Analysis",
        "status": "development",
    }


@router.post("/pcap/analyze")
async def upload_and_analyze_pcap(file: UploadFile = File(...)):
    """
    Upload and analyze a PCAP/PCAPNG file.
    """

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided.",
        )

    extension = Path(file.filename).suffix.lower()

    if extension not in {".pcap", ".pcapng"}:
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are supported.",
        )

    upload_directory = Path("datasets") / "raw"
    upload_directory.mkdir(parents=True, exist_ok=True)

    safe_filename = f"{uuid.uuid4().hex}{extension}"
    file_path = upload_directory / safe_filename

    try:
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        analysis = analyze_pcap(file_path)

        return {
            "status": "success",
            "filename": file.filename,
            "stored_as": safe_filename,
            "analysis": analysis,
        }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {str(exc)}",
        )

    finally:
        await file.close()
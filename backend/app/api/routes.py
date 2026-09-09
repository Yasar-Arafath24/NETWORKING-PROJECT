from pathlib import Path
import shutil
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile

from network.flow_engine import analyze_pcap


router = APIRouter(prefix="/api/v1", tags=["NetSentry"])


BASE_DIR = Path(__file__).resolve().parents[3]
UPLOAD_DIR = BASE_DIR / "datasets" / "raw"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


@router.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "NetSentry AI",
        "version": "0.1.0",
    }


@router.get("/system/info")
def system_info():
    return {
        "name": "NetSentry AI",
        "version": "0.1.0",
        "description": "Privacy-Preserving Intelligent Network Traffic Classification & Adaptive Threat Defense",
        "components": [
            "FastAPI",
            "Scapy",
            "Flow Engine",
            "ML Traffic Classifier",
        ],
    }


@router.post("/pcap/analyze")
async def upload_and_analyze_pcap(file: UploadFile = File(...)):
    """
    Upload and analyze a PCAP/PCAPNG file.
    """

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="No filename provided",
        )

    extension = Path(file.filename).suffix.lower()

    if extension not in [".pcap", ".pcapng"]:
        raise HTTPException(
            status_code=400,
            detail="Only .pcap and .pcapng files are supported",
        )

    stored_name = f"{uuid.uuid4().hex}{extension}"
    output_file = UPLOAD_DIR / stored_name

    try:
        with output_file.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        result = analyze_pcap(str(output_file))

        # analyze_pcap() returns a list of flow dictionaries
        flows = result if isinstance(result, list) else []

        protocol_counts = {}

        for flow in flows:
            if not isinstance(flow, dict):
                continue

            protocol = flow.get("protocol", "OTHER")

            if protocol not in ["TCP", "UDP", "ICMP"]:
                protocol = "OTHER"

            protocol_counts[protocol] = (
                protocol_counts.get(protocol, 0) + 1
            )

        return {
            "status": "success",
            "filename": file.filename,
            "stored_as": stored_name,
            "analysis": {
                "total_flows": len(flows),
                "protocol_counts": protocol_counts,
                "flows": flows,
            },
        }

    except Exception as exc:
        if output_file.exists():
            output_file.unlink()

        raise HTTPException(
            status_code=500,
            detail=f"PCAP analysis failed: {str(exc)}",
        )

    finally:
        await file.close()
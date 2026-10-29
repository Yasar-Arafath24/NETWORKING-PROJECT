import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.app.main import app
from backend.app.models.analysis import AnalysisReport
from backend.app.services.database import Base, get_db
from tests.auth_helpers import authenticate_test_client


@pytest.fixture
def history_client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )

    def override_get_db():
        with session_factory() as db:
            yield db

    app.dependency_overrides[get_db] = override_get_db

    try:
        with TestClient(app) as client:
            user_id = authenticate_test_client(client)
            yield client, session_factory, user_id
    finally:
        app.dependency_overrides.pop(get_db, None)
        engine.dispose()


def test_history_lists_existing_analysis_reports(history_client):
    client, session_factory, user_id = history_client
    with session_factory() as db:
        db.add_all(
            [
                AnalysisReport(
                    owner_id=user_id,
                    total_packets=10,
                    total_flows=2,
                    report_data={
                        "suspicious_flows": 1,
                        "flows": [{"anomaly": True}],
                    },
                ),
                AnalysisReport(
                    owner_id=user_id,
                    total_packets=20,
                    total_flows=3,
                    report_data={
                        "suspicious_flows": 0,
                        "flows": [{"anomaly": False}],
                    },
                ),
            ]
        )
        db.commit()

    response = client.get("/api/v1/history?limit=1")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert data["count"] == 1
    assert len(data["history"]) == 1
    assert data["history"][0]["total_packets"] == 20


def test_history_returns_analysis_details_and_404(history_client):
    client, session_factory, user_id = history_client
    with session_factory() as db:
        report = AnalysisReport(
            owner_id=user_id,
            total_packets=10,
            total_flows=1,
            report_data={
                "suspicious_flows": 1,
                "flows": [{"anomaly": True, "label": "SUSPICIOUS"}],
            },
        )
        db.add(report)
        db.commit()
        report_id = report.id

    response = client.get(f"/api/v1/history/{report_id}")

    assert response.status_code == 200
    data = response.json()
    assert data["id"] == report_id
    assert data["suspicious_flows"] == 1
    assert data["result"]["flows"][0]["anomaly"] is True

    missing = client.get("/api/v1/history/99999")
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Analysis history record not found."


def test_history_rejects_invalid_limit(history_client):
    client, _, _ = history_client

    response = client.get("/api/v1/history?limit=201")

    assert response.status_code == 422

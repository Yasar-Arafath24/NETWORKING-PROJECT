
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.services.database import Base


class AnalysisReport(Base):
    __tablename__ = "analysis_reports"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    total_packets: Mapped[int] = mapped_column(
        Integer, default=0
    )
    total_flows: Mapped[int] = mapped_column(
        Integer, default=0
    )
    report_data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
    )

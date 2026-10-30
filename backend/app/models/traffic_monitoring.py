from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Float, Integer, JSON, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.services.database import Base


class AnalysisHistory(Base):
    __tablename__ = "analysis_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    report_id: Mapped[int | None] = mapped_column(ForeignKey("analysis_reports.id", ondelete="CASCADE"), unique=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    total_packets: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_flows: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    suspicious_flows: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    analysis_status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class TrafficFlowRecord(Base):
    __tablename__ = "traffic_flow_records"
    __table_args__ = (
        UniqueConstraint("report_id", "flow_index", name="uq_traffic_report_flow"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    report_id: Mapped[int] = mapped_column(ForeignKey("analysis_reports.id", ondelete="CASCADE"), nullable=False)
    flow_index: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    src_ip: Mapped[str | None] = mapped_column(String(45))
    dst_ip: Mapped[str | None] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str | None] = mapped_column(String(16))
    packet_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    anomaly: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    label: Mapped[str] = mapped_column(String(32), default="UNASSESSED", nullable=False)
    anomaly_score: Mapped[float | None] = mapped_column(Float)
    flow_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

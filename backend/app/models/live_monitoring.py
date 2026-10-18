from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    Integer,
    JSON,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.services.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class LiveFlowRecord(Base):
    """Latest persisted snapshot of a flow from one monitoring session."""

    __tablename__ = "live_flow_records"

    __table_args__ = (
        UniqueConstraint(
            "session_id",
            "flow_id",
            name="uq_live_flow_session_flow",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    flow_id: Mapped[int] = mapped_column(Integer, index=True)

    src_ip: Mapped[str] = mapped_column(String(45))
    dst_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int] = mapped_column(Integer)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(16))

    packet_count: Mapped[int] = mapped_column(Integer, default=0)
    total_bytes: Mapped[int] = mapped_column(Integer, default=0)
    duration: Mapped[float] = mapped_column(Float, default=0.0)

    anomaly: Mapped[bool] = mapped_column(Boolean, default=False)
    label: Mapped[str] = mapped_column(String(32), default="UNASSESSED")
    anomaly_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    features: Mapped[dict] = mapped_column(JSON)
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
    )
    last_updated: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
    )


class NetworkAlert(Base):
    """Persisted anomaly alert associated with a live flow."""

    __tablename__ = "network_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    session_id: Mapped[str] = mapped_column(String(100), index=True)
    flow_id: Mapped[int] = mapped_column(Integer, index=True)

    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(1000))

    anomaly_score: Mapped[float] = mapped_column(Float)
    flow_data: Mapped[dict] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        index=True,
    )
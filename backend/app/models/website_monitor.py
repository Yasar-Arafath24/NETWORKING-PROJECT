from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.services.database import Base


def utc_now():
    return datetime.now(timezone.utc)


class MonitoredWebsite(Base):
    __tablename__ = "monitored_websites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    platform: Mapped[str] = mapped_column(String(20), default="custom", nullable=False)
    integration_method: Mapped[str] = mapped_column(String(32), default="generic_jsonl", nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    collector_revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collector_status: Mapped[str] = mapped_column(String(16), default="UNKNOWN", nullable=False)
    collector_last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    collector_last_error: Mapped[str] = mapped_column(String(1000), default="", nullable=False)
    collector_last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class WebsiteTrafficEvent(Base):
    __tablename__ = "website_traffic_events"
    __table_args__ = (
        Index("ix_website_events_site_created", "site_id", "created_at"),
        Index("uq_website_events_site_event_id", "site_id", "event_id", unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("monitored_websites.id", ondelete="CASCADE"), index=True, nullable=False)
    event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    request_path: Mapped[str] = mapped_column(String(512), nullable=False)
    method: Mapped[str] = mapped_column(String(12), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_ms: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    response_bytes: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    user_agent: Mapped[str] = mapped_column(String(256), default="", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), default="INFO", nullable=False)
    reason: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    event_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    request_timestamp: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True)


class WebsiteSecurityAlert(Base):
    """Grouped website-traffic detection incident, scoped through its website owner."""
    __tablename__ = "website_security_alerts"
    __table_args__ = (
        Index("ix_website_alert_site_status_last_seen", "site_id", "status", "last_seen"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("monitored_websites.id", ondelete="CASCADE"), index=True, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(180), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source_ip: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    endpoint: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    explanation: Mapped[str] = mapped_column(String(2000), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="OPEN", nullable=False)
    related_event_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)


class WebsiteAlertStatusChange(Base):
    __tablename__ = "website_alert_status_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("website_security_alerts.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    previous_status: Mapped[str] = mapped_column(String(20), nullable=False)
    new_status: Mapped[str] = mapped_column(String(20), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

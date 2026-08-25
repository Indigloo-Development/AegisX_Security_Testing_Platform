from datetime import datetime, timezone
from enum import Enum
from sqlalchemy import String, Text, DateTime, Integer, JSON, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column
from app.db.session import Base

class FindingLifecycleStatus(str, Enum):
    open = "open"
    fixed = "fixed"
    reopened = "reopened"
    accepted_risk = "accepted_risk"
    false_positive = "false_positive"

class FindingLifecycle(Base):
    __tablename__ = "finding_lifecycles"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(100), index=True)
    status: Mapped[FindingLifecycleStatus] = mapped_column(SAEnum(FindingLifecycleStatus), default=FindingLifecycleStatus.open, index=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), index=True)
    last_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    owner_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(default=0.0)
    status_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), onupdate=lambda: datetime.now(timezone.utc).replace(tzinfo=None), index=True)

class EvidenceSnapshot(Base):
    __tablename__ = "evidence_snapshots"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(100), index=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), index=True)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    fingerprint: Mapped[str] = mapped_column(String(128), index=True)
    source_scan_id: Mapped[int | None] = mapped_column(ForeignKey("scans.id"), nullable=True)

class RetestRecord(Base):
    __tablename__ = "retest_records"
    id: Mapped[int] = mapped_column(primary_key=True)
    finding_key: Mapped[str] = mapped_column(String(100), index=True)
    previous_status: Mapped[str] = mapped_column(String(40))
    result: Mapped[str] = mapped_column(String(40), index=True)
    compared_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc).replace(tzinfo=None), index=True)
    previous_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    current_fingerprint: Mapped[str | None] = mapped_column(String(128), nullable=True)
    diff: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

class RiskTrendPoint(Base):
    __tablename__ = "risk_trend_points"
    id: Mapped[int] = mapped_column(primary_key=True)
    period: Mapped[str] = mapped_column(String(40), index=True)
    total_findings: Mapped[int] = mapped_column(default=0)
    critical: Mapped[int] = mapped_column(default=0)
    high: Mapped[int] = mapped_column(default=0)
    medium: Mapped[int] = mapped_column(default=0)
    low: Mapped[int] = mapped_column(default=0)
    info: Mapped[int] = mapped_column(default=0)
    risk_score: Mapped[float] = mapped_column(default=0.0)

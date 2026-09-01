from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_number: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="open", nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="medium", nullable=False)
    threat_type: Mapped[str] = mapped_column(String(64), default="phishing", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    email_artifacts: Mapped[list[EmailArtifact]] = relationship(
        "EmailArtifact", back_populates="case", cascade="all, delete-orphan"
    )
    investigation_results: Mapped[list[InvestigationResult]] = relationship(
        "InvestigationResult", back_populates="case", cascade="all, delete-orphan"
    )
    analyst_notes: Mapped[list[AnalystNote]] = relationship(
        "AnalystNote", back_populates="case", cascade="all, delete-orphan"
    )
    timeline_events: Mapped[list[TimelineEvent]] = relationship(
        "TimelineEvent", back_populates="case", cascade="all, delete-orphan"
    )


class EmailArtifact(Base):
    __tablename__ = "email_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    subject: Mapped[str] = mapped_column(String(512), default="", nullable=False)
    sender: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    recipient: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    raw_content: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    case: Mapped[Case] = relationship("Case", back_populates="email_artifacts")


class InvestigationResult(Base):
    __tablename__ = "investigation_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(32), default="safe", nullable=False)
    verdict: Mapped[str] = mapped_column(String(64), default="benign", nullable=False)
    ai_analysis: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    case: Mapped[Case] = relationship("Case", back_populates="investigation_results")


class AnalystNote(Base):
    __tablename__ = "analyst_notes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    note: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    case: Mapped[Case] = relationship("Case", back_populates="analyst_notes")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    event_metadata: Mapped[str] = mapped_column(Text, default="{}", nullable=False)

    case: Mapped[Case] = relationship("Case", back_populates="timeline_events")

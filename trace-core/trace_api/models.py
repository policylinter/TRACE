"""SQLAlchemy models.

The domain model is deliberately small: a ``Scan`` owns many ``Finding`` rows,
and every finding carries its call-graph frames and AI evidence as JSON. That
keeps the schema portable between SQLite and Postgres while still allowing the
API to reconstruct the full triage drawer payload in one query.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import JSON

from .database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Project(Base):
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    """A workspace: one analysed repository. Scans are isolated per project so
    findings and triage state from different repos never mix."""

    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    repo_url: Mapped[str] = mapped_column(String(512), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", lazy="selectin"
    )


class Scan(Base):
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True, nullable=True
    )
    repository: Mapped[str] = mapped_column(String(255), nullable=False)
    branch: Mapped[str] = mapped_column(String(128), default="main")
    commit_short: Mapped[str] = mapped_column(String(40), default="")
    commit_long: Mapped[str] = mapped_column(String(64), default="")
    pipeline: Mapped[str] = mapped_column(String(128), default="trace-scan/local")
    triggered_by: Mapped[str] = mapped_column(String(128), default="manual")
    sbom: Mapped[str] = mapped_column(String(255), default="CycloneDX 1.6")
    duration: Mapped[str] = mapped_column(String(32), default="0s")
    status: Mapped[str] = mapped_column(String(24), default="completed")

    scanner_results: Mapped[list] = mapped_column(JSON, default=list)
    raw_count: Mapped[int] = mapped_column(Integer, default=0)
    engines: Mapped[list] = mapped_column(JSON, default=list)
    ai_runtime: Mapped[dict] = mapped_column(JSON, default=dict)
    ai_engine: Mapped[str] = mapped_column(String(64), default="rules")
    profile: Mapped[str] = mapped_column(String(64), default="prod-eu-1")
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    project: Mapped["Project | None"] = relationship(back_populates="scans")


class Finding(Base):
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    cve: Mapped[str] = mapped_column(String(32), index=True)
    package_name: Mapped[str] = mapped_column(String(255), index=True)
    version: Mapped[str] = mapped_column(String(64), default="")
    ecosystem: Mapped[str] = mapped_column(String(32), default="maven")
    raw_count: Mapped[int] = mapped_column(Integer, default=1)

    severity: Mapped[str] = mapped_column(String(16), index=True)
    cvss: Mapped[float] = mapped_column(Float, default=0.0)
    reachability: Mapped[str] = mapped_column(String(16), index=True)
    verdict: Mapped[str] = mapped_column(String(16), index=True)
    usage: Mapped[str] = mapped_column(String(16), default="unknown", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    cwe: Mapped[list] = mapped_column(JSON, default=list)
    fixed_in: Mapped[str] = mapped_column(String(64), default="")

    dependency_path: Mapped[list] = mapped_column(JSON, default=list)
    frames: Mapped[list] = mapped_column(JSON, default=list)
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    blocker: Mapped[str | None] = mapped_column(Text, nullable=True)
    suppress_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    assignee: Mapped[str] = mapped_column(String(128), default="")
    workflow_status: Mapped[str] = mapped_column(String(24), default="new")
    due_date: Mapped[str] = mapped_column(String(10), default="")
    triage_note: Mapped[str] = mapped_column(Text, default="")
    reviewed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")


class AppSetting(Base):
    """Key/value application settings, persisted so runtime changes (e.g. the
    chosen AI engine) survive restarts. Env vars remain the seed defaults."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class TriageEvent(Base):
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    """Append-only audit log of human triage actions (review / suppress)."""

    __tablename__ = "triage_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=True
    )
    finding_id: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(128), default="analyst")
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class User(Base):
    """Optional RBAC v1 accounts. Enabled only when TRACE_AUTH_ENABLED=1."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(128), default="")
    password_hash: Mapped[str] = mapped_column(String(255), default="")
    role: Mapped[str] = mapped_column(String(16), default="user")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

"""Durable dispatch records; only trusted workers may read private parameters."""
from sqlalchemy import String, Float, Integer, ForeignKey, ForeignKeyConstraint, UniqueConstraint, Index, CheckConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON
from .database import Base


class Job(Base):
    __tablename__ = "scan_jobs"
    __table_args__ = (
        Index("ix_scan_jobs_scope_created", "organization_id", "workspace_id", "created_at"),
        ForeignKeyConstraint(['organization_id', 'workspace_id'], ['workspaces.organization_id', 'workspaces.id']),
        CheckConstraint("status IN ('queued', 'running', 'completed', 'failed')"),
    )
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default")
    workspace_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="queued")
    mode: Mapped[str] = mapped_column(String(24))
    created_at: Mapped[float] = mapped_column(Float)
    started_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    finished_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    params: Mapped[dict] = mapped_column(JSON)
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class JobAttempt(Base):
    __tablename__ = "scan_job_attempts"
    __table_args__ = (UniqueConstraint("job_id"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), index=True)
    started_at: Mapped[float] = mapped_column(Float)
    finished_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(24))


class JobOutbox(Base):
    __tablename__ = "scan_job_outbox"
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    delivered_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    deliveries: Mapped[int] = mapped_column(Integer, default=0)
    next_delivery_at: Mapped[float] = mapped_column(Float, default=0, server_default='0')


class QueueControl(Base):
    __tablename__ = "scan_queue_control"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    max_running: Mapped[int] = mapped_column(Integer, default=2)
    max_queued: Mapped[int] = mapped_column(Integer, default=100)


class JobHeartbeat(Base):
    __tablename__ = "scan_job_heartbeats"
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("scan_job_attempts.id"), unique=True)
    heartbeat_at: Mapped[float] = mapped_column(Float)
    expires_at: Mapped[float] = mapped_column(Float)


class JobReceipt(Base):
    """Written alongside the final scan commit, never inferred from partial data."""
    __tablename__ = "scan_job_receipts"
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    attempt_id: Mapped[str] = mapped_column(ForeignKey("scan_job_attempts.id"), unique=True)
    scan_id: Mapped[str] = mapped_column(String(64))
    scan_status: Mapped[str] = mapped_column(String(24))
    scanners: Mapped[list] = mapped_column(JSON)
    saved_at: Mapped[float] = mapped_column(Float)


class RescanJob(Base):
    __tablename__ = "scan_rescan_jobs"
    job_id: Mapped[str] = mapped_column(ForeignKey("scan_jobs.id"), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(64), index=True)
    progress: Mapped[dict] = mapped_column(JSON, default=dict)

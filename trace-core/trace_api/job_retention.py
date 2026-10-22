"""Reviewable, bounded retention of terminal job metadata, never scan results."""
import hashlib
import json
import time
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, delete, func, or_
from .job_models import Job, JobAttempt, JobOutbox, JobHeartbeat, JobReceipt, RescanJob

CHILDREN = (JobReceipt, JobHeartbeat, RescanJob, JobOutbox, JobAttempt)


class Candidate(BaseModel):
    model_config = ConfigDict(extra='forbid')
    jobId: str = Field(min_length=1, max_length=64)
    status: Literal['completed', 'failed']
    finishedAt: float = Field(gt=0, allow_inf_nan=False)
    terminalReason: Literal['cancelled'] | None = None


class Plan(BaseModel):
    model_config = ConfigDict(extra='forbid')
    version: Literal[1] = 1
    organizationId: Literal['default'] = 'default'
    workspaceId: str = Field(min_length=1, max_length=64)
    days: int = Field(ge=1, le=3650)
    limit: int = Field(ge=1, le=500)
    createdAt: float = Field(gt=0, allow_inf_nan=False)
    expiresAt: float = Field(gt=0, allow_inf_nan=False)
    cutoff: float = Field(gt=0, allow_inf_nan=False)
    candidates: list[Candidate] = Field(max_length=500)
    counts: dict[str, int]


def counts(db, ids):
    result = {'scan_jobs':len(ids)}
    for model in CHILDREN:
        result[model.__tablename__] = db.scalar(select(func.count()).select_from(model).where(model.job_id.in_(ids))) if ids else 0
    return result


def eligible(workspace_id, cutoff):
    active_attempt = select(JobAttempt.id).where(JobAttempt.job_id == Job.id,
        or_(JobAttempt.status == 'running', JobAttempt.finished_at.is_(None))).exists()
    return select(Job).where(Job.organization_id == 'default', Job.workspace_id == workspace_id,
        Job.status.in_(('completed', 'failed')), Job.finished_at < cutoff, ~active_attempt)


def preview(factory, workspace_id='default', days=90, limit=100):
    if not 1 <= days <= 3650 or not 1 <= limit <= 500: raise ValueError('Invalid retention bounds')
    now = time.time()
    cutoff = now-days*86400
    from .workspace_models import Workspace
    with factory() as db:
        workspace = db.get(Workspace, workspace_id)
        if workspace is None or workspace.organization_id != 'default': raise ValueError('Workspace not found')
        jobs = db.scalars(eligible(workspace_id, cutoff).order_by(Job.finished_at, Job.id).limit(limit)).all()
        return Plan(workspaceId=workspace_id, days=days, limit=limit, createdAt=now,
            expiresAt=now+3600, cutoff=cutoff,
            candidates=[Candidate(jobId=j.id, status=j.status, finishedAt=j.finished_at,
                terminalReason='cancelled' if (j.result or {}).get('terminalReason') == 'cancelled' else None) for j in jobs],
            counts=counts(db, [j.id for j in jobs]))


def apply_plan(factory, value, workspace_id='default'):
    plan = Plan.model_validate(value)
    now = time.time()
    if (plan.workspaceId != workspace_id or plan.createdAt > now+5 or now > plan.expiresAt
            or abs(plan.expiresAt-plan.createdAt-3600) > .01
            or abs(plan.cutoff-(plan.createdAt-plan.days*86400)) > .01
            or len(plan.candidates) > plan.limit): raise ValueError('Plan scope or validity mismatch; generate a fresh preview')
    ids = [c.jobId for c in plan.candidates]
    if len(set(ids)) != len(ids): raise ValueError('Duplicate plan IDs')
    if any(c.finishedAt >= plan.cutoff for c in plan.candidates): raise ValueError('Plan includes recent jobs')
    digest = hashlib.sha256(json.dumps(plan.model_dump(), sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    from .job_dispatcher import locked_control
    from .platform import PlatformAudit, audit
    with factory() as db:
        db.info.update(organization_id='default', workspace_id=workspace_id, actor='system:job-retention')
        locked_control(db)
        previous = db.scalar(select(PlatformAudit.id).where(PlatformAudit.action == 'jobs.retained', PlatformAudit.object_id == digest))
        if previous: return {'status':'already-applied', 'deleted':0, 'planId':digest}
        jobs = db.scalars(eligible(workspace_id, plan.cutoff).where(Job.id.in_(ids))).all() if ids else []
        actual = {j.id:(j.status, j.finished_at, 'cancelled' if (j.result or {}).get('terminalReason') == 'cancelled' else None) for j in jobs}
        expected = {c.jobId:(c.status, c.finishedAt, c.terminalReason) for c in plan.candidates}
        if actual != expected or counts(db, ids) != plan.counts:
            raise ValueError('Job metadata changed since preview; nothing deleted')
        if not ids: return {'status':'nothing-to-delete', 'deleted':0, 'planId':digest}
        # FK-safe order. No Scan/Finding/Project/PlatformAudit deletion occurs.
        for model in CHILDREN: db.execute(delete(model).where(model.job_id.in_(ids)))
        removed = db.execute(delete(Job).where(Job.id.in_(ids), Job.organization_id == 'default',
            Job.workspace_id == workspace_id, Job.status.in_(('completed', 'failed')), Job.finished_at < plan.cutoff)).rowcount
        if removed != len(ids): raise ValueError('Concurrent state change; transaction rolled back')
        audit(db, 'jobs.retained', digest, json.dumps({'days':plan.days, 'cutoff':plan.cutoff,
            'jobIds':ids, 'deleted':plan.counts}, ensure_ascii=False))
        db.commit()
        return {'status':'applied', 'deleted':removed, 'planId':digest}

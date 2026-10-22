"""Scan job dispatch.

Scans are dispatched to the heavy agent when a queue is available, and run in a
background thread otherwise — so the API never blocks and the same workflow
works whether you deployed one box or a web + agent split. Job state is kept in
the database for both execution paths; broker results are not authoritative.
"""

from __future__ import annotations

from typing import Any

from .config import REDIS_URL
from .database import SessionLocal

def _redis_available() -> bool:
    try:
        import redis  # type: ignore

        client = redis.Redis.from_url(REDIS_URL, socket_connect_timeout=1.0, socket_timeout=1.0)
        return bool(client.ping())
    except Exception:
        return False


def _celery_available() -> bool:
    try:
        import celery  # type: ignore  # noqa: F401

        return True
    except Exception:
        return False


def queue_mode() -> str:
    if _redis_available() and _celery_available():
        return "celery"
    return "in-process"


def authorize_execution(db, actor, user_id=None, require_admin=False):
    """Recheck current membership and grants before accessing scan sources."""
    from sqlalchemy import select
    from . import config
    from .access import Principal
    from .access_models import Membership
    from .models import User
    from .workspaces import workspace_role
    if actor.startswith("user:"):
        user = db.get(User, user_id) if user_id is not None else None
        if user is None or not user.is_active or actor != "user:" + user.username:
            raise PermissionError("job author identity is no longer valid")
        member = db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.organization_id == "default", Membership.is_active.is_(True))) if user else None
        if member is None:
            raise PermissionError("job author is no longer an active member")
        principal = Principal(actor, member.role, "user", user_id=user.id)
        role = workspace_role(db, principal, db.info["workspace_id"])
        if role not in (("admin",) if require_admin else ("analyst", "admin")):
            raise PermissionError("job author no longer has scan permission")
        return
    allowed = "static-admin" if config.ADMIN_TOKEN else "local-operator"
    if config.AUTH_ENABLED or actor != allowed:
        raise PermissionError("job has no authorized execution identity")


def _prepare_execution(db, params):
    """Restore trusted dispatch context before any source access or scanner run."""
    execution_params = dict(params)
    db.info["actor"] = execution_params.pop("_actor", "system:worker")
    db.info["workspace_id"] = execution_params.pop("_workspace_id", "default")
    kind = execution_params.pop('_kind', 'source')
    if kind not in ('source', 'rescan', 'sast'): raise ValueError('unknown job kind')
    db.info['job_kind'] = kind
    authorize_execution(db, db.info["actor"], execution_params.pop("_user_id", None), require_admin=kind in ('source','sast'))
    from .workspace_models import Workspace
    workspace = db.get(Workspace, db.info["workspace_id"])
    if workspace is None or workspace.organization_id != "default":
        raise ValueError("invalid job workspace")
    if execution_params.get("project_id") is not None:
        from .models import Project
        if db.get(Project, execution_params["project_id"]) is None:
            raise ValueError("project is outside the job workspace")
    return execution_params


def submit_scan(**params: Any) -> dict[str, Any]:
    from .job_store import submit
    return submit(SessionLocal, queue_mode(), params)


def submit_rescan(scan_id, *, actor, workspace_id, user_id=None):
    from .job_store import submit
    return submit(SessionLocal, queue_mode(), {'_kind':'rescan', 'scan_id':scan_id,
        '_actor':actor, '_workspace_id':workspace_id, '_user_id':user_id})


def job_status(job_id: str, workspace_id: str = "default"):
    from .job_store import status
    return status(SessionLocal, job_id, workspace_id)


def list_jobs(limit: int = 20, workspace_id: str = "default"):
    from .job_store import listing
    return listing(SessionLocal, limit, workspace_id)


def run_scan_job(job_id: str, params=None):
    # Ignore legacy broker parameters: only committed DB state is authoritative.
    from .job_store import execute
    return execute(SessionLocal, job_id)


def _execute(job_id: str, params=None):
    return run_scan_job(job_id)


def _run_pipeline(job_id: str, params: dict[str, Any], factory=None, attempt_id=None) -> dict[str, Any]:
    """Run the authorized pipeline without exposing private source/error details."""
    from .services import scan_source

    db = (factory or SessionLocal)()
    try:
        if attempt_id is not None:
            db.info.update(job_id=job_id, job_attempt_id=attempt_id)
        execution_params = _prepare_execution(db, params)
        if db.info['job_kind']=='sast':
            from .sast_jobs import run
            return run(db,execution_params,job_id,attempt_id,user_id=params.get('_user_id'))
        if db.info['job_kind'] == 'rescan':
            from .models import Scan
            from .services import rescan
            from .rescan_jobs import report
            scan = db.get(Scan, execution_params['scan_id'])
            if scan is None: raise ValueError('scan is outside the job workspace')
            scan = rescan(db, scan, on_phase=lambda phase, fraction, message: report(factory or SessionLocal, job_id, phase, fraction, message))
            return {'jobId':job_id, 'status':'completed', 'scanId':scan.id, 'scanStatus':scan.status, 'scanners':[], 'sourceMeta':{}}
        scan, meta, used = scan_source(db, **execution_params)
        return {"jobId": job_id, "status": "completed", "scanId": scan.id, "scanStatus": scan.status, "scanners": used, "sourceMeta": {}}
    except Exception as exc:
        return {"jobId": job_id, "status": "failed", "error": "Execution denied" if isinstance(exc, PermissionError) else "Scan execution failed", "errorType": type(exc).__name__}
    finally:
        db.close()

def submit_sast(*,target_id,commit,config_sha,rules_sha,actor,workspace_id,user_id=None):
    from .job_store import submit
    return submit(SessionLocal,queue_mode(),dict(_kind='sast',target_id=target_id,commit=commit,config_sha=config_sha,rules_sha=rules_sha,_actor=actor,_workspace_id=workspace_id,_user_id=user_id))

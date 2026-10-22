"""TRACE HTTP API.

FastAPI application exposing scans, findings, funnel metrics, reachability,
SBOM and VEX. All analysis runs locally; the only optional network dependency
is the local Ollama socket.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from . import __version__
from .config import ADMIN_TOKEN, AUTH_ENABLED, CORS_ORIGINS, FRONTEND_DIST, OLLAMA_MODEL
from .database import SessionLocal, get_db, init_db
from .integrations import registry
from .models import Finding, Project, Scan, TriageEvent, User
from .pipeline import ai, ingest as ingest_mod
from .pipeline.vex import build_vex, document_id, file_name
from .pipeline.seed import (
    DEFAULT_PROJECT_ID,
    DEMO_SCAN_ID,
    ensure_default_project,
    ensure_demo_scan,
)
from .serializers import (
    serialize_event,
    serialize_finding,
    serialize_project,
    serialize_scan,
)
from .settings import (
    get_ai_settings,
    normalize_ai_patch,
    get_policy_settings,
    public_ai_settings,
    set_ai_settings,
    set_policy_settings,
)
from .policies import evaluate_policy
from . import compliance, jobs, rbac
from .services import rescan, run_scan, scan_source
from . import access, workspaces


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    db = next(get_db())
    try:
        ensure_default_project(db)
        ensure_demo_scan(db)
        rbac.ensure_bootstrap(db)
        access.ensure_default_identity(db)
        workspaces.ensure_legacy_workspace_grants(db)
    finally:
        db.close()
    from .job_dispatcher import Dispatcher
    with Dispatcher(SessionLocal):
        yield


app = FastAPI(title="TRACE Security API", version=__version__, lifespan=lifespan)
app.middleware("http")(access.access_middleware)
app.include_router(access.router)
from .http_baseline import router as http_baseline_router
app.include_router(http_baseline_router)
app.include_router(workspaces.router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _resolve_project(
    db: Session,
    *,
    project_id: int | str | None = None,
    name: str | None = None,
    repo_url: str | None = None,
) -> Project:
    """Find (or create) the workspace a scan belongs to.

    Resolution order: explicit id, then repo URL (so a GitLab webhook for an
    already-known repo reuses its project), otherwise a new project is created.
    """
    project: Project | None = None
    if project_id not in (None, ""):
        try:
            project = db.get(Project, int(project_id))
        except (TypeError, ValueError):
            raise HTTPException(422, "invalid project id")
        if project is None:
            raise HTTPException(404, "project not found")
    if project is None and repo_url:
        project = db.execute(select(Project).where(Project.repo_url == repo_url)).scalars().first()
    if project is None:
        project = Project(name=name or repo_url or "Unnamed project", repo_url=repo_url or "")
        db.add(project)
        db.commit()
        db.refresh(project)
    return project


def _default_scan(db: Session, project_id: int | None = None) -> Scan:
    query = select(Scan).order_by(Scan.scanned_at.desc())
    if project_id is not None:
        query = query.where(Scan.project_id == project_id)
    scan = db.execute(query.limit(1)).scalars().first()
    if scan is None:
        raise HTTPException(status_code=404, detail="no scans in the requested project")
    return scan


def _get_scan(db: Session, scan_id: str | None, project_id: int | None = None) -> Scan:
    if scan_id == "active" or scan_id is None or scan_id == "":
        return _default_scan(db, project_id)
    scan = db.get(Scan, scan_id) if scan_id else _default_scan(db, project_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if project_id is not None and scan.project_id != project_id:
        raise HTTPException(status_code=404, detail="scan not found in project")
    return scan


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _sort_findings(items: list[Finding], sort: str) -> list[Finding]:
    if sort == "confidence":
        return sorted(items, key=lambda f: f.confidence, reverse=True)
    if sort == "raw":
        return sorted(items, key=lambda f: f.raw_count, reverse=True)
    if sort == "cve":
        return sorted(items, key=lambda f: f.cve)
    return sorted(items, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.cvss))


def _filter_findings(items: list[Finding], flt: str) -> list[Finding]:
    if flt == "actionable":
        return [f for f in items if f.reachability == "reachable" and f.verdict == "affected"]
    if flt == "reachable":
        return [f for f in items if f.reachability == "reachable"]
    if flt == "unreachable":
        return [f for f in items if f.reachability == "unreachable"]
    if flt == "suppressed":
        return [f for f in items if f.reachability == "suppressed"]
    return items


# --------------------------------------------------------------------------- #
def _matches(finding: Finding, query: str) -> bool:
    q = query.strip().lower()
    if not q:
        return True
    haystack = " ".join(
        [
            finding.cve,
            finding.id,
            finding.package_name,
            finding.version,
            finding.ecosystem,
            finding.verdict,
            finding.reachability,
            finding.evidence.get("headline", "") if finding.evidence else "",
            *(finding.cwe or []),
            *[fr.get("symbol", "") for fr in (finding.frames or [])],
        ]
    ).lower()
    return q in haystack


# --------------------------------------------------------------------------- #
# Meta
# --------------------------------------------------------------------------- #
@app.get("/api/v1/health")
def health(db: Session = Depends(get_db)) -> dict[str, Any]:
    settings = get_ai_settings(db)
    cfg = ai.config_from(settings)
    return {
        "status": "ok",
        "version": __version__,
        "model": (cfg["models"] or [OLLAMA_MODEL])[0],
        "modelAvailable": ai.model_available(settings),
        "aiActive": ai.active_engine(settings),
        "scanCount": db.query(Scan).count(),
        "projectCount": db.query(Project).count(),
    }


@app.get("/api/v1/events")
async def list_events(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    events = (
        db.execute(select(TriageEvent).order_by(TriageEvent.created_at.desc()).limit(limit))
        .scalars()
        .all()
    )
    out: list[dict[str, Any]] = []
    for event in events:
        out.append(serialize_event(event, db.get(Finding, event.finding_id)))
    return out


# --------------------------------------------------------------------------- #
# Projects (workspaces)
# --------------------------------------------------------------------------- #
@app.get("/api/v1/projects")
async def list_projects(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    projects = db.execute(select(Project).order_by(Project.updated_at.desc())).scalars().all()
    return [serialize_project(p) for p in projects]


@app.post("/api/v1/projects", status_code=201)
def create_project(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Register a repository as a workspace (manual input or GitLab webhook).

    ``{"name": "acme/api", "repoUrl": "git@gitlab.com:acme/api.git", "id": 3}``.
    Idempotent on ``repoUrl`` so repeated webhooks reuse the same project.
    """
    project = _resolve_project(
        db,
        project_id=payload.get("id") or payload.get("projectId"),
        name=payload.get("name") or payload.get("project"),
        repo_url=payload.get("repoUrl") or payload.get("repo_url"),
    )
    return serialize_project(project)


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
@app.get("/api/v1/scans")
async def list_scans(
    project_id: int | None = Query(None), db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    query = select(Scan).order_by(Scan.scanned_at.desc())
    if project_id is not None:
        query = query.where(Scan.project_id == project_id)
    scans = db.execute(query).scalars().all()
    return [serialize_scan(s) for s in scans]


@app.get("/api/v1/scans/{scan_id}")
async def get_scan(scan_id: str, project_id: int | None = Query(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    return serialize_scan(_get_scan(db, scan_id, project_id))


@app.delete("/api/v1/scans/{scan_id}")
def delete_scan(scan_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.id == DEMO_SCAN_ID:
        raise HTTPException(status_code=409, detail="demo scan cannot be deleted")
    findings_count = len(scan.findings)
    events_count = db.query(TriageEvent).filter(TriageEvent.scan_id == scan.id).count()
    db.execute(delete(TriageEvent).where(TriageEvent.scan_id == scan.id))
    db.delete(scan)
    db.commit()
    return {"deleted": scan.id, "findings": findings_count, "events": events_count}


@app.delete("/api/v1/projects/{project_id}")
def delete_project(project_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Remove a workspace and everything under it.

    The default workspace (id=1) is protected: it owns the demo scan, so deleting
    it would leave a fresh install with nothing to show.
    """
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    if project_id == DEFAULT_PROJECT_ID:
        raise HTTPException(status_code=409, detail="default workspace cannot be deleted")

    from .platform import Asset
    if db.scalar(select(Asset.id).where(Asset.project_id == project_id).limit(1)):
        raise HTTPException(409, "project is referenced by registered assets")
    scans = db.execute(select(Scan).where(Scan.project_id == project_id)).scalars().all()
    scan_ids = [s.id for s in scans]
    findings_count = 0
    events_count = 0
    if scan_ids:
        findings_count = (
            db.query(Finding).filter(Finding.scan_id.in_(scan_ids)).count()
        )
        events_count = (
            db.query(TriageEvent).filter(TriageEvent.scan_id.in_(scan_ids)).count()
        )
        db.execute(delete(TriageEvent).where(TriageEvent.scan_id.in_(scan_ids)))
        db.execute(delete(Finding).where(Finding.scan_id.in_(scan_ids)))
        db.execute(delete(Scan).where(Scan.id.in_(scan_ids)))

    name = project.name
    db.delete(project)
    db.commit()
    return {
        "deleted": project_id,
        "name": name,
        "scans": len(scan_ids),
        "findings": findings_count,
        "events": events_count,
    }


@app.post("/api/v1/scans", status_code=201)
def create_scan(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> dict[str, Any]:
    repository = payload.get("repository", "acme/telemetry-api")
    commit = payload.get("commit", "")
    files=payload.get('files')
    if not isinstance(files,list) or not files or len(files)>20:
        raise HTTPException(422,'Добавьте от 1 до 20 JSON-отчётов')
    payloads=[]
    for item in files:
        if not isinstance(item,dict):raise HTTPException(422,'Некорректное описание файла отчёта')
        name=item.get('name','payload.json')
        if not isinstance(name,str) or not name.strip() or len(name)>512:raise HTTPException(422,'Некорректное имя отчёта')
        data=item.get('json')
        if data is None and isinstance(item.get('content'),str):
            try:data=json.loads(item['content'])
            except json.JSONDecodeError:raise HTTPException(422,'Файл не является корректным JSON') from None
        try:batch=ingest_mod.detect_and_parse(name,data)
        except ValueError:raise HTTPException(422,'Структура отчёта сканера повреждена') from None
        if batch.scanner=='unknown':raise HTTPException(422,'Формат отчёта не распознан. Поддерживаются Trivy, Grype, OSV и Semgrep')
        payloads.append((name,data))
    if db.info.get("principal_kind") == "service-account" and not payload.get("projectId"):
        raise HTTPException(422, "service imports require an existing projectId")
    project = _resolve_project(
        db,
        project_id=payload.get("projectId"),
        name=payload.get("project") or repository,
        repo_url=payload.get("repoUrl") or repository,
    )
    scan = run_scan(
        db,
        repository=repository,
        commit_sha=commit,
        branch=payload.get("branch", "main"),
        payloads=payloads or [(f.get("name", "payload.json"), f.get("json")) for f in files],
        explicit_graph=None,
        triggered_by=db.info.get("actor", "local-operator"),
        profile=payload.get("profile", "prod-eu-1"),
        project_id=project.id,
        ai_settings=payload.get("ai") or payload.get("aiSettings"),
    )
    return serialize_scan(scan)


@app.post("/api/v1/scans/{scan_id}/rescan")
def rescan_scan(
    scan_id: str,
    wait: bool = Query(True),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = _get_scan(db, scan_id)
    if not wait:
        return jobs.submit_rescan(scan_id, actor=db.info.get('actor', 'system'),
            workspace_id=db.info.get('workspace_id', 'default'), user_id=db.info.get('user_id'))
    scan = _get_scan(db, scan_id)
    return serialize_scan(rescan(db, scan))


@app.get("/api/v1/scans/{scan_id}/progress")
async def scan_progress(scan_id: str, job_id: str | None = Query(None, alias="jobId"), db: Session = Depends(get_db)) -> dict[str, Any]:
    _get_scan(db, scan_id)
    from .rescan_jobs import progress
    return progress(SessionLocal, scan_id, db.info.get('workspace_id', 'default'), job_id)


@app.post("/api/v1/scans/from-source", status_code=201)
def create_scan_from_source(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Clone/read a source, run the installed scanners, and analyse.

    ``{"source": "group/project" | "https://..." | "/local/path", "ref": "main",
       "wait": true}``. With ``wait=false`` the work is dispatched to the agent
       (Celery when a queue is present, a background thread otherwise).
    """
    source = payload.get("source")
    if not source:
        raise HTTPException(status_code=422, detail="'source' is required")
    if not payload.get("wait", True):
        # Validate before _resolve_project can persist a credential-bearing URL.
        from .job_store import _safe_params
        _safe_params(payload)
    project = _resolve_project(
        db,
        project_id=payload.get("projectId"),
        name=payload.get("project"),
        repo_url=payload.get("repository") or payload.get("repoUrl") or source,
    )
    params: dict[str, Any] = {
        "source": source,
        "ref": payload.get("ref"),
        "repository": payload.get("repository"),
        "profile": payload.get("profile", "prod-eu-1"),
        "triggered_by": db.info.get("actor", "local-operator"),
        "project_id": project.id,
        "ai_settings": payload.get("ai") or payload.get("aiSettings"),
    }
    if payload.get("wait", True):
        scan, meta, used = scan_source(db, **params)
        return {"scan": serialize_scan(scan), "source": meta, "scanners": used}
    return jobs.submit_scan(_user_id=db.info.get("user_id"), _actor=db.info.get("actor", "local-operator"), _workspace_id=db.info.get("workspace_id", "default"), **params)


@app.get("/api/v1/integrations")
def get_integrations(request: access.Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    result = registry(get_ai_settings(db))
    if request.state.principal.role != "admin":
        public_fields = {"id", "kind", "label", "available", "role", "knob", "install"}
        result = {"integrations": [{k: v for k, v in entry.items() if k in public_fields} for entry in result["integrations"]]}
    return result


def _require_admin(request: access.Request) -> None:
    access.require_admin(request)


from .platform import make_router
app.include_router(make_router(access.require_read))
from .result_contracts import make_router as result_router
app.include_router(result_router(access.require_read))
from .module_intake import make_router as intake_router
app.include_router(intake_router())
from .signed_intake import router as signed_intake_router
app.include_router(signed_intake_router)
from .result_evidence import router as evidence_router
app.include_router(evidence_router)
from .result_provenance import router as provenance_router
app.include_router(provenance_router)
from .inventory_intake import router as inventory_router
app.include_router(inventory_router)
from .inventory_comparison import router as inventory_comparison_router
app.include_router(inventory_comparison_router)
from .inventory_reconciliation import router as inventory_reconciliation_router
app.include_router(inventory_reconciliation_router)
from .semgrep_batch import router as semgrep_batch_router
app.include_router(semgrep_batch_router)
from .sast_jobs import router as sast_job_router
app.include_router(sast_job_router)
from .sast_compare import router as sast_compare_router
app.include_router(sast_compare_router)
from .security_work import router as security_work_router
app.include_router(security_work_router)

from .result_retests import make_router as retest_router
app.include_router(retest_router())
from .supply_chain import make_router as supply_chain_router
app.include_router(supply_chain_router())


# --------------------------------------------------------------------------- #
# Authentication (opt-in RBAC v1)
# --------------------------------------------------------------------------- #
@app.get("/api/v1/auth/status")
def auth_status() -> dict[str, Any]:
    return {"enabled": AUTH_ENABLED, "tokenRequired": bool(ADMIN_TOKEN) and not AUTH_ENABLED, "method": "bearer" if AUTH_ENABLED else "static-header" if ADMIN_TOKEN else "open"}


@app.post("/api/v1/auth/login")
def auth_login(payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    username = str(payload.get("username") or "")
    password = str(payload.get("password") or "")
    if not AUTH_ENABLED:
        return {"authenticated": True, "token": None, "method": "open", "user": None}
    user = db.query(User).filter(User.username == username, User.is_active.is_(True)).first()
    if user is None or not rbac.verify_password(password, user.password_hash or ""):
        raise HTTPException(status_code=401, detail="invalid credentials")
    membership = db.scalar(select(access.Membership).where(access.Membership.user_id == user.id, access.Membership.organization_id == "default", access.Membership.is_active.is_(True)))
    if membership is None:
        raise HTTPException(403, "active organization membership required")
    serialized = rbac.serialize_user(user)
    serialized["role"] = membership.role
    return {"authenticated": True, "token": rbac.issue_token(user.username), "method": "bearer", "user": serialized}


@app.post("/api/v1/auth/logout")
def auth_logout(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    token = rbac.bearer_from_header(authorization)
    if token:
        rbac.revoke_token(token)
    return {"ok": True}


@app.get("/api/v1/auth/me")
def auth_me(request: access.Request, db: Session = Depends(get_db), authorization: str | None = Header(default=None)) -> dict[str, Any]:
    user = rbac.user_for_token(rbac.bearer_from_header(authorization)) if AUTH_ENABLED else None
    if user is None:
        return {"authenticated": False}
    with SessionLocal() as session:
        membership = session.scalar(select(access.Membership).where(access.Membership.user_id == user.id, access.Membership.organization_id == "default", access.Membership.is_active.is_(True)))
        if membership is None:
            return {"authenticated": False}
        serialized = rbac.serialize_user(user)
        principal = access.Principal("user:" + user.username, membership.role, "user", user_id=user.id)
        effective = workspaces.workspace_role(session, principal, request.headers.get("X-Trace-Workspace", "default"))
        serialized["role"] = effective or "viewer"
        serialized["organizationRole"] = membership.role
        return {"authenticated": True, "user": serialized}


@app.get("/api/v1/ai/providers")
def ai_providers(db: Session = Depends(get_db)) -> dict[str, Any]:
    settings = get_ai_settings(db)
    public = public_ai_settings(db)
    return {
        "settings": public,
        "providers": ai.provider_status(settings),
        "models": ai.list_models(settings),
        "active": ai.active_engine(settings),
        "available": ai.model_available(settings),
        "catalog": [
            {"id": "auto", "label": "Авто (локальный Ollama → OpenAI-совместимый → rules)"},
            {"id": "ollama", "label": "Ollama (локально, без egress)"},
            {"id": "openai", "label": "OpenAI-совместимый endpoint (egress)"},
            {"id": "rules", "label": "Rules-движок (встроенный)"},
        ],
    }


@app.get("/api/v1/ai/settings")
def ai_settings_read(db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"settings": public_ai_settings(db), "active": ai.active_engine(get_ai_settings(db))}


@app.put("/api/v1/ai/settings")
def ai_settings_write(
    payload: dict[str, Any] = Body(default={}),
    db: Session = Depends(get_db),
    _: None = Depends(_require_admin),
) -> dict[str, Any]:
    if payload.get("provider") and payload["provider"] not in ("auto", "ollama", "openai", "rules"):
        raise HTTPException(status_code=422, detail="unknown provider")
    try:
        set_ai_settings(db, payload)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    settings = get_ai_settings(db)
    return {
        "settings": public_ai_settings(db),
        "active": ai.active_engine(settings),
        "available": ai.model_available(settings),
    }


@app.post("/api/v1/ai/test")
def ai_test(
    payload: dict[str, Any] = Body(default={}),
    db: Session = Depends(get_db),
    _: None = Depends(_require_admin),
) -> dict[str, Any]:
    override = payload.get("settings") or payload or None
    settings = get_ai_settings(db)
    if override:
        try:
            patch = normalize_ai_patch(override)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        if patch.get('api_key') == '••••••': patch.pop('api_key')
        settings = {**settings, **patch}
        if 'secret_ref' in patch:
            from .scoped_settings import resolve_secret
            settings['api_key']=resolve_secret(db,patch['secret_ref'])
    return ai.test_provider(settings)


# --------------------------------------------------------------------------- #
# Release policy & CI gate
# --------------------------------------------------------------------------- #
@app.get("/api/v1/settings/policy")
def policy_settings_read(db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"policy": get_policy_settings(db)}


@app.put("/api/v1/settings/policy")
def policy_settings_write(
    payload: dict[str, Any] = Body(default={}),
    db: Session = Depends(get_db),
    _: None = Depends(_require_admin),
) -> dict[str, Any]:
    return {"policy": set_policy_settings(db, payload.get("policy") or payload or {})}


@app.get("/api/v1/scans/{scan_id}/policy")
def scan_policy(
    scan_id: str,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    scan = _get_scan(db, scan_id)
    findings = [serialize_finding(f) for f in scan.findings]
    return evaluate_policy(scan.id, findings, get_policy_settings(db))


@app.post("/api/v1/scans/{scan_id}/gate")
def gate_scan(
    scan_id: str,
    enforce: bool = Query(False),
    payload: dict[str, Any] = Body(default={}),
    db: Session = Depends(get_db),
) -> Any:
    """CI release gate. Exits non-zero when the scan breaks the policy.

    With ``enforce=1`` a blocked gate returns HTTP 409 (so `curl -f` fails),
    otherwise the decision is always HTTP 200 with ``exitCode`` in the body.
    """
    scan = _get_scan(db, scan_id)
    policy = payload.get("policy") or get_policy_settings(db)
    findings = [serialize_finding(f) for f in scan.findings]
    result = evaluate_policy(scan.id, findings, policy)
    if enforce and result.get("gate") == "blocked":
        raise HTTPException(status_code=409, detail=result)
    return result


# --------------------------------------------------------------------------- #
# Compliance reports
# --------------------------------------------------------------------------- #
@app.get("/api/v1/compliance/standards")
def compliance_standards() -> list[dict[str, Any]]:
    return compliance.STANDARDS


# --------------------------------------------------------------------------- #
# Advisory database (derived from local scan evidence)
# --------------------------------------------------------------------------- #
@app.get("/api/v1/advisories")
def list_advisories(
    scan_id: str | None = None,
    severity: str | None = Query(None),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    stmt = select(Scan, Finding).join(Finding, Scan.id == Finding.scan_id)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    rows = db.execute(stmt.order_by(Finding.cve)).all()

    groups: dict[str, dict[str, Any]] = {}
    for scan, finding in rows:
        key = f"{finding.cve}::{finding.package_name}"
        group = groups.setdefault(
            key,
            {
                "cve": finding.cve,
                "packageName": finding.package_name,
                "severity": finding.severity,
                "cvss": finding.cvss,
                "versions": set(),
                "fixedIn": set(),
                "scans": set(),
                "scannedFrom": None,
                "scannedTo": None,
                "affected": 0,
                "observed": [],
            },
        )
        group["versions"].add(finding.version)
        if finding.fixed_in:
            group["fixedIn"].add(finding.fixed_in)
        group["scans"].add(scan.id)
        group["observed"].append(
            {
                "scanId": scan.id,
                "repository": scan.repository,
                "commit": scan.commit_short,
                "version": finding.version,
                "reachability": finding.reachability,
                "verdict": finding.verdict,
                "fixedIn": finding.fixed_in,
            }
        )
        ts = scan.scanned_at
        if ts is not None:
            if group["scannedFrom"] is None or ts < group["scannedFrom"]:
                group["scannedFrom"] = ts
            if group["scannedTo"] is None or ts > group["scannedTo"]:
                group["scannedTo"] = ts
        if finding.reachability == "reachable" and finding.verdict == "affected":
            group["affected"] += 1

    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    result = []
    for group in groups.values():
        group["versions"] = sorted(group["versions"])
        group["fixedIn"] = sorted(group["fixedIn"])
        group["scanCount"] = len(group["scans"])
        group.pop("scans")
        group["scannedFrom"] = group["scannedFrom"].isoformat().replace("+00:00", "Z") if group["scannedFrom"] else ""
        group["scannedTo"] = group["scannedTo"].isoformat().replace("+00:00", "Z") if group["scannedTo"] else ""
        group["recommendation"] = (
            f"Upgrade {group['packageName']} to {', '.join(group['fixedIn'])}"
            if group["fixedIn"]
            else f"Review {group['cve']} and pin the verdict via VEX; no fixed release recorded."
        )
        result.append(group)
    result.sort(key=lambda g: (order.get(str(g["severity"]).lower(), 0), g["cve"]), reverse=True)
    return result


@app.get("/api/v1/advisories/{cve}")
def advisory_by_cve(cve: str, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    rows = db.execute(select(Finding).where(Finding.cve == cve)).scalars().all()
    if not rows:
        raise HTTPException(status_code=404, detail="no advisory for this CVE in local evidence")
    return [serialize_finding(f) for f in rows]


# --------------------------------------------------------------------------- #
# Compliance reports
# --------------------------------------------------------------------------- #


@app.get("/api/v1/scans/{scan_id}/compliance")
def scan_compliance(
    scan_id: str,
    standard: str = Query("iso-27001"),
    format: str = Query("md"),
    download: bool = Query(False),
    db: Session = Depends(get_db),
) -> Any:
    scan = _get_scan(db, scan_id)
    findings = [serialize_finding(f) for f in scan.findings]
    try:
        report = compliance.build_report(scan, findings, standard, format)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not download:
        return report
    ext = "md" if format == "md" else "html"
    filename = f"{scan.repository.replace('/', '_')}-{standard}-{scan.commit_short}.{ext}"
    from fastapi.responses import Response

    return Response(
        content=report["report"],
        media_type="text/markdown; charset=utf-8" if ext == "md" else "text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/v1/access/job-retention")
def preview_job_retention(days: int = Query(90, ge=1, le=3650), limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    from .job_retention import preview
    return preview(SessionLocal, db.info.get('workspace_id', 'default'), days, limit).model_dump()


@app.get("/api/v1/jobs")
def get_jobs(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return jobs.list_jobs(limit, workspace_id=db.info.get("workspace_id", "default"))


@app.get("/api/v1/jobs/{job_id}")
def get_job(job_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    job = jobs.job_status(job_id, workspace_id=db.info.get("workspace_id", "default"))
    if job is None:
        raise HTTPException(status_code=404, detail="job not found")
    return {"jobId": job_id, **job}


@app.post("/api/v1/jobs/{job_id}/cancel")
def cancel_job(job_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    from .job_store import cancel
    return cancel(SessionLocal, job_id, db.info.get('workspace_id', 'default'), db.info.get('actor', 'system'))


@app.get("/api/v1/scans/{scan_id}/funnel")
async def get_funnel(
    scan_id: str | None = None, project_id: int | None = Query(None), db: Session = Depends(get_db)
) -> list[dict[str, Any]]:
    scan = _get_scan(db, scan_id, project_id)
    return serialize_scan(scan)["funnel"]


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@app.get("/api/v1/scans/{scan_id}/findings")
async def scan_findings(
    scan_id: str | None = None,
    filter: str = Query("all"),
    sort: str = Query("severity"),
    q: str = Query(""),
    db: Session = Depends(get_db),
) -> list[dict[str, Any]]:
    scan = _get_scan(db, scan_id)
    items = _filter_findings(list(scan.findings), filter)
    items = [f for f in items if _matches(f, q)]
    return [serialize_finding(f) for f in _sort_findings(items, sort)]


def _remember_pre_suppress(finding: Finding) -> None:
    """Stash the pre-suppress state so ``unsuppress`` can restore it exactly.

    Re-suppressing an already-suppressed finding must not overwrite the saved
    state, otherwise ``unsuppress`` would restore "suppressed" and the finding
    could never leave the suppressed pool.
    """
    evidence = dict(finding.evidence or {})
    if evidence.get("preSuppress"):
        return
    evidence["preSuppress"] = {"reachability": finding.reachability, "verdict": finding.verdict}
    finding.evidence = evidence


def _restore_pre_suppress(finding: Finding) -> None:
    evidence = dict(finding.evidence or {})
    previous = evidence.pop("preSuppress", None) or {}
    finding.evidence = evidence
    finding.reachability = previous.get("reachability") or "unknown"
    finding.verdict = previous.get("verdict") or "needs_review"


@app.get("/api/v1/findings/{finding_id}")
async def get_finding(finding_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return serialize_finding(finding)


@app.post("/api/v1/findings/{finding_id}/review")
async def review_finding(
    finding_id: str, payload: dict[str, Any] = Body(default={}), db: Session = Depends(get_db)
) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.reviewed = bool(payload.get("reviewed", True))
    db.add(TriageEvent(finding_id=finding_id, scan_id=finding.scan_id, action="review", actor=db.info.get("actor", "local-operator"), detail=str(finding.reviewed)))
    db.commit()
    return serialize_finding(finding)


@app.post("/api/v1/findings/{finding_id}/suppress")
async def suppress_finding(
    finding_id: str, payload: dict[str, Any] = Body(default={}), db: Session = Depends(get_db)
) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    reason = payload.get("reason", "Manually suppressed by analyst.")
    _remember_pre_suppress(finding)
    finding.reachability = "suppressed"
    finding.verdict = "not_affected"
    finding.suppress_reason = reason
    db.add(TriageEvent(finding_id=finding_id, scan_id=finding.scan_id, action="suppress", actor=db.info.get("actor", "local-operator"), detail=reason))
    db.commit()
    return serialize_finding(finding)


@app.post("/api/v1/findings/{finding_id}/unsuppress")
async def unsuppress_finding(finding_id: str, db: Session = Depends(get_db)) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    finding.suppress_reason = None
    _restore_pre_suppress(finding)
    db.add(TriageEvent(finding_id=finding_id, scan_id=finding.scan_id, action="unsuppress", actor=db.info.get("actor", "local-operator"), detail=""))
    db.commit()
    return serialize_finding(finding)


# --------------------------------------------------------------------------- #
# Batch triage
# --------------------------------------------------------------------------- #
@app.post("/api/v1/findings/batch-review")
def batch_review(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> dict[str, Any]:
    ids = payload.get("ids") or []
    reviewed = bool(payload.get("reviewed", True))
    actor = db.info.get("actor", "local-operator")
    updated = 0
    for finding_id in ids:
        finding = db.get(Finding, finding_id)
        if finding is None:
            continue
        finding.reviewed = reviewed
        db.add(TriageEvent(finding_id=finding_id, scan_id=finding.scan_id, action="review", actor=actor, detail=str(reviewed)))
        updated += 1
    db.commit()
    return {"updated": updated}


@app.post("/api/v1/findings/batch-suppress")
def batch_suppress(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> dict[str, Any]:
    ids = payload.get("ids") or []
    reason = payload.get("reason", "Manually suppressed by analyst.")
    actor = db.info.get("actor", "local-operator")
    updated = 0
    for finding_id in ids:
        finding = db.get(Finding, finding_id)
        if finding is None:
            continue
        _remember_pre_suppress(finding)
        finding.reachability = "suppressed"
        finding.verdict = "not_affected"
        finding.suppress_reason = reason
        db.add(TriageEvent(finding_id=finding_id, scan_id=finding.scan_id, action="suppress", actor=actor, detail=reason))
        updated += 1
    db.commit()
    return {"updated": updated}


@app.post("/api/v1/findings/batch-unsuppress")
def batch_unsuppress(payload: dict[str, Any] = Body(...), db: Session = Depends(get_db)) -> dict[str, Any]:
    ids = payload.get("ids") or []
    updated = 0
    for finding_id in ids:
        finding = db.get(Finding, finding_id)
        if finding is None:
            continue
        finding.suppress_reason = None
        _restore_pre_suppress(finding)
        db.add(TriageEvent(finding_id=finding_id, scan_id=finding.scan_id, action="unsuppress", actor=db.info.get("actor", "local-operator"), detail=""))
        updated += 1
    db.commit()
    return {"updated": updated}


# --------------------------------------------------------------------------- #
# Reachability & SBOM
# --------------------------------------------------------------------------- #
@app.get("/api/v1/scans/{scan_id}/reachability")
async def get_reachability(scan_id: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = _get_scan(db, scan_id)
    findings = [f for f in scan.findings if f.reachability in ("reachable", "suppressed")]
    findings = _sort_findings(findings, "severity")
    return {
        "scan": serialize_scan(scan),
        "findings": [serialize_finding(f) for f in findings],
        "paths": sum(1 for f in findings if f.reachability == "reachable"),
    }


@app.get("/api/v1/scans/{scan_id}/sbom")
async def get_sbom(scan_id: str | None = None, db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = _get_scan(db, scan_id)
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []

    def add_node(node_id: str, depth: int, kind: str, vulnerable: bool = False, finding_id: str | None = None) -> None:
        existing = nodes.get(node_id)
        if existing is None:
            existing = nodes[node_id] = {
                "id": node_id,
                "label": node_id,
                "depth": depth,
                "kind": kind,
                "vulnerable": vulnerable,
                "findings": 0,
                "findingIds": [],
            }
        if vulnerable:
            existing["vulnerable"] = True
        existing["findings"] += 1
        if finding_id and finding_id not in existing["findingIds"]:
            existing["findingIds"].append(finding_id)

    for finding in scan.findings:
        path = finding.dependency_path or [scan.repository, finding.package_name]
        for depth, node in enumerate(path):
            add_node(
                node,
                depth,
                "package" if depth else "root",
                vulnerable=(node == finding.package_name),
                finding_id=finding.id,
            )
        for a, b in zip(path, path[1:]):
            edge = {"source": a, "target": b}
            if edge not in edges:
                edges.append(edge)

    return {
        "scan": scan.id,
        "components": len(nodes),
        "nodes": list(nodes.values()),
        "edges": edges,
    }


# --------------------------------------------------------------------------- #
# Ingest (preview) & VEX
# --------------------------------------------------------------------------- #
@app.post("/api/v1/ingest")
def ingest_preview(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    files: list[dict[str, Any]] = payload.get("files") or []
    parsed: list[tuple[str, Any]] = []
    for f in files:
        content = f.get("content")
        data = f.get("json")
        if data is None and isinstance(content, str):
            try:
                data = json.loads(content)
            except json.JSONDecodeError:
                data = None
        if data is not None:
            parsed.append((f.get("name", "payload.json"), data))

    records, semgrep_results, scanners = ingest_mod.parse_many(parsed)
    from .pipeline.dedup import deduplicate

    candidates = deduplicate(records)
    return {
        "rawRecords": len(records),
        "semgrepMatches": len(semgrep_results),
        "scanners": scanners,
        "candidates": [
            {
                "cve": c.cve,
                "packageName": c.package,
                "version": c.version,
                "ecosystem": c.ecosystem,
                "severity": c.severity,
                "cvss": c.cvss,
                "rawCount": c.raw_count,
            }
            for c in candidates
        ],
    }


def _resolve_vex_scope(scan: Scan, scope: str, finding_id: str | None) -> tuple[list[Finding], list[dict[str, Any]]]:
    items = list(scan.findings)
    if scope == "finding":
        finding = next((f for f in items if f.id == finding_id), None)
        selected = [finding] if finding else []
    elif scope == "actionable":
        selected = [f for f in items if f.reachability == "reachable" and f.verdict == "affected"]
    else:
        selected = items
    return selected, [serialize_finding(f) for f in selected]


@app.get("/api/v1/vex")
async def get_vex(
    scan_id: str | None = None,
    scope: str = Query("all"),
    finding: str | None = None,
    download: int = 0,
    db: Session = Depends(get_db),
) -> Response:
    scan = _get_scan(db, scan_id)
    selected, serialized = _resolve_vex_scope(scan, scope, finding)
    content = build_vex(serialize_scan(scan), serialized, scope)
    headers = {}
    if download:
        headers["Content-Disposition"] = f'attachment; filename="{file_name(serialize_scan(scan), scope)}"'
    return Response(content=content, media_type="application/json", headers=headers)


@app.get("/api/v1/vex/meta")
async def get_vex_meta(scan_id: str | None = None, scope: str = Query("all"), db: Session = Depends(get_db)) -> dict[str, Any]:
    scan = _get_scan(db, scan_id)
    selected, serialized = _resolve_vex_scope(scan, scope, None)
    return {
        "documentId": document_id(serialize_scan(scan), scope),
        "fileName": file_name(serialize_scan(scan), scope),
        "count": len(serialized),
        "affected": sum(1 for f in serialized if f["verdict"] == "affected"),
        "notAffected": sum(1 for f in serialized if f["verdict"] == "not_affected"),
        "suppressed": sum(1 for f in serialized if f["reachability"] == "suppressed"),
    }


from datetime import date
from typing import Literal
from pydantic import BaseModel, Field

class WorkflowUpdate(BaseModel):
    assignee: str = Field(default="", max_length=128)
    status: Literal["new", "in_progress", "resolved", "accepted_risk"] = "new"
    dueDate: date | None = None
    note: str = Field(default="", max_length=4000)

@app.put("/api/v1/findings/{finding_id}/workflow", dependencies=[Depends(access.require_analyst)])
def update_workflow(finding_id: str, payload: WorkflowUpdate, db: Session = Depends(get_db)) -> dict[str, Any]:
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if payload.status == "accepted_risk" and (not payload.note.strip() or payload.dueDate is None):
        raise HTTPException(status_code=422, detail="Для принятия риска укажите причину и дату пересмотра")
    finding.assignee = payload.assignee.strip()
    finding.workflow_status = payload.status
    finding.due_date = payload.dueDate.isoformat() if payload.dueDate else ""
    finding.triage_note = payload.note.strip()
    db.add(TriageEvent(finding_id=finding.id, scan_id=finding.scan_id, action="workflow", actor=db.info.get("actor", "local-operator"), detail=json.dumps({"assignee": finding.assignee, "status": finding.workflow_status, "dueDate": finding.due_date, "note": finding.triage_note}, ensure_ascii=False)))
    db.commit()
    return serialize_finding(finding)

@app.post("/api/v1/findings/{finding_id}/analyze", dependencies=[Depends(access.require_analyst)])
def analyze_one_finding(finding_id: str, payload: dict[str, Any] = Body(default={}), db: Session = Depends(get_db)) -> dict[str, Any]:
    from .pipeline.dedup import Candidate
    from .pipeline.reachability import ReachabilityResult
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="finding not found")
    try:
        overrides = normalize_ai_patch({k:v for k,v in payload.items() if k in ('analysisDepth','responseLanguage')})
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    settings = {**get_ai_settings(db), **overrides}
    evidence = finding.evidence or {}
    candidate = Candidate(cve=finding.cve, package=finding.package_name, version=finding.version, ecosystem=finding.ecosystem, severity=finding.severity, cvss=finding.cvss, raw_count=finding.raw_count)
    reached = ReachabilityResult(reachability=finding.reachability, frames=finding.frames or [], blocker=finding.blocker, taint_source=evidence.get('taintSource'), sink=evidence.get('sink'), propagation=evidence.get('taintPropagation') or [], usage=finding.usage or 'unknown', usage_hits=evidence.get('usageHits') or [], usage_note=evidence.get('usageNote'))
    result = ai.assess(candidate, reached, finding.dependency_path or [], finding.scan.profile, settings, extra_context={'fixedVersion':finding.fixed_in, 'cwe':finding.cwe or []})
    finding.evidence = result['evidence']
    if finding.reachability != 'suppressed':
        finding.verdict = result['verdict']
        finding.confidence = result['confidence']
    db.add(TriageEvent(finding_id=finding.id, scan_id=finding.scan_id, action='ai-analysis', actor=db.info.get('actor', 'local-operator'), detail=json.dumps({'engine':result['engine'], 'depth':settings.get('analysis_depth'), 'source':result['evidence']['deepAnalysis']['source']}, ensure_ascii=False)))
    db.commit()
    return {'finding':serialize_finding(finding), 'engine':result['engine'], 'source':result['evidence']['deepAnalysis']['source']}

# --------------------------------------------------------------------------- #
# Frontend (single-origin serving)
# --------------------------------------------------------------------------- #
# Mounted last so the explicit /api routes, /docs and /openapi.json win the
# route match. `html=True` makes the bundle act as a SPA: "/" serves
# index.html. When the bundle is absent (backend-only deploy) we fall back to a
# small JSON descriptor on "/".
if FRONTEND_DIST is not None:

    class SpaStaticFiles(StaticFiles):
        """Serve the SPA with sane caching: hashed assets are immutable, but the
        HTML shell is always revalidated so a rebuilt bundle is picked up instead
        of leaving a stale page that points at removed assets (blank screen)."""

        async def get_response(self, path: str, scope) -> Response:
            response = await super().get_response(path, scope)
            if path.replace("\\", "/").lstrip("/").startswith("assets/"):
                response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
            else:
                response.headers["Cache-Control"] = "no-cache"
            return response

    app.mount("/", SpaStaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")
else:

    @app.get("/")
    async def root() -> dict[str, str]:
        return {"service": "TRACE Security API", "version": __version__, "docs": "/docs"}

"""Request authorization and organization ownership, stage 2A.

Only the default organization is enabled. No header can enable another tenant.
Credentials and scopes are resolved server-side for every request.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
import secrets
from uuid import uuid4
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from starlette.responses import JSONResponse
from . import config, rbac
from .database import SessionLocal, get_db
from .access_models import DEFAULT_ORGANIZATION, Organization, Membership, ServiceAccount
from .models import AppSetting, User
from .platform import PlatformAudit, audit

ROLES = {"viewer", "analyst", "admin"}
SCOPES = {"inventory:read", "inventory:write", "findings:read", "findings:triage", "scans:read", "scans:import", "gate:read"}

@dataclass(frozen=True)
class Principal:
    actor: str
    role: str
    kind: str
    scopes: frozenset[str] = frozenset()
    user_id: int | None = None
    workspace_id: str = "default"
    organization_role: str = ""


def ensure_default_identity(db: Session):
    if db.get(Organization, DEFAULT_ORGANIZATION) is None:
        db.add(Organization(id=DEFAULT_ORGANIZATION, name="Основная организация"))
        db.flush()
    # A marker prevents a revoked/deleted membership being restored on restart.
    key = "access.legacy-memberships.v1"
    if db.get(AppSetting, key) is None:
        for user in db.scalars(select(User)):
            existing = db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.organization_id == DEFAULT_ORGANIZATION))
            if existing is None:
                role = "admin" if user.role == "admin" else "analyst"
                db.add(Membership(organization_id=DEFAULT_ORGANIZATION, user_id=user.id, role=role, is_active=user.is_active))
        db.add(AppSetting(key=key, value={"version": 1}))
    db.flush()  # SessionLocal disables autoflush; bootstrap must see pending memberships.
    # A fresh bootstrap admin can appear after an earlier unauthenticated startup.
    if config.AUTH_ENABLED and config.TRACE_ADMIN_PASSWORD:
        user = db.scalar(select(User).where(User.username == config.TRACE_ADMIN_USERNAME))
        bootstrap_key = "access.bootstrap-membership.v1"
        if user and db.get(AppSetting, bootstrap_key) is None:
            existing = db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.organization_id == DEFAULT_ORGANIZATION))
            if existing is None:
                db.add(Membership(organization_id=DEFAULT_ORGANIZATION, user_id=user.id, role="admin", is_active=True))
            db.add(AppSetting(key=bootstrap_key, value={"version": 1}))
    db.commit()


def _expired(value):
    expiry = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
    return expiry <= datetime.now(timezone.utc)


def _resolve_identity(request: Request) -> Principal:
    requested = request.headers.get("X-Trace-Organization", DEFAULT_ORGANIZATION)
    if requested != DEFAULT_ORGANIZATION:
        raise HTTPException(403, "Additional organizations are disabled in stage 2A")
    token = rbac.bearer_from_header(request.headers.get("Authorization"))
    if not config.AUTH_ENABLED:
        if config.ADMIN_TOKEN:
            supplied = request.headers.get("X-Admin-Token", "")
            if not hmac.compare_digest(supplied, config.ADMIN_TOKEN):
                raise HTTPException(401, "admin token required")
            return Principal("static-admin", "admin", "static-token")
        return Principal("local-operator", "admin", "local")
    if token and token.startswith("trace_sa_"):
        with SessionLocal() as db:
            account = db.scalar(select(ServiceAccount).where(ServiceAccount.token_hash == hashlib.sha256(token.encode()).hexdigest()))
            if account is None or account.revoked or _expired(account.expires_at) or account.organization_id != DEFAULT_ORGANIZATION:
                raise HTTPException(401, "invalid service account")
            return Principal("service:" + account.id, "service", "service-account", frozenset(account.scopes.split()), workspace_id=account.workspace_id)
    user = rbac.user_for_token(token)
    if user is None:
        raise HTTPException(401, "login required")
    with SessionLocal() as db:
        membership = db.scalar(select(Membership).where(Membership.user_id == user.id, Membership.organization_id == DEFAULT_ORGANIZATION, Membership.is_active.is_(True)))
        if membership is None or membership.role not in ROLES:
            raise HTTPException(403, "active organization membership required")
        return Principal("user:" + user.username, membership.role, "user", user_id=user.id)


def resolve_principal(request: Request) -> Principal:
    from .workspaces import bind_principal
    principal = _resolve_identity(request)
    with SessionLocal() as db:
        return bind_principal(request, principal, db)


def required_service_scope(method, path):
    read = method in ("GET", "HEAD")
    if read and re.fullmatch(r'/api/v1/platform/assets/[^/]+/supply-chain',path):
        return 'inventory:read'
    if re.fullmatch(r"/api/v1/platform/(assets(?:/[^/]+)?|links)", path):
        return "inventory:read" if read else "inventory:write"
    if path == "/api/v1/platform/modules" and read:
        return "inventory:read"
    if re.fullmatch(r"/api/v1/findings/[^/]+(?:/(?:review|suppress|unsuppress|workflow|result))?", path):
        return "findings:read" if read else "findings:triage"
    if re.fullmatch(r"/api/v1/scans/[^/]+/(?:policy|gate)", path):
        return "gate:read"
    if path == "/api/v1/scans" and method == "POST":
        return "scans:import"
    if read and (re.fullmatch(r"/api/v1/scans(?:/[^/]+(?:/(?:findings|funnel|sbom|reachability|compliance|progress))?)?", path) or path in ("/api/v1/vex", "/api/v1/vex/meta")):
        return "scans:read"
    return None


def authorize(principal: Principal, method: str, path: str):
    if principal.kind == "service-account":
        scope = required_service_scope(method, path)
        if scope is None or scope not in principal.scopes:
            raise HTTPException(403, "service account scope denied")
        return
    read = method in ("GET", "HEAD")
    if method == "DELETE" and principal.role != "admin":
        raise HTTPException(403, "organization admin required for deletion")
    if path.startswith("/api/v1/access/"):
        if path == "/api/v1/access/context" and read:
            return
        if principal.role != "admin":
            raise HTTPException(403, "organization admin required")
    elif (path.startswith("/api/v1/teams") or (path.startswith("/api/v1/workspaces") and not (path == "/api/v1/workspaces" and read))):
        if (principal.organization_role or principal.role) != "admin":
            raise HTTPException(403, "organization admin required")
    elif path.startswith(("/api/v1/ai/", "/api/v1/settings/")) or path == "/api/v1/scans/from-source" or (method == "POST" and re.fullmatch(r"/api/v1/jobs/[^/]+/cancel", path)):
        if principal.role != "admin":
            raise HTTPException(403, "organization admin required")
    elif not read and principal.role == "viewer":
        if not (re.fullmatch(r"/api/v1/scans/[^/]+/gate", path) or path == "/api/v1/ingest"):
            raise HTTPException(403, "read-only organization role")


async def access_middleware(request: Request, call_next):
    path = request.url.path
    public = {"/api/v1/auth/status", "/api/v1/auth/login", "/api/v1/auth/me", "/api/v1/auth/logout"}
    signed_hook = request.method == "POST" and re.fullmatch(r"/api/v1/hooks/results/[A-Za-z0-9_-]{1,64}",path) is not None
    if path.startswith("/api/") and not signed_hook and path not in public and request.method != "OPTIONS":
        try:
            principal = resolve_principal(request)
            authorize(principal, request.method, path)
            request.state.principal = principal
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
    response = await call_next(request)
    if path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


def require_read(request: Request):
    return request.state.principal


def require_admin(request: Request):
    principal = request.state.principal
    if principal.role != "admin":
        raise HTTPException(403, "organization admin required")


def require_analyst(request: Request):
    principal = request.state.principal
    if principal.role not in ("analyst", "admin") and not (principal.kind == "service-account" and "findings:triage" in principal.scopes):
        raise HTTPException(403, "analyst role required")


class ServiceInput(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r".*\S.*")
    scopes: list[Literal["inventory:read", "inventory:write", "findings:read", "findings:triage", "scans:read", "scans:import", "gate:read"]] = Field(min_length=1, max_length=7)
    expiresInDays: int = Field(default=30, ge=1, le=90)

class MemberUpdate(BaseModel):
    role: Literal["viewer", "analyst", "admin"]
    active: bool


def service_public(a):
    return dict(id=a.id, name=a.name, workspaceId=a.workspace_id, scopes=a.scopes.split(), expiresAt=(a.expires_at.replace(tzinfo=timezone.utc) if a.expires_at.tzinfo is None else a.expires_at).isoformat(), revoked=a.revoked, createdBy=a.created_by)

router = APIRouter(prefix="/api/v1/access")

@router.get("/context")
def access_context(request: Request, db: Session = Depends(get_db)):
    organization = db.get(Organization, DEFAULT_ORGANIZATION)
    p = request.state.principal
    return {"organization": {"id": DEFAULT_ORGANIZATION, "name": organization.name},
            "workspaceId": p.workspace_id,
            "organizationRole": p.organization_role or p.role,
            "principal": {"actor": p.actor, "role": p.role, "kind": p.kind},
            "authenticationEnabled": config.AUTH_ENABLED, "additionalOrganizationsEnabled": False,
            "permissions": {"write": p.role in ("analyst", "admin"), "admin": p.role == "admin"}}

@router.get("/members")
def members(db: Session = Depends(get_db)):
    rows = db.execute(select(Membership, User).join(User, User.id == Membership.user_id).where(Membership.organization_id == DEFAULT_ORGANIZATION).order_by(User.username)).all()
    return [dict(id=m.id, userId=u.id, username=u.username, displayName=u.display_name, role=m.role, active=m.is_active, userActive=u.is_active) for m,u in rows]

def lock_default_organization(db):
    # SQLite ignores FOR UPDATE. A harmless write serializes access mutations
    # before counting administrators or active service accounts.
    if db.get_bind().dialect.name == "sqlite":
        db.execute(update(Organization).where(Organization.id == DEFAULT_ORGANIZATION).values(name=Organization.name))
    else:
        db.scalar(select(Organization).where(Organization.id == DEFAULT_ORGANIZATION).with_for_update())


@router.put("/members/{member_id}")
def update_member(member_id: int, body: MemberUpdate, request: Request, db: Session = Depends(get_db)):
    lock_default_organization(db)
    member = db.get(Membership, member_id)
    if not member or member.organization_id != DEFAULT_ORGANIZATION:
        raise HTTPException(404, "member not found")
    if member.role == "admin" and member.is_active and (body.role != "admin" or not body.active):
        admins = db.scalars(select(Membership).join(User, User.id == Membership.user_id).where(Membership.organization_id == DEFAULT_ORGANIZATION, Membership.role == "admin", Membership.is_active.is_(True), User.is_active.is_(True))).all()
        if len(admins) <= 1:
            raise HTTPException(409, "cannot remove the last active administrator")
    member.role = body.role
    member.is_active = body.active
    audit(db, "membership.updated", str(member.id), f"role={body.role};active={body.active}")
    db.commit()
    return {"id": member.id, "role": member.role, "active": member.is_active}

@router.get("/service-accounts")
def service_accounts(db: Session = Depends(get_db)):
    return [service_public(a) for a in db.scalars(select(ServiceAccount).where(ServiceAccount.organization_id == DEFAULT_ORGANIZATION, ServiceAccount.workspace_id == db.info.get("workspace_id", "default")).order_by(ServiceAccount.created_at.desc()))]

@router.post("/service-accounts", status_code=201)
def create_service(body: ServiceInput, request: Request, db: Session = Depends(get_db)):
    if not config.AUTH_ENABLED:
        raise HTTPException(409, "enable authentication before issuing service credentials")
    lock_default_organization(db)
    active_count = len(db.scalars(select(ServiceAccount.id).where(ServiceAccount.organization_id == DEFAULT_ORGANIZATION, ServiceAccount.revoked.is_(False), ServiceAccount.expires_at > datetime.now(timezone.utc))).all())
    if active_count >= 100:
        raise HTTPException(409, "active service account limit reached (100)")
    token = "trace_sa_" + secrets.token_urlsafe(32)
    a = ServiceAccount(id=uuid4().hex, organization_id=DEFAULT_ORGANIZATION, workspace_id=request.state.principal.workspace_id, name=body.name.strip(), token_hash=hashlib.sha256(token.encode()).hexdigest(), scopes=" ".join(sorted(set(body.scopes))), expires_at=datetime.now(timezone.utc) + timedelta(days=body.expiresInDays), created_by=request.state.principal.actor)
    db.add(a)
    audit(db, "service.created", a.id, "scopes=" + a.scopes)
    db.commit()
    return {"account": service_public(a), "token": token}

@router.post("/service-accounts/{account_id}/revoke")
def revoke_service(account_id: str, db: Session = Depends(get_db)):
    account = db.get(ServiceAccount, account_id)
    if not account or account.organization_id != DEFAULT_ORGANIZATION or account.workspace_id != db.info.get("workspace_id", "default"):
        raise HTTPException(404, "service account not found")
    if not account.revoked:
        account.revoked = True
        audit(db, "service.revoked", account.id, "credential revoked")
        db.commit()
    return service_public(account)

@router.get("/audit")
def access_audit(limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    return [dict(id=a.id, action=a.action, objectId=a.object_id, actor=a.actor, detail=a.detail, at=a.occurred_at) for a in db.scalars(select(PlatformAudit).order_by(PlatformAudit.occurred_at.desc()).limit(limit))]

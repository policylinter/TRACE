"""Workspace grants and team administration. Additional organizations remain disabled."""
from dataclasses import replace
from uuid import uuid4
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from .database import get_db
from .access_models import Organization, Membership
from .workspace_models import Workspace, WorkspaceMember, Team, TeamMember, WorkspaceTeam
from .models import AppSetting, User
from .platform import audit

RANK = {"viewer": 0, "analyst": 1, "admin": 2}


def ensure_default_workspace(db):
    if db.get(Organization, "default") is None:
        db.add(Organization(id="default", name="Основная организация"))
        db.flush()
    if db.get(Workspace, "default") is None:
        db.add(Workspace(id="default", organization_id="default", name="Основное пространство"))
    db.commit()


def ensure_legacy_workspace_grants(db):
    key = "access.legacy-workspace-grants.v1"
    if db.get(AppSetting, key) is not None:
        return
    for member in db.scalars(select(Membership).where(Membership.organization_id == "default")):
        grant = db.scalar(select(WorkspaceMember).where(WorkspaceMember.workspace_id == "default", WorkspaceMember.user_id == member.user_id))
        if grant is None:
            db.add(WorkspaceMember(organization_id="default", workspace_id="default", user_id=member.user_id, role="viewer" if member.role == "viewer" else "analyst", active=True))
    db.add(AppSetting(key=key, value={"version": 1}))
    db.commit()


def workspace_role(db, principal, workspace_id):
    workspace = db.get(Workspace, workspace_id)
    if workspace is None or workspace.organization_id != "default":
        return None
    org_role = principal.organization_role or principal.role
    if org_role == "admin":
        return "admin"
    if principal.user_id is None:
        return None
    direct = db.scalars(select(WorkspaceMember.role).where(WorkspaceMember.organization_id == "default", WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.user_id == principal.user_id, WorkspaceMember.active.is_(True))).all()
    via_team = db.scalars(select(WorkspaceTeam.role).join(TeamMember, (TeamMember.team_id == WorkspaceTeam.team_id) & (TeamMember.organization_id == WorkspaceTeam.organization_id)).where(WorkspaceTeam.organization_id == "default", WorkspaceTeam.workspace_id == workspace_id, WorkspaceTeam.active.is_(True), TeamMember.user_id == principal.user_id, TeamMember.active.is_(True))).all()
    ranks = [RANK[r] for r in list(direct) + list(via_team) if r in ("viewer", "analyst")]
    if not ranks or org_role not in RANK:
        return None
    return ("viewer", "analyst", "admin")[min(RANK[org_role], max(ranks))]


def bind_principal(request, principal, db):
    workspace_id = request.headers.get("X-Trace-Workspace", "default")
    if not workspace_id or len(workspace_id) > 64:
        raise HTTPException(403, "workspace access denied")
    org_role = principal.organization_role or principal.role
    if principal.kind == "service-account":
        if workspace_id != principal.workspace_id:
            raise HTTPException(403, "service account is bound to another workspace")
        workspace = db.get(Workspace, workspace_id)
        if workspace is None or workspace.organization_id != "default":
            raise HTTPException(403, "workspace access denied")
        return principal
    # Discovery and grant administration use organization permissions, and never
    # query business rows from a requested workspace before authorization.
    if request.url.path.startswith(("/api/v1/workspaces", "/api/v1/teams")):
        selected = db.get(Workspace, workspace_id)
        if selected is None or selected.organization_id != "default":
            if request.method == "GET" and request.url.path == "/api/v1/workspaces":
                workspace_id = "default"
            else:
                raise HTTPException(403, "workspace access denied")
        return replace(principal, organization_role=org_role, workspace_id=workspace_id)
    role = workspace_role(db, principal, workspace_id)
    if role is None:
        raise HTTPException(403, "workspace access denied")
    return replace(principal, organization_role=org_role, role=role, workspace_id=workspace_id)


def require_organization_admin(request: Request):
    p = request.state.principal
    if (p.organization_role or p.role) != "admin":
        raise HTTPException(403, "organization admin required")


def get_workspace(db, workspace_id):
    obj = db.get(Workspace, workspace_id)
    if obj is None or obj.organization_id != "default":
        raise HTTPException(404, "workspace not found")
    return obj


def get_team(db, team_id):
    obj = db.get(Team, team_id)
    if obj is None or obj.organization_id != "default":
        raise HTTPException(404, "team not found")
    return obj


def get_member(db, user_id, require_active=True):
    query = select(Membership).join(User, User.id == Membership.user_id).where(Membership.organization_id == "default", Membership.user_id == user_id)
    if require_active:
        query = query.where(Membership.is_active.is_(True), User.is_active.is_(True))
    member = db.scalar(query)
    if member is None:
        raise HTTPException(404, "active organization member not found")
    return member


def commit(db):
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "name or grant already exists")


class NameInput(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r".*\S.*")

class GrantInput(BaseModel):
    role: Literal["viewer", "analyst"]
    active: bool = True

class TeamMemberInput(BaseModel):
    active: bool

router = APIRouter()
admin = [Depends(require_organization_admin)]

@router.get("/api/v1/workspaces")
def list_workspaces(request: Request, db: Session = Depends(get_db)):
    p = request.state.principal
    rows = []
    for w in db.scalars(select(Workspace).where(Workspace.organization_id == "default").order_by(Workspace.name)):
        role = workspace_role(db, p, w.id)
        if role is not None:
            rows.append({"id": w.id, "name": w.name, "role": role})
    return rows

@router.post("/api/v1/workspaces", status_code=201, dependencies=admin)
def create_workspace(body: NameInput, db: Session = Depends(get_db)):
    w = Workspace(id=uuid4().hex, organization_id="default", name=body.name.strip())
    db.add(w)
    audit(db, "workspace.created", w.id, w.name)
    commit(db)
    return {"id": w.id, "name": w.name, "role": "admin"}

@router.get("/api/v1/workspaces/{workspace_id}/grants", dependencies=admin)
def list_grants(workspace_id: str, db: Session = Depends(get_db)):
    get_workspace(db, workspace_id)
    direct = db.scalars(select(WorkspaceMember).where(WorkspaceMember.organization_id == "default", WorkspaceMember.workspace_id == workspace_id)).all()
    teams = db.scalars(select(WorkspaceTeam).where(WorkspaceTeam.organization_id == "default", WorkspaceTeam.workspace_id == workspace_id)).all()
    return {"members": [{"userId": m.user_id, "role": m.role, "active": m.active} for m in direct], "teams": [{"teamId": t.team_id, "role": t.role, "active": t.active} for t in teams]}

@router.put("/api/v1/workspaces/{workspace_id}/members/{user_id}", dependencies=admin)
def grant_member(workspace_id: str, user_id: int, body: GrantInput, db: Session = Depends(get_db)):
    get_workspace(db, workspace_id)
    get_member(db, user_id, require_active=body.active)
    row = db.scalar(select(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace_id, WorkspaceMember.organization_id == "default", WorkspaceMember.user_id == user_id))
    if row is None:
        row = WorkspaceMember(organization_id="default", workspace_id=workspace_id, user_id=user_id)
        db.add(row)
    row.role, row.active = body.role, body.active
    audit(db, "workspace.member", workspace_id, f"user={user_id};role={body.role};active={body.active}")
    commit(db)
    return {"userId": user_id, "role": row.role, "active": row.active}

@router.get("/api/v1/teams", dependencies=admin)
def list_teams(db: Session = Depends(get_db)):
    return [{"id": t.id, "name": t.name} for t in db.scalars(select(Team).where(Team.organization_id == "default").order_by(Team.name))]

@router.post("/api/v1/teams", status_code=201, dependencies=admin)
def create_team(body: NameInput, db: Session = Depends(get_db)):
    t = Team(id=uuid4().hex, organization_id="default", name=body.name.strip())
    db.add(t)
    audit(db, "team.created", t.id, t.name)
    commit(db)
    return {"id": t.id, "name": t.name}

@router.get("/api/v1/teams/{team_id}/members", dependencies=admin)
def team_members(team_id: str, db: Session = Depends(get_db)):
    get_team(db, team_id)
    return [{"userId": m.user_id, "active": m.active} for m in db.scalars(select(TeamMember).where(TeamMember.team_id == team_id, TeamMember.organization_id == "default"))]

@router.put("/api/v1/teams/{team_id}/members/{user_id}", dependencies=admin)
def assign_team_member(team_id: str, user_id: int, body: TeamMemberInput, db: Session = Depends(get_db)):
    get_team(db, team_id)
    get_member(db, user_id, require_active=body.active)
    row = db.scalar(select(TeamMember).where(TeamMember.team_id == team_id, TeamMember.user_id == user_id, TeamMember.organization_id == "default"))
    if row is None:
        row = TeamMember(organization_id="default", team_id=team_id, user_id=user_id)
        db.add(row)
    row.active = body.active
    audit(db, "team.member", team_id, f"user={user_id};active={body.active}")
    commit(db)
    return {"userId": user_id, "active": row.active}

@router.put("/api/v1/workspaces/{workspace_id}/teams/{team_id}", dependencies=admin)
def grant_team(workspace_id: str, team_id: str, body: GrantInput, db: Session = Depends(get_db)):
    get_workspace(db, workspace_id)
    get_team(db, team_id)
    row = db.scalar(select(WorkspaceTeam).where(WorkspaceTeam.workspace_id == workspace_id, WorkspaceTeam.team_id == team_id, WorkspaceTeam.organization_id == "default"))
    if row is None:
        row = WorkspaceTeam(organization_id="default", workspace_id=workspace_id, team_id=team_id)
        db.add(row)
    row.role, row.active = body.role, body.active
    audit(db, "workspace.team", workspace_id, f"team={team_id};role={body.role};active={body.active}")
    commit(db)
    return {"teamId": team_id, "role": row.role, "active": row.active}

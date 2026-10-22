"""Platform foundation. Single-install scope; no tenant boundary is claimed."""
from datetime import datetime, timezone
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, select
from sqlalchemy.orm import Mapped, Session, mapped_column
from .database import Base, get_db
from .models import Project, Scan, Finding
from .pipeline.seed import DEMO_SCAN_ID
from .scanners import scanner_status

class Asset(Base):
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    __tablename__ = "platform_assets"
    __table_args__ = (UniqueConstraint("organization_id", "workspace_id", "external_key", name="uq_asset_workspace_key"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    kind: Mapped[str] = mapped_column(String(32))
    external_key: Mapped[str] = mapped_column(String(512))
    owner: Mapped[str] = mapped_column(String(128), default="")
    project_id: Mapped[int | None] = mapped_column(ForeignKey("projects.id"), nullable=True)
    source: Mapped[str] = mapped_column(String(32), default="manual")

class AssetLink(Base):
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    __tablename__ = "platform_asset_links"
    __table_args__ = (UniqueConstraint("source_id", "target_id", "relation"),)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_id: Mapped[str] = mapped_column(ForeignKey("platform_assets.id"))
    target_id: Mapped[str] = mapped_column(ForeignKey("platform_assets.id"))
    relation: Mapped[str] = mapped_column(String(32))
    evidence: Mapped[str] = mapped_column(Text)

class PlatformAudit(Base):
    workspace_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    organization_id: Mapped[str] = mapped_column(String(64), default="default", server_default="default", index=True)
    __tablename__ = "platform_audit"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action: Mapped[str] = mapped_column(String(32))
    object_id: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(128), default="legacy-unattributed", server_default="legacy-unattributed")
    occurred_at: Mapped[str] = mapped_column(String(64))

class AssetInput(BaseModel):
    name: str = Field(min_length=1, max_length=255, pattern=r".*\S.*")
    kind: Literal["repository", "build", "artifact", "deployment", "server", "cloud", "identity", "data", "service"]
    externalKey: str = Field(min_length=1, max_length=512, pattern=r".*\S.*")
    owner: str = Field(default="", max_length=128)
    projectId: int | None = None

class LinkInput(BaseModel):
    sourceId: str
    targetId: str
    relation: Literal["builds", "produces", "deploys", "runs_on", "depends_on", "accesses"]
    evidence: str = Field(min_length=1, max_length=4000, pattern=r".*\S.*")

def audit(db, action, object_id, detail):
    db.add(PlatformAudit(id=uuid4().hex, action=action, object_id=object_id,
                         detail=detail, actor=db.info.get("actor", "local-operator"), occurred_at=datetime.now(timezone.utc).isoformat()))

def serialize(a):
    return dict(id=a.id, name=a.name, kind=a.kind, externalKey=a.external_key,
                workspaceId=a.workspace_id, owner=a.owner, projectId=a.project_id, source=a.source)

def make_router(guard):
    router = APIRouter(prefix="/api/v1/platform", dependencies=[Depends(guard)])

    @router.get("/assets")
    def assets(db: Session = Depends(get_db), offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
        return [serialize(a) for a in db.scalars(select(Asset).order_by(Asset.name, Asset.id).offset(offset).limit(limit))]

    @router.post("/assets", status_code=201)
    def create_asset(body: AssetInput, db: Session = Depends(get_db)):
        if body.projectId is not None and db.get(Project, body.projectId) is None:
            raise HTTPException(404, "project not found")
        from sqlalchemy.exc import IntegrityError
        a = Asset(id=uuid4().hex, name=body.name.strip(), kind=body.kind,
                  external_key=body.externalKey.strip(), owner=body.owner.strip(), project_id=body.projectId)
        db.add(a)
        audit(db, "asset.created", a.id, "manual registration")
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "asset key already exists")
        return serialize(a)

    @router.post("/links", status_code=201)
    def create_link(body: LinkInput, db: Session = Depends(get_db)):
        if body.sourceId == body.targetId:
            raise HTTPException(422, "self links are not allowed")
        for key in (body.sourceId, body.targetId):
            if not db.get(Asset, key):
                raise HTTPException(404, "asset not found")
        from sqlalchemy.exc import IntegrityError
        link = AssetLink(id=uuid4().hex, source_id=body.sourceId, target_id=body.targetId,
                         relation=body.relation, evidence=body.evidence.strip())
        db.add(link)
        audit(db, "link.created", link.id, body.evidence.strip())
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            raise HTTPException(409, "link already exists")
        return {"id": link.id}

    @router.get("/assets/{asset_id}")
    def detail(asset_id: str, request: Request, db: Session = Depends(get_db)):
        a = db.get(Asset, asset_id)
        if a is None:
            raise HTTPException(404, "asset not found")
        links = db.scalars(select(AssetLink).where((AssetLink.source_id == a.id) | (AssetLink.target_id == a.id))).all()
        principal = getattr(request.state, "principal", None)
        service_scopes = principal.scopes if principal and principal.kind == "service-account" else None
        can_read_scans = service_scopes is None or "scans:read" in service_scopes
        can_read_findings = service_scopes is None or "findings:read" in service_scopes
        scans = db.scalars(select(Scan).where(Scan.project_id == a.project_id).order_by(Scan.scanned_at.desc()).limit(25)).all() if a.project_id and can_read_scans else []
        latest = scans[0] if scans else None
        findings = db.scalars(select(Finding).where(Finding.scan_id == latest.id).order_by(Finding.id).limit(200)).all() if latest and can_read_findings else []
        return {"asset": serialize(a), "links": [dict(id=l.id, sourceId=l.source_id, targetId=l.target_id, relation=l.relation, evidence=l.evidence) for l in links],
                "scans": [dict(id=s.id, status=s.status, commit=s.commit_long, demo=s.id == DEMO_SCAN_ID) for s in scans],
                "findings": [dict(id=f.id, title=f.cve, severity=f.severity, status=f.workflow_status, scanId=f.scan_id) for f in findings],
                "findingScope": "latest project scan; association by project, not verified deployment exposure",
                "limits": {"scans": 25, "findings": 200},
                "history": [dict(action=e.action, detail=e.detail, at=e.occurred_at, actor=e.actor) for e in db.scalars(select(PlatformAudit).where(PlatformAudit.object_id.in_([a.id] + [l.id for l in links])).order_by(PlatformAudit.occurred_at.desc()).limit(100))]}

    @router.get("/modules")
    def modules():
        return {"scope": "single-install", "modules": [
            {"id": "assets", "name": "Активы и связи", "status": "implemented", "mode": "native"},
            {"id": "appsec", "name": "Безопасность разработки", "status": "partial", "mode": "native+integration", "engines": scanner_status()},
            {"id":"infra","name":"Инфраструктура и облака","status":"partial","mode":"native+integration","detail":"Импорт инвентаризации и локальный сборщик; внешние системы и сканеры не подключены"},
            {"id":"monitoring","name":"Мониторинг и инциденты","status":"partial","mode":"native+integration","detail":"Выбранные оператором события, обнаружения и инциденты, связи и история решений; поток SIEM и реагирование не подключены"},
            {"id":"governance","name":"Риски и соответствие","status":"partial","mode":"native","detail":"Риски, задачи, основания контролей и согласование исключений; автоматическое применение исключений и аттестация соответствия не реализованы"},
            {"id":"access","name":"Доступ и данные","status":"planned","mode":"integration"}]}
    return router


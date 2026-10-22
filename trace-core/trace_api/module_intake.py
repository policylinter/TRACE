"""Bounded manual module intake. No network fetch, scan or incident synthesis."""
from datetime import datetime, timezone, date
import json
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, field_validator
from sqlalchemy import String, Integer, Boolean, ForeignKey, ForeignKeyConstraint, UniqueConstraint, select, update
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON
from .database import Base, get_db
from .platform import Asset, audit
from .result_contracts import digest
from . import access

class ResultSource(Base):
    __tablename__='module_result_sources'
    __table_args__=(UniqueConstraint('organization_id','workspace_id','id'),ForeignKeyConstraint(['organization_id','workspace_id'],['workspaces.organization_id','workspaces.id']))
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    name:Mapped[str]=mapped_column(String(128))
    module:Mapped[str]=mapped_column(String(32))
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    revision:Mapped[int]=mapped_column(Integer,default=0)

class ModuleResult(Base):
    __tablename__='module_results'
    __table_args__=(UniqueConstraint('source_id','external_id'),ForeignKeyConstraint(['organization_id','workspace_id','source_id'],['module_result_sources.organization_id','module_result_sources.workspace_id','module_result_sources.id']))
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    source_id:Mapped[str]=mapped_column(String(64),index=True)
    asset_id:Mapped[str]=mapped_column(ForeignKey('platform_assets.id'),index=True)
    external_id:Mapped[str]=mapped_column(String(128))
    payload:Mapped[dict]=mapped_column(JSON)
    sha256:Mapped[str]=mapped_column(String(64))
    received_at:Mapped[str]=mapped_column(String(64),index=True)
    received_by:Mapped[str]=mapped_column(String(128))

class ResultWorkflow(Base):
    __tablename__='module_result_workflows'
    __table_args__=(ForeignKeyConstraint(['organization_id','workspace_id'],['workspaces.organization_id','workspaces.id']),)
    result_id:Mapped[str]=mapped_column(ForeignKey('module_results.id'),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    revision:Mapped[int]=mapped_column(Integer,default=0)
    state:Mapped[dict]=mapped_column(JSON)
    updated_at:Mapped[str]=mapped_column(String(64))
    updated_by:Mapped[str]=mapped_column(String(128))

class ResultContextBinding(Base):
    __tablename__='module_result_context_bindings'
    __table_args__=(ForeignKeyConstraint(['organization_id','workspace_id'],['workspaces.organization_id','workspaces.id']),)
    result_id:Mapped[str]=mapped_column(ForeignKey('module_results.id'),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    context_asset_id:Mapped[str]=mapped_column(ForeignKey('asset_supply_chain_contexts.asset_id'),index=True)
    context_sha256:Mapped[str]=mapped_column(String(64))

class ResultWorkflowInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    expectedRevision:int=Field(ge=0,strict=True)
    status:Literal['new','in_progress','resolved','accepted_risk']
    assignee:str=Field(default='',max_length=128)
    dueDate:date|None=None
    note:str=Field(default='',max_length=4000)

def workflow_public(row=None):
    return dict(revision=row.revision if row else 0,
        **(row.state if row else {'status':'new','assignee':'','dueDate':None,'note':''}),
        updatedAt=row.updated_at if row else None,updatedBy=row.updated_by if row else None)

class SourceInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    name:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    module:Literal['appsec','infrastructure','access-data','governance']

class SourceState(BaseModel):
    model_config=ConfigDict(extra='forbid')
    active:bool

class EvidenceInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    label:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    reference:str=Field(min_length=1,max_length=256,pattern=r'.*\S.*')
    sha256:str=Field(pattern=r'^[0-9a-f]{64}$')

class SastLocation(BaseModel):
    model_config=ConfigDict(extra='forbid')
    path:str=Field(min_length=1,max_length=512)
    startLine:int=Field(strict=True,ge=1,le=10000000)
    endLine:int=Field(strict=True,ge=1,le=10000000)

    @field_validator('path')
    @classmethod
    def repository_path(cls,value):
        if (not value.strip() or value.startswith(('/', '\\')) or '\\' in value or ':' in value
                or any(ord(c)<32 or ord(c)==127 for c in value)
                or any(part in ('','.', '..') for part in value.split('/'))):
            raise ValueError('Use a relative repository path with forward slashes')
        return value

class SastOrigin(BaseModel):
    model_config=ConfigDict(extra='forbid')
    adapter:Literal['semgrep-json/1']
    runId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    commit:str=Field(pattern=r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
    reportSha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    reportState:Literal['no_reported_errors','partial','unknown']
    reportedSeverity:Literal['CRITICAL','HIGH','MEDIUM','LOW','INFO','ERROR','WARNING','UNKNOWN']

class SastAnalysis(BaseModel):
    model_config=ConfigDict(extra='forbid')
    kind:Literal['sast']
    scanner:Literal['semgrep']
    location:SastLocation
    origin:SastOrigin|None=None

class IntakeInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    schemaVersion:Literal['trace.intake/1']
    objectType:Literal['finding']
    sourceId:str=Field(min_length=1,max_length=64)
    externalId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    assetId:str=Field(min_length=1,max_length=64)
    ruleId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    title:str=Field(min_length=1,max_length=255,pattern=r'.*\S.*')
    description:str=Field(default='',max_length=4000)
    severity:Literal['critical','high','medium','low','info','unknown']
    observedAt:AwareDatetime
    evidence:list[EvidenceInput]=Field(min_length=1,max_length=20)
    contextAssetId:str|None=Field(default=None,min_length=1,max_length=64)
    contextReason:str|None=Field(default=None,min_length=1,max_length=4000,pattern=r'.*\S.*')
    analysis:SastAnalysis|None=None

    @field_validator('observedAt')
    @classmethod
    def utc(cls,value):
        return value.astimezone(timezone.utc)

def source_public(row):
    return dict(id=row.id,workspaceId=row.workspace_id,name=row.name,module=row.module,active=row.active,mode='manual')

def result_public(row,workflow=None):
    return dict(id=row.id,workspaceId=row.workspace_id,receivedAt=row.received_at,
        receivedBy=row.received_by,sha256=row.sha256,verification='not_attested',payload=row.payload,
        workflow=workflow_public(workflow))

def lock_source(db,source_id):
    changed=db.execute(update(ResultSource).where(ResultSource.id==source_id).values(revision=ResultSource.revision+1)).rowcount
    if changed!=1:raise HTTPException(404,'result source not found')
    return db.scalar(select(ResultSource).where(ResultSource.id==source_id).execution_options(populate_existing=True))

def make_router():
    router=APIRouter(prefix='/api/v1/platform',dependencies=[Depends(access.require_read)])
    @router.get('/result-sources')
    def sources(db=Depends(get_db)):
        return [source_public(row) for row in db.scalars(select(ResultSource).order_by(ResultSource.name,ResultSource.id).limit(200))]

    @router.post('/result-sources',status_code=201,dependencies=[Depends(access.require_admin)])
    def create_source(body:SourceInput,db=Depends(get_db)):
        row=ResultSource(id=uuid4().hex,name=body.name.strip(),module=body.module)
        db.add(row);audit(db,'result-source.created',row.id,'Manual import source; module='+body.module)
        db.commit();return source_public(row)

    @router.put('/result-sources/{source_id}',dependencies=[Depends(access.require_admin)])
    def change_source(source_id:str,body:SourceState,db=Depends(get_db)):
        row=lock_source(db,source_id)
        row.active=body.active
        audit(db,'result-source.state',row.id,'active='+str(body.active))
        db.commit();return source_public(row)

    @router.get('/module-results')
    def results(assetId:str|None=None,contextAssetId:str|None=None,analysisKind:Literal['sast']|None=None,ruleId:str|None=Query(None,max_length=128),path:str|None=Query(None,max_length=512),limit:int=Query(100,ge=1,le=200),offset:int=Query(0,ge=0),db=Depends(get_db)):
        query=select(ModuleResult)
        if analysisKind:query=query.where(ModuleResult.payload['analysis']['kind'].as_string()==analysisKind)
        if ruleId:query=query.where(ModuleResult.payload['ruleId'].as_string()==ruleId)
        if path:query=query.where(ModuleResult.payload['analysis']['location']['path'].as_string()==path)
        if assetId:
            if db.get(Asset,assetId) is None:raise HTTPException(404,'asset not found')
            query=query.where(ModuleResult.asset_id==assetId)
        if contextAssetId:
            if db.get(Asset,contextAssetId) is None:raise HTTPException(404,'context asset not found')
            query=query.where(ModuleResult.id.in_(select(ResultContextBinding.result_id).where(ResultContextBinding.context_asset_id==contextAssetId)))
        rows=db.scalars(query.order_by(ModuleResult.received_at.desc(),ModuleResult.id).offset(offset).limit(limit)).all()
        workflows={row.result_id:row for row in db.scalars(select(ResultWorkflow).where(ResultWorkflow.result_id.in_([row.id for row in rows])))} if rows else {}
        return [result_public(row,workflows.get(row.id)) for row in rows]

    @router.get('/module-results/{result_id}')
    def detail(result_id:str,db=Depends(get_db)):
        row=db.get(ModuleResult,result_id)
        if row is None:raise HTTPException(404,'module result not found')
        from .platform import PlatformAudit
        from .result_retests import related
        events=db.scalars(select(PlatformAudit).where(PlatformAudit.object_id==row.id,
            PlatformAudit.action=='module-result.workflow').order_by(PlatformAudit.occurred_at.desc(),PlatformAudit.id).limit(100))
        return dict(result=result_public(row,db.get(ResultWorkflow,row.id)),
            retests=related(db,row.id),
            history=[dict(id=event.id,at=event.occurred_at,actor=event.actor,change=json.loads(event.detail)) for event in events])

    @router.put('/module-results/{result_id}/workflow',dependencies=[Depends(access.require_analyst)])
    def change_workflow(result_id:str,body:ResultWorkflowInput,db=Depends(get_db)):
        result=db.get(ModuleResult,result_id)
        if result is None:raise HTTPException(404,'module result not found')
        # Shared source lock covers first-write races, even before a workflow row exists.
        # Disabling intake does not prevent the team processing prior reports.
        lock_source(db,result.source_id)
        row=db.get(ResultWorkflow,result_id,populate_existing=True)
        before=workflow_public(row)
        if body.expectedRevision!=before['revision']:
            raise HTTPException(409,'Результат изменён другим участником. Обновите состояние перед сохранением.')
        if body.status in ('accepted_risk','resolved') and not body.note.strip():
            raise HTTPException(422,'Для решения требуется причина')
        if body.status=='accepted_risk' and (body.dueDate is None or body.dueDate<=datetime.now(timezone.utc).date()):
            raise HTTPException(422,'Принятие риска требует будущей даты пересмотра (UTC)')
        state=dict(status=body.status,assignee=body.assignee.strip(),dueDate=body.dueDate.isoformat() if body.dueDate else None,note=body.note.strip())
        if state=={key:before[key] for key in state}:return before
        if row is None:
            row=ResultWorkflow(result_id=result_id,revision=0,state={})
            db.add(row)
        row.revision+=1;row.state=state
        row.updated_at=datetime.now(timezone.utc).isoformat();row.updated_by=db.info.get('actor','system')
        after=workflow_public(row)
        audit(db,'module-result.workflow',result.id,json.dumps({'before':before,'after':after},ensure_ascii=False))
        db.commit();return after

    @router.post('/module-results',status_code=201,dependencies=[Depends(access.require_admin)])
    def ingest(body:IntakeInput,response:Response,db=Depends(get_db)):
        result,created=ingest_result(db,body)
        response.status_code=201 if created else 200
        return result
    return router

def ingest_result(db,body:IntakeInput,*,commit=True,delivery=None):
    source=lock_source(db,body.sourceId)
    if not source.active:raise HTTPException(409,'result source is disabled')
    asset=db.get(Asset,body.assetId)
    if asset is None:raise HTTPException(404,'asset not found')
    if body.analysis:
        if source.module!='appsec' or asset.kind!='repository':
            raise HTTPException(422,'SAST observations require an appsec source and repository asset')
        if body.analysis.location.endLine<body.analysis.location.startLine:
            raise HTTPException(422,'SAST endLine must not precede startLine')
    # Omitting optional null fields preserves the canonical hash of legacy intake/1.
    payload=body.model_dump(mode='json',exclude_none=True)
    context=None
    if bool(body.contextAssetId)!=bool(body.contextReason):
        raise HTTPException(422,'Для привязки нужны contextAssetId и contextReason вместе')
    if body.contextAssetId:
        from .supply_chain import SupplyChainContext,public as context_public
        context_asset=db.get(Asset,body.contextAssetId)
        if context_asset is None:raise HTTPException(404,'context asset not found')
        if asset.kind in ('build','artifact','deployment') and asset.id!=context_asset.id:
            raise HTTPException(422,'Для результата сборки, артефакта или развёртывания укажите контекст этого же актива')
        context=db.get(SupplyChainContext,context_asset.id)
        if context is None:raise HTTPException(409,'Контекст поставки ещё не зафиксирован')
        payload['supplyChainSnapshot']=context_public(context)
    checksum=digest(payload)
    existing=db.scalar(select(ModuleResult).where(ModuleResult.source_id==source.id,ModuleResult.external_id==body.externalId))
    if existing:
        if existing.sha256!=checksum:raise HTTPException(409,'externalId already contains different data; use a new externalId for a new observation')
        return result_public(existing,db.get(ResultWorkflow,existing.id)), False
    row=ModuleResult(id=uuid4().hex,source_id=source.id,asset_id=body.assetId,
        external_id=body.externalId,payload=payload,sha256=checksum,
        received_at=datetime.now(timezone.utc).isoformat(),received_by=db.info.get('actor','system'))
    db.add(row)
    if context:
        db.flush()
        db.add(ResultContextBinding(result_id=row.id,context_asset_id=context.asset_id,context_sha256=context.sha256))
    db.flush()
    from .result_provenance import record_intake
    record_intake(db,row,delivery)
    audit(db,'module-result.received',row.id,'source='+source.id+'; sha256='+checksum)
    db.flush()
    if commit:db.commit()
    return result_public(row), True

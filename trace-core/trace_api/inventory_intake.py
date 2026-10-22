"""Passive, operator-imported infrastructure inventory. No remote scans or deletion."""
from datetime import datetime,timezone,timedelta
from typing import Literal
from uuid import uuid4
import hashlib
from fastapi import APIRouter,Depends,HTTPException,Request,Response,Query
from pydantic import BaseModel,ConfigDict,Field,AwareDatetime,field_validator,model_validator,ValidationError
from sqlalchemy import String,Integer,Boolean,ForeignKey,JSON,UniqueConstraint,select,update,func
from sqlalchemy.orm import Mapped,mapped_column
from sqlalchemy.exc import IntegrityError
from starlette.concurrency import run_in_threadpool
from .database import Base,get_db
from .platform import Asset,audit
from .result_contracts import digest
from . import access

MAX_BYTES=262144
class InventorySource(Base):
    __tablename__='inventory_sources'
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    name:Mapped[str]=mapped_column(String(128))
    active:Mapped[bool]=mapped_column(Boolean,default=True)
    freshness_hours:Mapped[int]=mapped_column(Integer,default=24)
    revision:Mapped[int]=mapped_column(Integer,default=0)

class InventoryRun(Base):
    __tablename__='inventory_runs'
    __table_args__=(UniqueConstraint('source_id','external_id'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    source_id:Mapped[str]=mapped_column(ForeignKey('inventory_sources.id'),index=True)
    external_id:Mapped[str]=mapped_column(String(128))
    observed_at:Mapped[str]=mapped_column(String(64))
    payload:Mapped[dict]=mapped_column(JSON)
    sha256:Mapped[str]=mapped_column(String(64))
    received_at:Mapped[str]=mapped_column(String(64))
    received_by:Mapped[str]=mapped_column(String(128))

class InventoryNode(Base):
    __tablename__='inventory_nodes'
    __table_args__=(UniqueConstraint('source_id','external_id'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    source_id:Mapped[str]=mapped_column(ForeignKey('inventory_sources.id'),index=True)
    external_id:Mapped[str]=mapped_column(String(128))
    asset_id:Mapped[str]=mapped_column(ForeignKey('platform_assets.id'),unique=True)

class InventoryObservation(Base):
    __tablename__='inventory_observations'
    __table_args__=(UniqueConstraint('run_id','node_id'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    run_id:Mapped[str]=mapped_column(ForeignKey('inventory_runs.id'),index=True)
    node_id:Mapped[str]=mapped_column(ForeignKey('inventory_nodes.id'),index=True)
    observed_at:Mapped[str]=mapped_column(String(64))
    payload:Mapped[dict]=mapped_column(JSON)

class StrictInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
class SourceInput(StrictInput):
    name:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    freshnessHours:int=Field(default=24,ge=1,le=720,strict=True)
class SourceSettings(StrictInput):
    active:bool
    freshnessHours:int=Field(ge=1,le=720,strict=True)
class NodeInput(StrictInput):
    externalId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    name:str=Field(min_length=1,max_length=255,pattern=r'.*\S.*')
    kind:Literal['server','cloud']='server'
    owner:str=Field(default='',max_length=128)
    platform:str=Field(default='',max_length=128)
    version:str=Field(default='',max_length=128)
    provider:str=Field(default='',max_length=128)
    region:str=Field(default='',max_length=128)
class CollectionError(StrictInput):
    code:Literal['collection_failed','access_denied','limit_reached','invalid_item','unknown']
    message:str=Field(min_length=1,max_length=400,pattern=r'.*\S.*')
class SnapshotInput(StrictInput):
    schemaVersion:Literal['trace.inventory/1']
    externalRunId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    observedAt:AwareDatetime
    status:Literal['complete','partial','error']
    items:list[NodeInput]=Field(default_factory=list,max_length=100)
    errors:list[CollectionError]=Field(default_factory=list,max_length=20)
    @field_validator('observedAt')
    @classmethod
    def utc(cls,value):return value.astimezone(timezone.utc)
    @model_validator(mode='after')
    def consistent(self):
        if len({item.externalId for item in self.items})!=len(self.items):raise ValueError('duplicate externalId')
        if self.status=='complete' and self.errors:raise ValueError('complete snapshot cannot contain errors')
        if self.status!='complete' and not self.errors:raise ValueError('partial/error requires an error description')
        if self.status=='error' and self.items:raise ValueError('error snapshot cannot contain observations')
        return self

def lock_source(db,id):
    if db.execute(update(InventorySource).where(InventorySource.id==id).values(revision=InventorySource.revision+1)).rowcount!=1:
        raise HTTPException(404,'inventory source not found')
    return db.get(InventorySource,id,populate_existing=True)

def run_public(row):
    return dict(id=row.id,externalRunId=row.external_id,observedAt=row.observed_at,status=row.payload['status'],
        itemCount=len(row.payload['items']),errors=row.payload['errors'],sha256=row.sha256,
        receivedAt=row.received_at,receivedBy=row.received_by)

def source_public(db,row):
    latest=db.scalar(select(InventoryRun).where(InventoryRun.source_id==row.id).order_by(InventoryRun.observed_at.desc()).limit(1))
    return dict(id=row.id,name=row.name,active=row.active,freshnessHours=row.freshness_hours,
        latestAttempt=run_public(latest) if latest else None)

def apply_snapshot(db,source_id,body,response):
    source=lock_source(db,source_id)
    if not source.active:raise HTTPException(409,'inventory source disabled')
    payload=body.model_dump(mode='json');checksum=digest(payload)
    old=db.scalar(select(InventoryRun).where(InventoryRun.source_id==source_id,InventoryRun.external_id==body.externalRunId))
    if old:
        if old.sha256!=checksum:raise HTTPException(409,'externalRunId contains different data')
        response.status_code=200;return run_public(old)
    if body.observedAt>datetime.now(timezone.utc)+timedelta(seconds=30):raise HTTPException(422,'observation time is in the future')
    last=db.scalar(select(InventoryRun).where(InventoryRun.source_id==source_id).order_by(InventoryRun.observed_at.desc()).limit(1))
    if last and body.observedAt<=datetime.fromisoformat(last.observed_at):raise HTTPException(409,'snapshot must be newer than the latest attempt')
    stamp=body.observedAt.isoformat(timespec='microseconds')
    row=InventoryRun(id=uuid4().hex,source_id=source_id,external_id=body.externalRunId,observed_at=stamp,payload=payload,
        sha256=checksum,received_at=datetime.now(timezone.utc).isoformat(),received_by=db.info.get('actor','system'))
    db.add(row);db.flush()
    for item in body.items:
        node=db.scalar(select(InventoryNode).where(InventoryNode.source_id==source_id,InventoryNode.external_id==item.externalId))
        if node is None:
            key='inventory:'+source_id+':'+hashlib.sha256(item.externalId.encode()).hexdigest()
            if db.scalar(select(Asset).where(Asset.external_key==key)):raise HTTPException(409,'inventory asset namespace already occupied')
            asset=Asset(id=uuid4().hex,name=item.name,kind=item.kind,external_key=key,source='inventory',owner='')
            db.add(asset);db.flush()
            node=InventoryNode(id=uuid4().hex,source_id=source_id,external_id=item.externalId,asset_id=asset.id)
            db.add(node);db.flush()
            audit(db,'asset.inventory-created',asset.id,'source='+source_id+'; externalId='+item.externalId)
        else:
            asset=db.get(Asset,node.asset_id)
            if asset is None or asset.kind!=item.kind:raise HTTPException(409,'inventory identity kind changed; use a new externalId')
        db.add(InventoryObservation(id=uuid4().hex,run_id=row.id,node_id=node.id,observed_at=stamp,payload=item.model_dump(mode='json')))
    audit(db,'inventory.snapshot',row.id,'source='+source_id+'; status='+body.status+'; sha256='+checksum)
    try:db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,'inventory identity conflict') from None
    return run_public(row)

def ingest(db,source_id,body,response):
    try:return apply_snapshot(db,source_id,body,response)
    except IntegrityError:
        db.rollback();raise HTTPException(409,'inventory identity conflict') from None

router=APIRouter(prefix='/api/v1/platform/inventory',dependencies=[Depends(access.require_read)])
@router.get('/sources')
def sources(db=Depends(get_db)):
    return [source_public(db,row) for row in db.scalars(select(InventorySource).order_by(InventorySource.name,InventorySource.id).limit(100))]
@router.post('/sources',status_code=201,dependencies=[Depends(access.require_admin)])
def create_source(body:SourceInput,db=Depends(get_db)):
    row=InventorySource(id=uuid4().hex,name=body.name.strip(),freshness_hours=body.freshnessHours)
    db.add(row);audit(db,'inventory.source-created',row.id,'manual snapshot intake');db.commit()
    return source_public(db,row)
@router.put('/sources/{source_id}',dependencies=[Depends(access.require_admin)])
def settings(source_id:str,body:SourceSettings,db=Depends(get_db)):
    row=lock_source(db,source_id);row.active=body.active;row.freshness_hours=body.freshnessHours
    audit(db,'inventory.source-settings',row.id,'active='+str(body.active)+'; freshnessHours='+str(body.freshnessHours))
    db.commit();return source_public(db,row)
@router.post('/sources/{source_id}/snapshots',status_code=201,dependencies=[Depends(access.require_admin)])
async def upload(source_id:str,request:Request,response:Response,db=Depends(get_db)):
    raw=bytearray()
    async for chunk in request.stream():
        if len(raw)+len(chunk)>MAX_BYTES:raise HTTPException(413,'inventory snapshot exceeds 262144 bytes')
        raw.extend(chunk)
    try:body=SnapshotInput.model_validate_json(bytes(raw))
    except ValidationError:raise HTTPException(422,'invalid trace.inventory/1 snapshot') from None
    return await run_in_threadpool(ingest,db,source_id,body,response)
@router.get('/sources/{source_id}')
def detail(source_id:str,limit:int=Query(100,ge=1,le=100),offset:int=Query(0,ge=0),db=Depends(get_db)):
    source=db.get(InventorySource,source_id)
    if source is None:raise HTTPException(404,'inventory source not found')
    nodes=db.scalars(select(InventoryNode).where(InventoryNode.source_id==source_id).order_by(InventoryNode.external_id).offset(offset).limit(limit)).all()
    ids=[node.id for node in nodes]
    ranked=select(InventoryObservation.id,func.row_number().over(partition_by=InventoryObservation.node_id,
        order_by=InventoryObservation.observed_at.desc()).label('position')).where(InventoryObservation.node_id.in_(ids)).subquery()
    latest={row.node_id:row for row in db.scalars(select(InventoryObservation).where(InventoryObservation.id.in_(select(ranked.c.id).where(ranked.c.position==1))))} if ids else {}
    now=datetime.now(timezone.utc);items=[]
    for node in nodes:
        observation=latest.get(node.id)
        age=(now-datetime.fromisoformat(observation.observed_at)).total_seconds() if observation else None
        items.append(dict(assetId=node.asset_id,externalId=node.external_id,observation=observation.payload if observation else None,
            observedAt=observation.observed_at if observation else None,runId=observation.run_id if observation else None,
            freshness='unknown' if age is None else 'current' if age<=source.freshness_hours*3600 else 'stale'))
    runs=db.scalars(select(InventoryRun).where(InventoryRun.source_id==source_id).order_by(InventoryRun.observed_at.desc()).limit(10)).all()
    total=db.scalar(select(func.count()).select_from(InventoryNode).where(InventoryNode.source_id==source_id))
    return dict(source=source_public(db,source),items=items,total=total,offset=offset,limit=limit,
        recentRuns=[run_public(row) for row in runs],checkedAt=now.isoformat(),maxSnapshotBytes=MAX_BYTES)

"""Small, operator-managed cases and governance records. Never a telemetry store."""
from datetime import datetime,timezone,date
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter,Depends,HTTPException,Query,Request,Response
from pydantic import BaseModel,ConfigDict,Field,model_validator
from sqlalchemy import String,Integer,JSON,ForeignKey,UniqueConstraint,select,update
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base,get_db
from . import access
from .platform import Asset,audit
from .models import Finding
from .module_intake import ModuleResult
from .result_contracts import digest

Kind=Literal['event','detection','incident','risk','control','exception','task']
STATES={
 'event':['recorded'], 'detection':['new','investigating','dismissed','escalated'],
 'incident':['open','investigating','contained','resolved','closed'],
 'risk':['open','mitigating','accepted','closed'],
 'control':['not_assessed','in_progress','evidence_recorded','gap'],
 'exception':['requested','approved','rejected','expired'], 'task':['open','in_progress','done','cancelled']}

class SecurityRecord(Base):
    __tablename__='security_records'
    __table_args__=(UniqueConstraint('organization_id','workspace_id','external_key'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    external_key:Mapped[str]=mapped_column(String(128))
    kind:Mapped[str]=mapped_column(String(32),index=True)
    payload:Mapped[dict]=mapped_column(JSON)
    sha256:Mapped[str]=mapped_column(String(64))
    state:Mapped[dict]=mapped_column(JSON)
    revision:Mapped[int]=mapped_column(Integer,default=0)
    created_at:Mapped[str]=mapped_column(String(64))
    created_by:Mapped[str]=mapped_column(String(128))

class SecurityChange(Base):
    __tablename__='security_changes'
    __table_args__=(UniqueConstraint('record_id','revision'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    record_id:Mapped[str]=mapped_column(ForeignKey('security_records.id'),index=True)
    revision:Mapped[int]=mapped_column(Integer)
    change:Mapped[dict]=mapped_column(JSON)
    actor:Mapped[str]=mapped_column(String(128))
    occurred_at:Mapped[str]=mapped_column(String(64))

class SecurityLink(Base):
    __tablename__='security_links'
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    record_id:Mapped[str]=mapped_column(ForeignKey('security_records.id'),index=True)
    target_kind:Mapped[str]=mapped_column(String(32))
    target_id:Mapped[str]=mapped_column(String(64))
    reason:Mapped[str]=mapped_column(String(2000))
    created_by:Mapped[str]=mapped_column(String(128))
    created_at:Mapped[str]=mapped_column(String(64))
    __table_args__=(UniqueConstraint('record_id','target_kind','target_id'),)

class LinkInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    targetKind:Literal['asset','finding','result','record']
    targetId:str=Field(min_length=1,max_length=64)
    reason:str=Field(min_length=1,max_length=2000,pattern=r'.*\S.*')

class CreateInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    kind:Kind
    title:str=Field(min_length=1,max_length=255,pattern=r'.*\S.*')
    description:str=Field(min_length=1,max_length=4000,pattern=r'.*\S.*')
    externalKey:str|None=Field(default=None,min_length=1,max_length=128,pattern=r'.*\S.*')
    sourceReference:str=Field(default='manual',min_length=1,max_length=512)
    severity:Literal['unknown','low','medium','high','critical']='unknown'
    dueDate:date|None=None
    links:list[LinkInput]=Field(default_factory=list,max_length=20)
    @model_validator(mode='after')
    def expiry(self):
        if self.kind=='exception' and (self.dueDate is None or self.dueDate<datetime.now(timezone.utc).date()):
            raise ValueError('Exception requires a current or future expiry date')
        if len({(x.targetKind,x.targetId) for x in self.links})!=len(self.links):raise ValueError('Duplicate links')
        return self

class DecisionInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    expectedRevision:int=Field(strict=True,ge=0)
    status:str=Field(min_length=1,max_length=32)
    owner:str=Field(default='',max_length=128)
    reason:str=Field(min_length=1,max_length=4000,pattern=r'.*\S.*')

TARGETS={'asset':Asset,'finding':Finding,'result':ModuleResult,'record':SecurityRecord}

def target(db,kind,id):
    row=db.get(TARGETS[kind],id)
    if row is None:raise HTTPException(404,'Linked object not found')
    return row

def lock_workspace(db):
    # Acquire the write lock before reading a revision/idempotency key (also on SQLite).
    from .workspace_models import Workspace
    changed=db.execute(update(Workspace).where(Workspace.id==db.info['workspace_id'],Workspace.organization_id==db.info['organization_id']).values(name=Workspace.name)).rowcount
    if changed!=1:raise HTTPException(404,'Workspace not found')

def public(row):
    return dict(id=row.id,kind=row.kind,externalKey=row.external_key,payload=row.payload,sha256=row.sha256,
        state=row.state,revision=row.revision,createdAt=row.created_at,createdBy=row.created_by,
        expired=bool(row.kind=='exception' and row.payload.get('dueDate') and row.payload['dueDate']<datetime.now(timezone.utc).date().isoformat()),
        verification='operator_recorded_not_attested')

def loaded(db,id):
    row=db.get(SecurityRecord,id)
    if row is None:raise HTTPException(404,'Record not found')
    if digest(row.payload)!=row.sha256:raise HTTPException(409,'Record integrity error')
    return row

def link_value(row):
    return dict(id=row.id,targetKind=row.target_kind,targetId=row.target_id,reason=row.reason,createdBy=row.created_by,createdAt=row.created_at)

def add_links(db,row,links):
    for item in links:
        if item.targetKind=='record' and item.targetId==row.id:raise HTTPException(422,'Self links are forbidden')
        target(db,item.targetKind,item.targetId)
        db.add(SecurityLink(id=uuid4().hex,record_id=row.id,target_kind=item.targetKind,target_id=item.targetId,
            reason=item.reason.strip(),created_by=db.info['actor'],created_at=datetime.now(timezone.utc).isoformat()))

router=APIRouter(prefix='/api/v1/platform/security-records',dependencies=[Depends(access.require_read)])
@router.get('/schema')
def schema():return dict(states=STATES,telemetryIngestion=False,automaticResponse=False,exceptionEnforcement=False)

@router.get('')
def listing(kind:Kind|None=None,status:str|None=Query(default=None,max_length=32),q:str=Query(default='',max_length=128),
        offset:int=Query(0,ge=0),limit:int=Query(50,ge=1,le=100),db=Depends(get_db)):
    query=select(SecurityRecord)
    if kind:query=query.where(SecurityRecord.kind==kind)
    if status:query=query.where(SecurityRecord.state['status'].as_string()==status)
    if q:query=query.where(SecurityRecord.payload['title'].as_string().contains(q,autoescape=True))
    return [public(row) for row in db.scalars(query.order_by(SecurityRecord.created_at.desc(),SecurityRecord.id).offset(offset).limit(limit))]

@router.post('',dependencies=[Depends(access.require_analyst)])
def create(body:CreateInput,response:Response,db=Depends(get_db)):
    lock_workspace(db)
    payload=body.model_dump(mode='json',exclude={'externalKey','links'});checksum=digest(payload)
    key=body.externalKey or uuid4().hex
    # Include link context in idempotency, without relying on caller-provided actors.
    payload['initialLinks']=[x.model_dump() for x in body.links];checksum=digest(payload)
    existing=db.scalar(select(SecurityRecord).where(SecurityRecord.external_key==key))
    if existing:
        if existing.sha256!=checksum:raise HTTPException(409,'External key already contains different data')
        return public(existing)
    now=datetime.now(timezone.utc).isoformat()
    row=SecurityRecord(id=uuid4().hex,external_key=key,kind=body.kind,payload=payload,sha256=checksum,
        state=dict(status=STATES[body.kind][0],owner='',reason='Created'),revision=0,created_at=now,created_by=db.info['actor'])
    db.add(row);add_links(db,row,body.links)
    db.add(SecurityChange(id=uuid4().hex,record_id=row.id,revision=0,change=dict(before=None,after=row.state),actor=db.info['actor'],occurred_at=now))
    audit(db,'security.created',row.id,'kind='+row.kind+'; sha256='+checksum)
    from sqlalchemy.exc import IntegrityError
    try:db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,'External key already exists; refresh') from None
    response.status_code=201;return public(row)

@router.get('/related')
def related(targetKind:Literal['asset','finding','result'],targetId:str=Query(min_length=1,max_length=64),db=Depends(get_db)):
    target(db,targetKind,targetId)
    rows=db.scalars(select(SecurityRecord).join(SecurityLink,SecurityLink.record_id==SecurityRecord.id).where(
        SecurityLink.target_kind==targetKind,SecurityLink.target_id==targetId).order_by(SecurityRecord.created_at.desc(),SecurityRecord.id).limit(100)).all()
    return [public(row) for row in rows]

@router.get('/{record_id}')
def detail(record_id:str,db=Depends(get_db)):
    row=loaded(db,record_id)
    history=db.scalars(select(SecurityChange).where(SecurityChange.record_id==row.id).order_by(SecurityChange.revision.desc()).limit(100)).all()
    outgoing=db.scalars(select(SecurityLink).where(SecurityLink.record_id==row.id).order_by(SecurityLink.id).limit(100)).all()
    incoming=db.scalars(select(SecurityLink).where(SecurityLink.target_kind=='record',SecurityLink.target_id==row.id).order_by(SecurityLink.id).limit(100)).all()
    return dict(record=public(row),links=[link_value(x) for x in outgoing],incoming=[dict(recordId=x.record_id,**link_value(x)) for x in incoming],
        historyTotal=row.revision+1,history=[dict(revision=x.revision,change=x.change,actor=x.actor,at=x.occurred_at) for x in history])

@router.put('/{record_id}/decision',dependencies=[Depends(access.require_analyst)])
def decide(record_id:str,body:DecisionInput,request:Request,db=Depends(get_db)):
    lock_workspace(db)
    row=loaded(db,record_id)
    if row.kind=='event':raise HTTPException(409,'Events are immutable observations')
    if body.status not in STATES[row.kind]:raise HTTPException(422,'Status is invalid for this record kind')
    actor=db.info['actor'];admin=request.state.principal.role=='admin'
    if row.kind=='exception':
        if row.state['status']!='requested':raise HTTPException(409,'Exception decision is terminal; create a new request')
        if body.status not in ('approved','rejected'):raise HTTPException(422,'Choose approve or reject')
        if not admin or row.created_by==actor:raise HTTPException(403,'A different administrator must decide an exception')
        if public(row)['expired']:raise HTTPException(409,'Exception request has expired')
    if row.kind=='risk' and body.status=='accepted' and not admin:raise HTTPException(403,'Administrator required for risk acceptance')
    if row.revision!=body.expectedRevision:raise HTTPException(409,'Record changed; refresh')
    if (row.kind,body.status) in {('incident','resolved'),('incident','closed'),('risk','closed'),('task','done'),('control','evidence_recorded')}:
        if not db.scalar(select(SecurityLink.id).where(SecurityLink.record_id==row.id).limit(1)):
            raise HTTPException(409,'Link an evidence record, finding, result or asset with a reason before closing')
    state=dict(status=body.status,owner=body.owner.strip(),reason=body.reason.strip())
    if state==row.state:return public(row)
    before=row.state;now=datetime.now(timezone.utc).isoformat()
    changed=db.execute(update(SecurityRecord).where(SecurityRecord.id==row.id,SecurityRecord.revision==body.expectedRevision).values(state=state,revision=body.expectedRevision+1)).rowcount
    if not changed:db.rollback();raise HTTPException(409,'Record changed; refresh')
    db.add(SecurityChange(id=uuid4().hex,record_id=row.id,revision=body.expectedRevision+1,change=dict(before=before,after=state),actor=actor,occurred_at=now))
    audit(db,'security.decided',row.id,'status='+body.status+'; revision='+str(body.expectedRevision+1))
    db.commit();db.expire_all();return public(loaded(db,record_id))

@router.post('/{record_id}/links',dependencies=[Depends(access.require_analyst)],status_code=201)
def link(record_id:str,body:LinkInput,db=Depends(get_db)):
    lock_workspace(db)
    row=loaded(db,record_id)
    existing=db.scalar(select(SecurityLink).where(SecurityLink.record_id==row.id,SecurityLink.target_kind==body.targetKind,SecurityLink.target_id==body.targetId))
    if existing:raise HTTPException(409,'Link already exists')
    add_links(db,row,[body]);audit(db,'security.linked',row.id,'target='+body.targetKind+':'+body.targetId)
    from sqlalchemy.exc import IntegrityError
    try:db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,'Link already exists') from None
    return dict(recordId=row.id,targetKind=body.targetKind,targetId=body.targetId)

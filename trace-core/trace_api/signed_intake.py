"""Source-bound HMAC intake. Signatures authenticate delivery, not finding truth."""
from datetime import datetime, timezone
import hashlib
import hmac
import os
import re
import time
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, field_validator, ValidationError
from sqlalchemy import String, Boolean, Integer, ForeignKey, select, func
from sqlalchemy.orm import Mapped, mapped_column
from . import access, database
from .database import Base, get_db
from .module_intake import ResultSource, IntakeInput, ingest_result, lock_source
from .platform import audit
from .scoped_settings import validate_ref

MAX_BODY=65536
WINDOW=300

class SourceWebhookConfig(Base):
    __tablename__='source_webhook_configs'
    source_id:Mapped[str]=mapped_column(ForeignKey('module_result_sources.id'),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    enabled:Mapped[bool]=mapped_column(Boolean,default=False)
    secret_ref:Mapped[str]=mapped_column(String(52),default='')

class WebhookDelivery(Base):
    __tablename__='webhook_deliveries'
    source_id:Mapped[str]=mapped_column(ForeignKey('module_result_sources.id'),primary_key=True)
    delivery_id:Mapped[str]=mapped_column(String(128),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    body_sha256:Mapped[str]=mapped_column(String(64))
    issued_at:Mapped[int]=mapped_column(Integer)
    received_at:Mapped[str]=mapped_column(String(64))
    result_id:Mapped[str]=mapped_column(ForeignKey('module_results.id'),index=True)
    result_sha256:Mapped[str]=mapped_column(String(64))

class HookInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    enabled:bool
    secretRef:str=''
    @field_validator('secretRef')
    @classmethod
    def reference(cls,value):return validate_ref(value)

def environment_name(source,reference):
    if not reference:return ''
    validate_ref(reference)
    scope=f'{source.organization_id}:{source.workspace_id}:{source.id}'
    return 'TRACE_HOOK_'+hashlib.sha256(scope.encode()).hexdigest()[:32].upper()+'_'+reference[4:]

def secret(source,config):
    name=environment_name(source,config.secret_ref) if config else ''
    return os.environ.get(name,'') if name else ''

def public(db,source):
    row=db.get(SourceWebhookConfig,source.id)
    count,last=db.execute(select(func.count(),func.max(WebhookDelivery.received_at)).where(WebhookDelivery.source_id==source.id)).one()
    return dict(enabled=bool(row and row.enabled),secretRef=row.secret_ref if row else '',
        environmentName=environment_name(source,row.secret_ref) if row else '',
        secretAvailable=bool(secret(source,row)),sourceActive=source.active,
        endpoint='/api/v1/hooks/results/'+source.id,maxBodyBytes=MAX_BODY,maxAgeSeconds=WINDOW,
        acceptedDeliveryCount=count,lastAcceptedAt=last)

router=APIRouter()
@router.get('/api/v1/platform/result-sources/{source_id}/webhook',dependencies=[Depends(access.require_admin)])
def configuration(source_id:str,db=Depends(get_db)):
    source=db.get(ResultSource,source_id)
    if source is None:raise HTTPException(404,'result source not found')
    return public(db,source)

@router.put('/api/v1/platform/result-sources/{source_id}/webhook',dependencies=[Depends(access.require_admin)])
def configure(source_id:str,body:HookInput,db=Depends(get_db)):
    source=lock_source(db,source_id)
    if body.enabled and not body.secretRef:raise HTTPException(422,'enabled webhook requires an environment reference')
    row=db.get(SourceWebhookConfig,source_id)
    if row is None:
        row=SourceWebhookConfig(source_id=source_id);db.add(row)
    row.enabled=body.enabled;row.secret_ref=body.secretRef
    audit(db,'source.webhook-configured',source_id,'enabled='+str(body.enabled)+'; reference='+body.secretRef)
    db.commit()
    return public(db,source)

def signing_message(source,timestamp,delivery,body):
    return ('v1\n'+source.id+'\n'+source.workspace_id+'\n'+timestamp+'\n'+delivery+'\n').encode()+body

def verify(source,config,timestamp,delivery,signature,body):
    key=secret(source,config)
    age=time.time()-int(timestamp)
    if not(source.active and config and config.enabled and key and -30<=age<=WINDOW):
        raise HTTPException(401,'signed delivery denied')
    expected='v1='+hmac.new(key.encode(),signing_message(source,timestamp,delivery,body),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,signature):raise HTTPException(401,'signed delivery denied')

@router.post('/api/v1/hooks/results/{source_id}',status_code=201)
async def receive(source_id:str,request:Request,response:Response):
    timestamp=request.headers.get('X-Trace-Timestamp','')
    delivery=request.headers.get('X-Trace-Delivery','')
    signature=request.headers.get('X-Trace-Signature','')
    if not(re.fullmatch(r'[0-9]{1,12}',timestamp) and re.fullmatch(r'[A-Za-z0-9._-]{1,128}',delivery) and re.fullmatch(r'v1=[a-f0-9]{64}',signature)):
        raise HTTPException(401,'signed delivery denied')
    raw=bytearray()
    async for chunk in request.stream():
        if len(raw)+len(chunk)>MAX_BODY:raise HTTPException(413,'intake document too large')
        raw.extend(chunk)
    body=bytes(raw)
    return await run_in_threadpool(deliver,source_id,timestamp,delivery,signature,body,response)

def deliver(source_id,timestamp,delivery,signature,body,response):
    # Waiting for a source lock must not block unrelated asynchronous API requests.
    with database.SessionLocal() as db:
        # Bootstrap only routing metadata; all subsequent reads/writes are workspace scoped.
        table=ResultSource.__table__
        scope=db.connection().execute(select(table.c.organization_id,table.c.workspace_id).where(table.c.id==source_id)).first()
        if scope is None or scope.organization_id!='default':raise HTTPException(401,'signed delivery denied')
        db.info.update(organization_id=scope.organization_id,workspace_id=scope.workspace_id,actor='source:'+source_id,principal_kind='signed-source')
        source=db.get(ResultSource,source_id)
        config=db.get(SourceWebhookConfig,source_id)
        verify(source,config,timestamp,delivery,signature,body)
        source=lock_source(db,source_id)
        config=db.get(SourceWebhookConfig,source_id,populate_existing=True)
        verify(source,config,timestamp,delivery,signature,body)
        checksum=hashlib.sha256(body).hexdigest()
        previous=db.get(WebhookDelivery,(source_id,delivery))
        if previous:
            if previous.body_sha256!=checksum:raise HTTPException(409,'delivery ID already contains different data')
            response.status_code=200
            return dict(status='accepted',deliveryId=delivery,resultId=previous.result_id,resultSha256=previous.result_sha256,replayed=True)
        try:document=IntakeInput.model_validate_json(body)
        except ValidationError:raise HTTPException(422,'invalid intake document') from None
        if document.sourceId!=source_id:raise HTTPException(422,'document source does not match signed endpoint')
        result,created=ingest_result(db,document,commit=False,delivery=dict(id=delivery,bodySha256=checksum,issuedAt=int(timestamp)))
        db.add(WebhookDelivery(source_id=source_id,delivery_id=delivery,body_sha256=checksum,issued_at=int(timestamp),
            received_at=datetime.now(timezone.utc).isoformat(),result_id=result['id'],result_sha256=result['sha256']))
        audit(db,'source.webhook-accepted',result['id'],'source='+source_id+'; delivery='+delivery+'; bodySha256='+checksum)
        db.commit()
        response.status_code=201 if created else 200
        return dict(status='accepted',deliveryId=delivery,resultId=result['id'],resultSha256=result['sha256'],replayed=False)

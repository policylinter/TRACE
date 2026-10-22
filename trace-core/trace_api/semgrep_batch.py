"""Atomic, bounded, operator-declared Semgrep conversions; no scanner execution."""
import json
from datetime import datetime,timezone
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter,Depends,HTTPException,Request,Response,Query
from pydantic import BaseModel,ConfigDict,Field,AwareDatetime,ValidationError,model_validator
from sqlalchemy import String,JSON,ForeignKey,UniqueConstraint,select
from sqlalchemy.orm import Mapped,mapped_column
from starlette.concurrency import run_in_threadpool
from .database import Base,get_db
from . import access
from .module_intake import IntakeInput,SastOrigin,ResultSource,ModuleResult,lock_source,ingest_result
from .platform import Asset,audit
from .result_contracts import digest

MAX_BYTES=1048576
class SemgrepBatch(Base):
    __tablename__='semgrep_batches'
    __table_args__=(UniqueConstraint('source_id','run_id'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    source_id:Mapped[str]=mapped_column(ForeignKey('module_result_sources.id'),index=True)
    asset_id:Mapped[str]=mapped_column(ForeignKey('platform_assets.id'))
    run_id:Mapped[str]=mapped_column(String(128))
    sha256:Mapped[str]=mapped_column(String(64))
    receipt:Mapped[dict]=mapped_column(JSON)
    received_at:Mapped[str]=mapped_column(String(64))
    received_by:Mapped[str]=mapped_column(String(128))

class Manifest(BaseModel):
    model_config=ConfigDict(extra='forbid')
    schemaVersion:Literal['trace.semgrep-conversion/1']
    adapter:Literal['semgrep-json/1']
    runId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    commit:str=Field(pattern=r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
    commitVerification:Literal['operator_declared']
    observedAt:AwareDatetime
    sourceId:str=Field(min_length=1,max_length=64)
    assetId:str=Field(min_length=1,max_length=64)
    reportSha256:str=Field(pattern=r'^[0-9a-f]{64}$')
    reportState:Literal['partial','unknown','no_reported_errors']
    inputResults:int=Field(strict=True,ge=0,le=100)
    outputResults:int=Field(strict=True,ge=0,le=100)
    ignoredResults:int=Field(strict=True,ge=0,le=100)
    reportedErrorCount:int=Field(strict=True,ge=0)
    skippedFileCount:int|None=Field(ge=0,strict=True)
    skippedRuleCount:int|None=Field(ge=0,strict=True)
    coverageVerified:Literal[False]
    files:list[str]=Field(max_length=100)
    documentSha256:list[str]=Field(max_length=100)

class BatchInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    manifest:Manifest
    results:list[IntakeInput]=Field(max_length=100)
    @model_validator(mode='after')
    def bindings(self):
        m=self.manifest
        if m.outputResults!=len(self.results) or m.inputResults!=m.outputResults+m.ignoredResults:
            raise ValueError('manifest count mismatch')
        if m.files!=[f'finding-{n+1:03d}.json' for n in range(len(self.results))] or len(m.documentSha256)!=len(self.results):
            raise ValueError('manifest file mapping mismatch')
        if m.reportedErrorCount or m.skippedFileCount or m.skippedRuleCount:
            if m.reportState!='partial':raise ValueError('reported failures require partial')
        elif m.reportState=='no_reported_errors' and (m.skippedFileCount is None or m.skippedRuleCount is None):
            raise ValueError('incomplete summary')
        seen=set()
        for result,checksum in zip(self.results,m.documentSha256):
            origin=result.analysis.origin if result.analysis else None
            if (not origin or result.sourceId!=m.sourceId or result.assetId!=m.assetId
                    or origin.runId!=m.runId or origin.commit!=m.commit or origin.reportSha256!=m.reportSha256
                    or origin.reportState!=m.reportState or result.observedAt!=m.observedAt
                    or result.externalId in seen or result.contextAssetId is not None or result.contextReason is not None):
                raise ValueError('batch context mismatch')
            if not any(e.sha256==m.reportSha256 for e in result.evidence):raise ValueError('missing report reference')
            if digest(result.model_dump(mode='json',exclude_none=True))!=checksum:
                raise ValueError('document checksum mismatch')
            seen.add(result.externalId)
        return self

def public(row):
    return dict(id=row.id,workspaceId=row.workspace_id,sourceId=row.source_id,assetId=row.asset_id,
                runId=row.run_id,sha256=row.sha256,receivedAt=row.received_at,receivedBy=row.received_by,
                verification='not_attested',**row.receipt)

def ingest(db,body,*,commit=True):
    m=body.manifest
    source=lock_source(db,m.sourceId)
    asset=db.get(Asset,m.assetId)
    if asset is None:raise HTTPException(404,'repository asset not found')
    if source.module!='appsec' or asset.kind!='repository':raise HTTPException(422,'appsec source and repository required')
    checksum=digest(body.model_dump(mode='json',exclude_none=False))
    existing=db.scalar(select(SemgrepBatch).where(SemgrepBatch.source_id==source.id,SemgrepBatch.run_id==m.runId))
    if existing:
        if existing.sha256!=checksum:raise HTTPException(409,'runId already contains a different batch')
        return public(existing),False
    if not source.active:raise HTTPException(409,'result source is disabled')
    ids=[];created=0
    for result in body.results:
        row,is_new=ingest_result(db,result,commit=False)
        ids.append(row['id']);created+=int(is_new)
    row=SemgrepBatch(id=uuid4().hex,source_id=source.id,asset_id=asset.id,run_id=m.runId,sha256=checksum,
        received_at=datetime.now(timezone.utc).isoformat(),received_by=db.info.get('actor','system'),
        receipt=dict(manifest=m.model_dump(mode='json'),resultIds=ids,createdCount=created,reusedCount=len(ids)-created))
    db.add(row);db.flush()
    audit(db,'semgrep-batch.received',row.id,'source='+source.id+'; sha256='+checksum)
    if commit:db.commit()
    return public(row),True

router=APIRouter(prefix='/api/v1/platform/semgrep-batches',dependencies=[Depends(access.require_read)])
@router.get('')
def history(limit:int=Query(20,ge=1,le=100),offset:int=Query(0,ge=0),db=Depends(get_db)):
    return [public(row) for row in db.scalars(select(SemgrepBatch).order_by(SemgrepBatch.received_at.desc(),SemgrepBatch.id).offset(offset).limit(limit))]

@router.post('',dependencies=[Depends(access.require_admin)])
async def receive(request:Request,response:Response,db=Depends(get_db)):
    raw=bytearray()
    async for chunk in request.stream():
        raw.extend(chunk)
        if len(raw)>MAX_BYTES:raise HTTPException(413,'batch exceeds 1 MiB')
    try:body=BatchInput.model_validate_json(bytes(raw))
    except (ValidationError,ValueError,RecursionError):raise HTTPException(422,'invalid Semgrep manifest, document hash or context') from None
    value,created=await run_in_threadpool(ingest,db,body)
    response.status_code=201 if created else 200
    return value

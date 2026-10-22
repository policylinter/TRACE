"""Bounded, immutable evidence bytes tied to an existing report's declared hash."""
from datetime import datetime,timezone
import hashlib
from fastapi import APIRouter,Depends,HTTPException,Path,Request,Response
from starlette.concurrency import run_in_threadpool
from sqlalchemy import String,Integer,LargeBinary,ForeignKey,select
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base,get_db
from . import access
from .module_intake import ModuleResult,lock_source
from .platform import audit

MAX_BYTES=65536

class ResultEvidence(Base):
    __tablename__='module_result_evidence'
    result_id:Mapped[str]=mapped_column(ForeignKey('module_results.id'),primary_key=True)
    evidence_index:Mapped[int]=mapped_column(Integer,primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    content:Mapped[bytes]=mapped_column(LargeBinary)
    sha256:Mapped[str]=mapped_column(String(64))
    byte_count:Mapped[int]=mapped_column(Integer)
    stored_at:Mapped[str]=mapped_column(String(64))
    stored_by:Mapped[str]=mapped_column(String(128))

def result(db,result_id):
    row=db.get(ModuleResult,result_id)
    if row is None:raise HTTPException(404,'module result not found')
    return row

def reference(row,index):
    items=row.payload['evidence']
    if index>=len(items):raise HTTPException(404,'evidence reference not found')
    return items[index]

def matches(row,expected):
    return row.byte_count==len(row.content) and row.sha256==expected==hashlib.sha256(row.content).hexdigest()

def public(row,index,item):
    return dict(index=index,label=item['label'],reference=item['reference'],expectedSha256=item['sha256'],
        status=('hash_matches' if matches(row,item['sha256']) else 'integrity_error') if row else 'not_stored',
        byteCount=row.byte_count if row else None,storedAt=row.stored_at if row else None,storedBy=row.stored_by if row else None)

router=APIRouter(prefix='/api/v1/platform/module-results',dependencies=[Depends(access.require_read)])

@router.get('/{result_id}/evidence')
def list_evidence(result_id:str,db=Depends(get_db)):
    report=result(db,result_id)
    rows={row.evidence_index:row for row in db.scalars(select(ResultEvidence).where(ResultEvidence.result_id==result_id))}
    return dict(maxBytes=MAX_BYTES,items=[public(rows.get(index),index,item) for index,item in enumerate(report.payload['evidence'])])

def store(db,result_id,index,content,response):
    report=result(db,result_id);item=reference(report,index)
    lock_source(db,report.source_id)
    checksum=hashlib.sha256(content).hexdigest()
    if checksum!=item['sha256']:raise HTTPException(422,'file SHA-256 does not match the original report')
    previous=db.get(ResultEvidence,(result_id,index))
    if previous:
        if not matches(previous,item['sha256']):raise HTTPException(409,'stored evidence integrity error; replacement is forbidden')
        response.status_code=200
        return public(previous,index,item)
    row=ResultEvidence(result_id=result_id,evidence_index=index,content=content,sha256=checksum,byte_count=len(content),
        stored_at=datetime.now(timezone.utc).isoformat(),stored_by=db.info.get('actor','system'))
    db.add(row)
    audit(db,'module-result.evidence-stored',result_id,'index='+str(index)+'; sha256='+checksum+'; bytes='+str(len(content)))
    db.commit()
    return public(row,index,item)

@router.put('/{result_id}/evidence/{index}',status_code=201,dependencies=[Depends(access.require_analyst)])
async def upload(result_id:str,request:Request,response:Response,index:int=Path(ge=0,le=19),db=Depends(get_db)):
    if request.headers.get('content-type','').split(';')[0].strip().lower()!='application/octet-stream':
        raise HTTPException(415,'send raw bytes as application/octet-stream')
    content=bytearray()
    async for chunk in request.stream():
        if len(content)+len(chunk)>MAX_BYTES:raise HTTPException(413,'evidence exceeds 65536 bytes')
        content.extend(chunk)
    return await run_in_threadpool(store,db,result_id,index,bytes(content),response)

@router.get('/{result_id}/evidence/{index}/content')
def download(result_id:str,index:int=Path(ge=0,le=19),db=Depends(get_db)):
    report=result(db,result_id);item=reference(report,index)
    row=db.get(ResultEvidence,(result_id,index))
    if row is None:raise HTTPException(404,'evidence file not stored')
    if not matches(row,item['sha256']):raise HTTPException(409,'stored evidence integrity error')
    # Never render supplied HTML/SVG/scripts or interpolate caller filenames into headers.
    return Response(content=row.content,media_type='application/octet-stream',headers={
        'Content-Disposition':f'attachment; filename="trace-evidence-{index}.bin"',
        'X-Content-Type-Options':'nosniff','Content-Security-Policy':"sandbox; default-src 'none'",'Cache-Control':'no-store'})

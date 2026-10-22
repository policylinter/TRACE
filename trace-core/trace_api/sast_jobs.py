"""Server-allowlisted SAST jobs with an independent, atomic execution receipt."""
import json,os,shutil,tempfile,time
from pathlib import Path
from uuid import uuid4
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,ConfigDict,Field
from sqlalchemy import String,JSON,ForeignKey,select,update,or_
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base,get_db
from . import access
from .module_intake import ResultSource
from .platform import Asset,audit
from .result_contracts import digest
from .semgrep_batch import BatchInput,SemgrepBatch,ingest
from .job_models import Job,JobAttempt,JobHeartbeat

class SastExecution(Base):
    __tablename__='sast_executions'
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    # Retained independently of terminal Job metadata retention.
    job_id:Mapped[str]=mapped_column(String(64),unique=True)
    attempt_id:Mapped[str]=mapped_column(String(64),unique=True)
    batch_id:Mapped[str]=mapped_column(ForeignKey('semgrep_batches.id'))
    payload:Mapped[dict]=mapped_column(JSON)
    sha256:Mapped[str]=mapped_column(String(64))
    created_at:Mapped[str]=mapped_column(String(64))
    created_by:Mapped[str]=mapped_column(String(128))

class Target(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id:str=Field(pattern=r'^[a-z0-9][a-z0-9_-]{0,63}$')
    name:str=Field(min_length=1,max_length=128)
    workspaceId:str=Field(min_length=1,max_length=64)
    sourceId:str=Field(min_length=1,max_length=64)
    assetId:str=Field(min_length=1,max_length=64)
    repositoryPath:str=Field(min_length=1,max_length=1024)
    rulesPath:str=Field(min_length=1,max_length=1024)
    timeout:int=Field(default=120,strict=True,ge=1,le=600)

def targets():
    name=os.environ.get('TRACE_SAST_TARGETS_FILE')
    if not name:return []
    try:
        path=Path(name)
        if not path.is_absolute():raise ValueError()
        with path.open('rb') as source:raw=source.read(65537)
        if len(raw)>65536:raise ValueError()
        data=json.loads(raw)
        if not isinstance(data,list) or len(data)>20:raise ValueError()
        result=[Target.model_validate(item) for item in data]
        if len({t.id for t in result})!=len(result) or any(not Path(p).is_absolute() for t in result for p in (t.repositoryPath,t.rulesPath)):raise ValueError()
        return result
    except (OSError,ValueError,TypeError):raise HTTPException(503,'SAST target configuration is unavailable') from None

def scanner():
    from .config import SEMGREP_BIN
    return os.environ.get('TRACE_SAST_EXECUTABLE',SEMGREP_BIN)

def choose(db,id):
    target=next((t for t in targets() if t.id==id and t.workspaceId==db.info.get('workspace_id','default')),None)
    if target is None:raise HTTPException(404,'SAST target not found')
    source=db.get(ResultSource,target.sourceId);asset=db.get(Asset,target.assetId)
    if source is None or asset is None:raise HTTPException(404,'SAST source or repository is unavailable')
    if not source.active or source.module!='appsec' or asset.kind!='repository':raise HTTPException(409,'SAST source or repository is not enabled')
    return target

def pin(target):
    try:
        from hashlib import sha256
        with Path(target.rulesPath).open('rb') as source:rules=source.read(65537)
        if not rules or len(rules)>65536 or not Path(target.repositoryPath).is_dir():raise ValueError()
        return digest(dict(target=target.model_dump(),scanner=scanner())),sha256(rules).hexdigest()
    except (OSError,ValueError):raise HTTPException(503,'SAST local inputs are unavailable') from None

def result(row):
    return dict(kind='sast',executionId=row.id,batchId=row.batch_id,reportState=row.payload['execution']['reportState'])

def public(row):
    return {**row.payload, 'id':row.id, 'jobId':row.job_id, 'batchId':row.batch_id,
        'sha256':row.sha256, 'receivedAt':row.created_at, 'receivedBy':row.created_by,
        'verification':'server_recorded_not_attested'}

def run(db,params,job_id,attempt_id,user_id=None):
    from .jobs import authorize_execution
    from tools.run_sast_local import execute
    target=choose(db,params['target_id'])
    config_sha,rules_sha=pin(target)
    if (config_sha,rules_sha)!=(params['config_sha'],params['rules_sha']):raise ValueError('SAST configuration changed')
    db.commit()  # Do not hold a SQLite read transaction during external execution.
    with tempfile.TemporaryDirectory(prefix='trace-sast-job-') as directory:
        output=Path(directory)/'export'
        execution,manifest=execute(repo=target.repositoryPath,commit=params['commit'],rules=target.rulesPath,
            output_dir=output,source_id=target.sourceId,asset_id=target.assetId,run_id='sast-job:'+job_id,
            scanner=scanner(),timeout=target.timeout)
        documents=[json.loads((output/name).read_text(encoding='utf-8')) for name in manifest['files']]
        body=BatchInput.model_validate(dict(manifest=manifest,results=documents))
        authorize_execution(db,db.info['actor'],user_id,require_admin=True)
        current=choose(db,target.id)
        if pin(current)!=(config_sha,rules_sha) or execution['rulesSha256']!=rules_sha:raise ValueError('SAST configuration changed')
        if execution['source']['commit']!=params['commit'] or manifest['commit']!=params['commit']:raise ValueError('SAST commit mismatch')
        job=db.get(Job,job_id);attempt=db.get(JobAttempt,attempt_id)
        if (job is None or job.status!='running' or job.workspace_id!=target.workspaceId or attempt is None
                or attempt.job_id!=job_id or attempt.status!='running'):raise ValueError('SAST job no longer running')
        batch,_=ingest(db,body,commit=False)
        payload=dict(targetId=target.id,configSha256=config_sha,execution=execution,jobId=job_id,attemptId=attempt_id,
            batchId=batch['id'],batchSha256=batch['sha256'])
        row=SastExecution(id=uuid4().hex,job_id=job_id,attempt_id=attempt_id,batch_id=batch['id'],payload=payload,
            sha256=digest(payload),created_at=execution['finishedAt'],created_by=db.info['actor'])
        db.add(row);db.flush();audit(db,'sast.executed',row.id,'batch='+batch['id']+'; sha256='+row.sha256)
        db.commit()
        return dict(jobId=job_id,status='completed',**result(row))

def reconcile(db,job,heartbeat):
    db.info.update(organization_id=job.organization_id,workspace_id=job.workspace_id)
    row=db.scalar(select(SastExecution).where(SastExecution.job_id==job.id))
    if row is None:return 'no-receipt'
    attempt=db.get(JobAttempt,row.attempt_id);batch=db.get(SemgrepBatch,row.batch_id)
    if (attempt is None or attempt.job_id!=job.id or attempt.status!='running' or batch is None or digest(row.payload)!=row.sha256
            or row.payload.get('jobId')!=job.id or row.payload.get('attemptId')!=row.attempt_id
            or row.payload.get('batchId')!=row.batch_id or row.payload.get('batchSha256')!=batch.sha256
            or (heartbeat is not None and heartbeat.attempt_id!=row.attempt_id)):return 'invalid-receipt'
    if heartbeat is not None:
        changed=db.execute(update(JobHeartbeat).where(JobHeartbeat.job_id==job.id,JobHeartbeat.expires_at==heartbeat.expires_at,
            JobHeartbeat.expires_at<time.time()).values(expires_at=0)).rowcount
        if not changed:db.rollback();return 'worker-responsive'
    now=time.time()
    if not db.execute(update(Job).where(Job.id==job.id,Job.status=='running').values(status='completed',finished_at=now,
        params={},result=dict(**result(row),reconciled=True))).rowcount:db.rollback();return 'not-running'
    attempt.status='completed';attempt.finished_at=now
    db.info['actor']='system:job-recovery';audit(db,'job.reconciled',job.id,'Status restored from committed SAST receipt')
    db.commit();return 'reconciled'

class Submission(BaseModel):
    model_config=ConfigDict(extra='forbid')
    targetId:str=Field(min_length=1,max_length=64)
    commit:str=Field(pattern=r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')

router=APIRouter(prefix='/api/v1/platform/sast',dependencies=[Depends(access.require_read)])
@router.get('/targets')
def listing(db=Depends(get_db)):
    available=bool(shutil.which(scanner()) and shutil.which('git'))
    return dict(toolsAvailable=available,targets=[dict(id=t.id,name=t.name,sourceId=t.sourceId,assetId=t.assetId,timeout=t.timeout)
        for t in targets() if t.workspaceId==db.info.get('workspace_id','default')])

@router.post('/jobs',dependencies=[Depends(access.require_admin)],status_code=202)
def submit(body:Submission,db=Depends(get_db)):
    from . import jobs
    target=choose(db,body.targetId)
    if not shutil.which(scanner()) or not shutil.which('git'):raise HTTPException(409,'SAST tools are not installed')
    config_sha,rules_sha=pin(target)
    db.commit()
    return jobs.submit_sast(target_id=target.id,commit=body.commit,config_sha=config_sha,rules_sha=rules_sha,
        actor=db.info['actor'],workspace_id=db.info['workspace_id'],user_id=db.info.get('user_id'))

@router.get('/executions')
def executions(limit:int=Query(20,ge=1,le=100),offset:int=Query(0,ge=0),db=Depends(get_db)):
    return [public(row) for row in db.scalars(select(SastExecution).order_by(SastExecution.created_at.desc(),SastExecution.id).offset(offset).limit(limit))]

@router.get('/jobs')
def job_listing(limit:int=Query(20,ge=1,le=100),offset:int=Query(0,ge=0),db=Depends(get_db)):
    from .job_store import public as job_public
    query=select(Job).where(Job.organization_id==db.info['organization_id'],Job.workspace_id==db.info['workspace_id'],
        or_(Job.params['_kind'].as_string()=='sast',Job.result['kind'].as_string()=='sast'))
    return [job_public(job,db.get(JobHeartbeat,job.id)) for job in db.scalars(query.order_by(Job.created_at.desc(),Job.id).offset(offset).limit(limit))]

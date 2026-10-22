"""Read-only differences between verified, bounded SAST execution batches."""
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import ValidationError
from . import access
from .database import get_db
from .sast_jobs import SastExecution
from .semgrep_batch import SemgrepBatch,BatchInput
from .module_intake import ModuleResult
from .result_contracts import digest


def verified(db,id):
    row=db.get(SastExecution,id)
    if row is None:raise HTTPException(404,'SAST execution not found')
    try:
        payload=row.payload;batch=db.get(SemgrepBatch,row.batch_id)
        if (digest(payload)!=row.sha256 or batch is None or payload['jobId']!=row.job_id
                or payload['attemptId']!=row.attempt_id or payload['batchId']!=row.batch_id
                or payload['batchSha256']!=batch.sha256):raise ValueError()
        ids=batch.receipt['resultIds']
        if len(ids)>100 or len(set(ids))!=len(ids):raise ValueError()
        rows=[db.get(ModuleResult,id) for id in ids]
        if any(r is None or digest(r.payload)!=r.sha256 for r in rows):raise ValueError()
        body=BatchInput.model_validate(dict(manifest=batch.receipt['manifest'],results=[r.payload for r in rows]))
        m=body.manifest
        if (digest(body.model_dump(mode='json',exclude_none=False))!=batch.sha256
                or m.sourceId!=batch.source_id or m.assetId!=batch.asset_id or m.runId!=batch.run_id
                or m.commit!=payload['execution']['source']['commit']
                or m.reportState!=payload['execution']['reportState']):raise ValueError()
        return row,batch,body,rows
    except (ValueError,KeyError,TypeError,ValidationError):
        raise HTTPException(409,'SAST execution evidence is inconsistent') from None


def compare(db,current_id,baseline_id):
    if current_id==baseline_id:raise HTTPException(422,'Choose two different SAST executions')
    current,cb,cd,cr=verified(db,current_id);baseline,bb,bd,br=verified(db,baseline_id)
    def context(row,batch):
        return (row.payload['targetId'],row.payload['configSha256'],row.payload['execution']['rulesSha256'],
            row.payload['execution']['executor'],batch.source_id,batch.asset_id)
    if context(current,cb)!=context(baseline,bb):raise HTTPException(409,'SAST target, configuration, rules or executor differ')
    if (baseline.created_at,baseline.id)>=(current.created_at,current.id):raise HTTPException(422,'Baseline must precede current execution')
    def observations(body,rows):
        result={}
        for document,row in zip(body.results,rows):
            loc=document.analysis.location
            key=(document.ruleId,loc.path,loc.startLine,loc.endLine)
            result.setdefault(key,[]).append(row.id)
        return result
    old=observations(bd,br);new=observations(cd,cr)
    items=[]
    for key in sorted(old.keys()|new.keys()):
        rule,path,start,end=key
        items.append(dict(state='repeated' if key in old and key in new else 'appeared' if key in new else 'not_observed',
            ruleId=rule,path=path,startLine=start,endLine=end,baselineResultIds=old.get(key,[]),currentResultIds=new.get(key,[])))
    return dict(baselineId=baseline.id,currentId=current.id,baselineCommit=bd.manifest.commit,currentCommit=cd.manifest.commit,
        baselineReportState=bd.manifest.reportState,currentReportState=cd.manifest.reportState,
        identity='rule_path_line_range',coverageVerified=False,remediationVerified=False,
        counts={state:sum(i['state']==state for i in items) for state in ('appeared','repeated','not_observed')},items=items)

router=APIRouter(prefix='/api/v1/platform/sast',dependencies=[Depends(access.require_read)])
@router.get('/executions/{execution_id}/compare')
def comparison(execution_id:str,baselineId:str=Query(min_length=1,max_length=64),db=Depends(get_db)):
    return compare(db,execution_id,baselineId)

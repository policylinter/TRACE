"""Versioned, read-only adapter for existing AppSec findings.

Digests attest to representation equality, never provenance or truth.
No event/incident is synthesized from a finding.
"""
from datetime import datetime, timezone
import hashlib
import json
import math
from typing import Any, Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from .database import get_db
from .models import Finding, Scan
from .pipeline.seed import DEMO_SCAN_ID


class EvidenceRecord(BaseModel):
    id: str
    category: Literal['reported_observation','engine_assessment','team_decision']
    method: str
    source: str
    observedAt: None = None
    verification: Literal['not_attested'] = 'not_attested'
    sha256: str
    payload: dict[str,Any]


class FindingResult(BaseModel):
    schemaVersion: Literal['trace.result/1'] = 'trace.result/1'
    objectType: Literal['finding'] = 'finding'
    module: Literal['appsec'] = 'appsec'
    adapter: Literal['legacy-appsec/1'] = 'legacy-appsec/1'
    id: str
    organizationId: str
    workspaceId: str
    scanId: str
    projectId: int | None
    demo: bool
    recordedAt: str | None
    scanRecordedAt: str | None
    observedAt: None = None
    identityBasis: Literal['existing_finding_id'] = 'existing_finding_id'
    reportedConfidence: float | None
    subject: dict[str,Any]
    state: dict[str,Any]
    evidence: list[EvidenceRecord]
    limitations: list[str]
    snapshotSha256: str


def iso(value):
    if not isinstance(value,datetime):return None
    if value.tzinfo is None:value=value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace('+00:00','Z')


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,ensure_ascii=False,
        separators=(',',':'),allow_nan=False).encode()).hexdigest()


def adapt(finding,scan):
    raw=finding.evidence if isinstance(finding.evidence,dict) else {}
    assessment={k:raw[k] for k in ('model','headline','reasoning','deepAnalysis','remediation','clamped') if k in raw}
    reported={k:v for k,v in raw.items() if k not in assessment}
    reported.update(frames=finding.frames or [],dependencyPath=finding.dependency_path or [],
        reachability=finding.reachability,usage=finding.usage or 'unknown',blocker=finding.blocker)
    detail=raw.get('deepAnalysis')
    source=detail.get('source') if isinstance(detail,dict) else None
    # Unknown legacy metadata is not proof that a model or scanner ran.
    assessment_source=source if source in ('rules','model') else 'unknown'
    records=[]
    def add(category,method,source,payload):
        records.append(EvidenceRecord(id=finding.id+':'+category,category=category,
            method=method,source=source,payload=payload,sha256=digest(payload)))
    add('reported_observation','legacy_report_context','legacy-appsec',reported)
    if assessment:add('engine_assessment','reported_engine_output',assessment_source,assessment)
    add('team_decision','current_workflow_state','TRACE workflow',{
        'reviewed':bool(finding.reviewed),'status':finding.workflow_status or 'new',
        'assignee':finding.assignee or '', 'dueDate':finding.due_date or '',
        'note':finding.triage_note or '', 'suppressionReason':finding.suppress_reason})
    confidence=finding.confidence
    if not isinstance(confidence,(int,float)) or not math.isfinite(confidence) or not 0<=confidence<=1:confidence=None
    data=dict(id=finding.id,organizationId=finding.organization_id,workspaceId=finding.workspace_id,
        scanId=scan.id,projectId=scan.project_id,demo=scan.id==DEMO_SCAN_ID,
        recordedAt=iso(finding.created_at),scanRecordedAt=iso(scan.scanned_at),reportedConfidence=confidence,
        subject={'cve':finding.cve,'package':finding.package_name,'version':finding.version,'ecosystem':finding.ecosystem},
        state={'severity':finding.severity,'verdict':finding.verdict,'workflowStatus':finding.workflow_status or 'new'},
        evidence=records,limitations=[
            'Проекция сохранённой находки; новый анализ не выполнялся.',
            'Время наблюдения и происхождение исходного отчёта не удостоверены.',
            'SHA-256 проверяет равенство содержимого, а не достоверность источника.',
            'Отметка проверки и ручной статус не подтверждают устранение уязвимости.',
            'Идентификатор взят из прежней модели; дедупликация между проверками не выполняется.'])
    result=FindingResult(**data,snapshotSha256='')
    result.snapshotSha256=digest(result.model_dump(exclude={'snapshotSha256'}))
    return result


def make_router(guard):
    router=APIRouter(dependencies=[Depends(guard)])
    @router.get('/api/v1/findings/{finding_id}/result',response_model=FindingResult)
    def finding_result(finding_id:str,db=Depends(get_db)):
        finding=db.get(Finding,finding_id)
        if finding is None:raise HTTPException(404,'finding not found')
        scan=db.get(Scan,finding.scan_id)
        if scan is None:raise HTTPException(404,'scan not found')
        return adapt(finding,scan)
    return router

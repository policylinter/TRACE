"""Explicit observation links. A retest association never proves remediation."""
from datetime import datetime, timezone
import json
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import String, Text, ForeignKey, ForeignKeyConstraint, Index, text, select
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base,get_db
from . import access
from .platform import audit

class ResultRetest(Base):
    __tablename__='module_result_retests'
    __table_args__=(ForeignKeyConstraint(['organization_id','workspace_id'],['workspaces.organization_id','workspaces.id']),
        Index('uq_module_retest_active_target','retest_id',unique=True,
            sqlite_where=text('withdrawn_at IS NULL'),postgresql_where=text('withdrawn_at IS NULL')))
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    original_id:Mapped[str]=mapped_column(ForeignKey('module_results.id'),index=True)
    retest_id:Mapped[str]=mapped_column(ForeignKey('module_results.id'),index=True)
    original_sha256:Mapped[str]=mapped_column(String(64))
    retest_sha256:Mapped[str]=mapped_column(String(64))
    reason:Mapped[str]=mapped_column(Text)
    created_at:Mapped[str]=mapped_column(String(64))
    created_by:Mapped[str]=mapped_column(String(128))
    withdrawn_at:Mapped[str|None]=mapped_column(String(64),nullable=True)
    withdrawn_by:Mapped[str|None]=mapped_column(String(128),nullable=True)
    withdrawal_reason:Mapped[str|None]=mapped_column(Text,nullable=True)

class RetestInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    targetResultId:str=Field(min_length=1,max_length=64)
    reason:str=Field(min_length=1,max_length=4000,pattern=r'.*\S.*')

class WithdrawalInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    reason:str=Field(min_length=1,max_length=4000,pattern=r'.*\S.*')

def public(row):
    return dict(id=row.id,originalId=row.original_id,retestId=row.retest_id,
        originalSha256=row.original_sha256,retestSha256=row.retest_sha256,
        reason=row.reason,createdAt=row.created_at,createdBy=row.created_by,
        withdrawnAt=row.withdrawn_at,withdrawnBy=row.withdrawn_by,withdrawalReason=row.withdrawal_reason,
        verification='manual_association')

def related(db,result_id):
    return [public(row) for row in db.scalars(select(ResultRetest).where(
        (ResultRetest.original_id==result_id)|(ResultRetest.retest_id==result_id))
        .order_by(ResultRetest.created_at.desc(),ResultRetest.id).limit(100))]

def make_router():
    router=APIRouter(prefix='/api/v1/platform',dependencies=[Depends(access.require_read)])
    @router.post('/module-results/{result_id}/retests',status_code=201,dependencies=[Depends(access.require_analyst)])
    def associate(result_id:str,body:RetestInput,response:Response,db=Depends(get_db)):
        from .module_intake import ModuleResult,lock_source
        original=db.get(ModuleResult,result_id)
        target=db.get(ModuleResult,body.targetResultId)
        if original is None or target is None:raise HTTPException(404,'module result not found')
        if original.id==target.id:raise HTTPException(422,'Нельзя связать результат с самим собой')
        if (original.asset_id!=target.asset_id or original.source_id!=target.source_id
                or original.payload['ruleId']!=target.payload['ruleId']):
            raise HTTPException(422,'Повторная проверка должна относиться к тому же активу, источнику и правилу')
        def observed(row):return datetime.fromisoformat(row.payload['observedAt'].replace('Z','+00:00'))
        if observed(target)<=observed(original):raise HTTPException(422,'Повторное наблюдение должно быть позже исходного')
        lock_source(db,original.source_id)
        existing=db.scalar(select(ResultRetest).where(ResultRetest.retest_id==target.id,ResultRetest.withdrawn_at.is_(None)))
        reason=body.reason.strip()
        if existing:
            if existing.original_id!=original.id or existing.reason!=reason:
                raise HTTPException(409,'У повторной проверки уже есть исходный результат. Проверьте существующую связь.')
            response.status_code=200;return public(existing)
        row=ResultRetest(id=uuid4().hex,original_id=original.id,retest_id=target.id,
            original_sha256=original.sha256,retest_sha256=target.sha256,reason=reason,
            created_at=datetime.now(timezone.utc).isoformat(),created_by=db.info.get('actor','system'))
        db.add(row)
        audit(db,'module-result.retest',original.id,json.dumps({'linkId':row.id,'targetId':target.id,'reason':reason},ensure_ascii=False))
        db.commit();return public(row)

    @router.post('/module-retests/{link_id}/withdraw',dependencies=[Depends(access.require_analyst)])
    def withdraw(link_id:str,body:WithdrawalInput,db=Depends(get_db)):
        from .module_intake import ModuleResult,lock_source
        row=db.get(ResultRetest,link_id)
        if row is None:raise HTTPException(404,'retest link not found')
        original=db.get(ModuleResult,row.original_id)
        if original is None:raise HTTPException(404,'module result not found')
        lock_source(db,original.source_id)
        db.refresh(row)
        if row.withdrawn_at:
            if row.withdrawal_reason!=body.reason.strip():raise HTTPException(409,'Связь уже отозвана с другой причиной')
            return public(row)
        row.withdrawn_at=datetime.now(timezone.utc).isoformat();row.withdrawn_by=db.info.get('actor','system')
        row.withdrawal_reason=body.reason.strip()
        audit(db,'module-retest.withdrawn',row.original_id,json.dumps({'linkId':row.id,'reason':row.withdrawal_reason},ensure_ascii=False))
        db.commit();return public(row)
    return router

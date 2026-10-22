"""Versioned analyst decisions for a missing observation in a pinned snapshot pair."""
from datetime import datetime,timezone
from typing import Literal
from uuid import uuid4
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import BaseModel,ConfigDict,Field
from sqlalchemy import String,Integer,ForeignKey,JSON,UniqueConstraint,select
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base,get_db
from . import access
from .inventory_intake import InventoryNode,lock_source
from .inventory_comparison import load_pair,summary
from .platform import audit

class InventoryReview(Base):
    __tablename__='inventory_reviews'
    __table_args__=(UniqueConstraint('before_id','after_id','node_id'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    source_id:Mapped[str]=mapped_column(ForeignKey('inventory_sources.id'))
    before_id:Mapped[str]=mapped_column(ForeignKey('inventory_runs.id'))
    after_id:Mapped[str]=mapped_column(ForeignKey('inventory_runs.id'))
    node_id:Mapped[str]=mapped_column(ForeignKey('inventory_nodes.id'))
    before_sha256:Mapped[str]=mapped_column(String(64))
    after_sha256:Mapped[str]=mapped_column(String(64))
    revision:Mapped[int]=mapped_column(Integer,default=0)
    state:Mapped[dict]=mapped_column(JSON)
    updated_at:Mapped[str]=mapped_column(String(64))
    updated_by:Mapped[str]=mapped_column(String(128))

class InventoryReviewEvent(Base):
    __tablename__='inventory_review_events'
    __table_args__=(UniqueConstraint('review_id','revision'),)
    id:Mapped[str]=mapped_column(String(64),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    review_id:Mapped[str]=mapped_column(ForeignKey('inventory_reviews.id'),index=True)
    revision:Mapped[int]=mapped_column(Integer)
    change:Mapped[dict]=mapped_column(JSON)
    actor:Mapped[str]=mapped_column(String(128))
    occurred_at:Mapped[str]=mapped_column(String(64))

class ReviewInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    beforeRunId:str=Field(min_length=1,max_length=64)
    afterRunId:str=Field(min_length=1,max_length=64)
    externalId:str=Field(min_length=1,max_length=128)
    expectedRevision:int=Field(ge=0,strict=True)
    status:Literal['open','in_progress','needs_observation','explained']
    reason:str=Field(min_length=1,max_length=4000,pattern=r'.*\S.*')

def public(row=None):
    return dict(revision=row.revision if row else 0,status=row.state['status'] if row else 'open',
        reason=row.state['reason'] if row else '',updatedAt=row.updated_at if row else None,updatedBy=row.updated_by if row else None)

def context(db,source_id,before,after,external_id):
    previous,current,old,new=load_pair(db,source_id,before,after)
    if old is None or new is None:raise HTTPException(409,'snapshot integrity error; reconciliation unavailable')
    if old.status=='error' or new.status=='error':raise HTTPException(409,'collection error; reconciliation unavailable')
    observed=next((item for item in old.items if item.externalId==external_id),None)
    if observed is None:raise HTTPException(404,'node not present in selected baseline')
    if any(item.externalId==external_id for item in new.items):raise HTTPException(409,'node is present in selected target snapshot')
    node=db.scalar(select(InventoryNode).where(InventoryNode.source_id==source_id,InventoryNode.external_id==external_id))
    if node is None:raise HTTPException(404,'inventory node not found')
    row=db.scalar(select(InventoryReview).where(InventoryReview.before_id==before,InventoryReview.after_id==after,InventoryReview.node_id==node.id))
    if row and (row.before_sha256!=previous.sha256 or row.after_sha256!=current.sha256):
        raise HTTPException(409,'review snapshot binding integrity error')
    return previous,current,new,node,row

router=APIRouter(prefix='/api/v1/platform/inventory',dependencies=[Depends(access.require_read)])
@router.get('/sources/{source_id}/reconciliation')
def detail(source_id:str,before:str=Query(min_length=1,max_length=64),after:str=Query(min_length=1,max_length=64),
        externalId:str=Query(min_length=1,max_length=128),db=Depends(get_db)):
    previous,current,target,node,row=context(db,source_id,before,after,externalId)
    events=db.scalars(select(InventoryReviewEvent).where(InventoryReviewEvent.review_id==row.id).order_by(InventoryReviewEvent.revision.desc()).limit(100)).all() if row else []
    return dict(sourceId=source_id,before=summary(previous),after=summary(current),externalId=externalId,assetId=node.asset_id,
        observationKind='not_in_after' if target.status=='complete' else 'not_observed_partial',review=public(row),
        historyTotal=row.revision if row else 0,history=[dict(id=event.id,revision=event.revision,at=event.occurred_at,actor=event.actor,change=event.change) for event in events])

@router.put('/sources/{source_id}/reconciliation',dependencies=[Depends(access.require_analyst)])
def decide(source_id:str,body:ReviewInput,db=Depends(get_db)):
    # Serialize first writes and updates even when the source is disabled for new intake.
    lock_source(db,source_id)
    previous,current,target,node,row=context(db,source_id,body.beforeRunId,body.afterRunId,body.externalId)
    before=public(row)
    if body.expectedRevision!=before['revision']:raise HTTPException(409,'reconciliation changed; refresh before saving')
    state=dict(status=body.status,reason=body.reason.strip())
    if state=={key:before[key] for key in state}:return before
    if row is None:
        row=InventoryReview(id=uuid4().hex,source_id=source_id,before_id=previous.id,after_id=current.id,node_id=node.id,
            before_sha256=previous.sha256,after_sha256=current.sha256,revision=0,state={})
        db.add(row)
    row.revision+=1;row.state=state;row.updated_at=datetime.now(timezone.utc).isoformat();row.updated_by=db.info.get('actor','system')
    db.flush();after=public(row)
    db.add(InventoryReviewEvent(id=uuid4().hex,review_id=row.id,revision=row.revision,change={'before':before,'after':after},
        actor=db.info.get('actor','system'),occurred_at=row.updated_at))
    audit(db,'inventory.reconciliation',row.id,'revision='+str(row.revision)+'; status='+body.status)
    db.commit();return after

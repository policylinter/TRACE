"""Read-only comparison of two pinned, source-local inventory snapshots."""
from typing import Literal
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException,Query
from pydantic import ValidationError
from sqlalchemy import select
from . import access
from .database import get_db
from .inventory_intake import InventorySource,InventoryRun,InventoryNode,SnapshotInput
from .result_contracts import digest

FIELDS=('name','kind','owner','platform','version','provider','region')

def summary(row):
    return dict(id=row.id,externalRunId=row.external_id,observedAt=row.observed_at,sha256=row.sha256,
        status=row.payload.get('status') if isinstance(row.payload,dict) else None)

def validated(row):
    try:
        document=SnapshotInput.model_validate(row.payload)
        if digest(row.payload)!=row.sha256 or document.externalRunId!=row.external_id or document.observedAt!=datetime.fromisoformat(row.observed_at):return None
        return document
    except (ValidationError,TypeError,ValueError):return None

router=APIRouter(prefix='/api/v1/platform/inventory',dependencies=[Depends(access.require_read)])
def load_pair(db,source_id,before,after):
    if db.get(InventorySource,source_id) is None:raise HTTPException(404,'inventory source not found')
    previous=db.get(InventoryRun,before);current=db.get(InventoryRun,after)
    if previous is None or current is None or previous.source_id!=source_id or current.source_id!=source_id:
        raise HTTPException(404,'inventory snapshot not found')
    if previous.id==current.id:
        raise HTTPException(422,'before must precede after')
    old=validated(previous);new=validated(current)
    if old is not None and new is not None and old.observedAt>=new.observedAt:raise HTTPException(422,'before must precede after')
    return previous,current,old,new

@router.get('/sources/{source_id}/compare')
def compare(source_id:str,before:str,after:str,includeUnchanged:bool=False,
        limit:int=Query(50,ge=1,le=100),offset:int=Query(0,ge=0),db=Depends(get_db)):
    previous,current,old,new=load_pair(db,source_id,before,after)
    base=dict(schemaVersion='trace.inventory-comparison/1',sourceId=source_id,before=summary(previous),after=summary(current),
        checkedAt=datetime.now(timezone.utc).isoformat(),includeUnchanged=includeUnchanged,offset=offset,limit=limit)
    if old is None or new is None:
        return dict(**base,status='unavailable',reason='integrity_error',counts=None,total=0,items=[])
    if old.observedAt>=new.observedAt:raise HTTPException(422,'before must precede after')
    if old.status=='error' or new.status=='error':
        return dict(**base,status='unavailable',reason='collection_error',counts=None,total=0,items=[])
    old_items={item.externalId:item.model_dump(mode='json') for item in old.items}
    new_items={item.externalId:item.model_dump(mode='json') for item in new.items}
    identities=sorted(old_items.keys()|new_items.keys())
    nodes={node.external_id:node.asset_id for node in db.scalars(select(InventoryNode).where(
        InventoryNode.source_id==source_id,InventoryNode.external_id.in_(identities)))} if identities else {}
    counts=dict(only_after=0,changed=0,not_in_after=0,not_observed_partial=0,unchanged=0)
    entries=[]
    for identity in identities:
        a=old_items.get(identity);b=new_items.get(identity)
        changes=[dict(field=key,before=a[key],after=b[key]) for key in FIELDS if a and b and a[key]!=b[key]]
        if a is None:kind='only_after'
        elif b is None:kind='not_in_after' if new.status=='complete' else 'not_observed_partial'
        else:kind='changed' if changes else 'unchanged'
        counts[kind]+=1
        if kind=='unchanged' and not includeUnchanged:continue
        entries.append(dict(externalId=identity,assetId=nodes.get(identity),kind=kind,before=a,after=b,changes=changes))
    return dict(**base,status='compared',reason=None,counts=counts,total=len(entries),items=entries[offset:offset+limit])

"""Server-recorded intake provenance; no retroactive attestation or trust promotion."""
from datetime import datetime,timezone
from fastapi import APIRouter,Depends,HTTPException,Query
from sqlalchemy import String,ForeignKey,JSON,select,func
from sqlalchemy.orm import Mapped,mapped_column
from .database import Base,get_db
from . import access
from .module_intake import ModuleResult,ResultSource
from .signed_intake import WebhookDelivery
from .result_contracts import digest
from .result_evidence import list_evidence

class ResultIntakeReceipt(Base):
    __tablename__='module_result_intake_receipts'
    result_id:Mapped[str]=mapped_column(ForeignKey('module_results.id'),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    record:Mapped[dict]=mapped_column(JSON)

def record_intake(db,row,delivery=None):
    value=dict(method='signed_hmac' if delivery else 'manual',actor=row.received_by,
        receivedAt=row.received_at,reportSha256=row.sha256,sourceId=row.source_id,
        assetId=row.asset_id,externalId=row.external_id)
    if delivery:value['delivery']=dict(delivery)
    db.add(ResultIntakeReceipt(result_id=row.id,record=value))

def receipt_status(db,row,receipt):
    if receipt is None:return 'not_recorded'
    value=receipt.record
    if not isinstance(value,dict):return 'integrity_error'
    expected=dict(actor=row.received_by,receivedAt=row.received_at,reportSha256=row.sha256,
        sourceId=row.source_id,assetId=row.asset_id,externalId=row.external_id)
    if any(value.get(key)!=item for key,item in expected.items()):return 'integrity_error'
    if value.get('method')=='manual':return 'consistent' if 'delivery' not in value else 'integrity_error'
    if value.get('method')!='signed_hmac':return 'integrity_error'
    delivery=value.get('delivery',{})
    if not isinstance(delivery,dict):return 'integrity_error'
    ledger=db.get(WebhookDelivery,(row.source_id,delivery.get('id','')))
    if ledger is None or ledger.result_id!=row.id or ledger.result_sha256!=row.sha256 or ledger.body_sha256!=delivery.get('bodySha256') or ledger.issued_at!=delivery.get('issuedAt'):
        return 'integrity_error'
    return 'consistent'

router=APIRouter(prefix='/api/v1/platform/module-results',dependencies=[Depends(access.require_read)])
@router.get('/{result_id}/provenance')
def provenance(result_id:str,limit:int=Query(20,ge=1,le=50),offset:int=Query(0,ge=0),db=Depends(get_db)):
    row=db.get(ModuleResult,result_id)
    if row is None:raise HTTPException(404,'module result not found')
    source=db.get(ResultSource,row.source_id)
    try:
        report_matches=digest(row.payload)==row.sha256 and all(row.payload.get(key)==value for key,value in
            [('sourceId',row.source_id),('assetId',row.asset_id),('externalId',row.external_id)])
    except (TypeError,ValueError,AttributeError):report_matches=False
    receipt=db.get(ResultIntakeReceipt,row.id)
    query=select(WebhookDelivery).where(WebhookDelivery.result_id==row.id)
    total=db.scalar(select(func.count()).select_from(WebhookDelivery).where(WebhookDelivery.result_id==row.id))
    deliveries=db.scalars(query.order_by(WebhookDelivery.received_at,WebhookDelivery.source_id,WebhookDelivery.delivery_id).offset(offset).limit(limit)).all()
    return dict(schemaVersion='trace.provenance/1',resultId=row.id,checkedAt=datetime.now(timezone.utc).isoformat(),
        report=dict(sha256=row.sha256,status='hash_matches' if report_matches else 'integrity_error'),
        source=dict(id=source.id,name=source.name,module=source.module,active=source.active) if source else None,
        initialIntake=dict(status=receipt_status(db,row,receipt),record=receipt.record if receipt else None),
        signedDeliveries=dict(total=total,offset=offset,limit=limit,items=[dict(id=item.delivery_id,sourceId=item.source_id,
            issuedAt=item.issued_at,receivedAt=item.received_at,bodySha256=item.body_sha256,reportSha256=item.result_sha256,
            status='consistent' if item.source_id==row.source_id and item.result_sha256==row.sha256 else 'integrity_error') for item in deliveries]),
        evidence=list_evidence(row.id,db),attestation='not_performed')

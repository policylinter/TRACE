"""Immutable operator-declared build/artifact/deployment context, not attestation."""
from datetime import datetime,timezone
from typing import Literal,Annotated
from fastapi import APIRouter,Depends,HTTPException,Response
from pydantic import BaseModel,ConfigDict,Field,AwareDatetime,field_validator
from sqlalchemy import String,ForeignKey
from sqlalchemy.orm import Mapped,mapped_column
from sqlalchemy.types import JSON
from sqlalchemy.exc import IntegrityError
from .database import Base,get_db
from .platform import Asset,audit
from .result_contracts import digest
from . import access

class SupplyChainContext(Base):
    __tablename__='asset_supply_chain_contexts'
    asset_id:Mapped[str]=mapped_column(ForeignKey('platform_assets.id'),primary_key=True)
    organization_id:Mapped[str]=mapped_column(String(64),default='default')
    workspace_id:Mapped[str]=mapped_column(String(64),default='default')
    repository_id:Mapped[str]=mapped_column(ForeignKey('platform_assets.id'))
    build_id:Mapped[str|None]=mapped_column(ForeignKey('platform_assets.id'),nullable=True)
    artifact_id:Mapped[str|None]=mapped_column(ForeignKey('platform_assets.id'),nullable=True)
    payload:Mapped[dict]=mapped_column(JSON)
    sha256:Mapped[str]=mapped_column(String(64))
    recorded_at:Mapped[str]=mapped_column(String(64))
    recorded_by:Mapped[str]=mapped_column(String(128))

class ContextBase(BaseModel):
    model_config=ConfigDict(extra='forbid')
    observedAt:AwareDatetime
    evidenceRef:str=Field(min_length=1,max_length=512,pattern=r'.*\S.*')
    @field_validator('observedAt')
    @classmethod
    def utc(cls,value):return value.astimezone(timezone.utc)

class BuildInput(ContextBase):
    kind:Literal['build']
    repositoryAssetId:str=Field(min_length=1,max_length=64)
    commitSha:str=Field(pattern=r'^(?:[0-9a-f]{40}|[0-9a-f]{64})$')
    buildExternalId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')

class ArtifactInput(ContextBase):
    kind:Literal['artifact']
    buildAssetId:str=Field(min_length=1,max_length=64)
    digest:str=Field(pattern=r'^sha256:[0-9a-f]{64}$')

class DeploymentInput(ContextBase):
    kind:Literal['deployment']
    artifactAssetId:str=Field(min_length=1,max_length=64)
    environment:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')
    deploymentExternalId:str=Field(min_length=1,max_length=128,pattern=r'.*\S.*')

ContextInput=Annotated[BuildInput|ArtifactInput|DeploymentInput,Field(discriminator='kind')]

def public(row):
    return dict(assetId=row.asset_id,workspaceId=row.workspace_id,context=row.payload,sha256=row.sha256,
        recordedAt=row.recorded_at,recordedBy=row.recorded_by,verification='operator_declared')

def make_router():
    router=APIRouter(prefix='/api/v1/platform',dependencies=[Depends(access.require_read)])
    @router.get('/assets/{asset_id}/supply-chain')
    def read(asset_id:str,db=Depends(get_db)):
        if db.get(Asset,asset_id) is None:raise HTTPException(404,'asset not found')
        row=db.get(SupplyChainContext,asset_id)
        return {'context':public(row) if row else None}

    @router.post('/assets/{asset_id}/supply-chain',status_code=201,dependencies=[Depends(access.require_analyst)])
    def register(asset_id:str,body:ContextInput,response:Response,db=Depends(get_db)):
        asset=db.get(Asset,asset_id)
        if asset is None:raise HTTPException(404,'asset not found')
        if asset.kind!=body.kind:raise HTTPException(422,'Тип контекста не совпадает с типом актива')
        def asset_of(id,kind):
            value=db.get(Asset,id)
            if value is None:raise HTTPException(404,'referenced asset not found')
            if value.kind!=kind:raise HTTPException(422,'Неверный тип связанного актива')
            return value
        def context_of(id,kind):
            asset_of(id,kind)
            value=db.get(SupplyChainContext,id)
            if value is None:raise HTTPException(409,'Сначала зафиксируйте контекст связанного актива')
            return value
        payload={'schemaVersion':'trace.supply-chain/1',**body.model_dump(mode='json')}
        build_id=artifact_id=None
        if isinstance(body,BuildInput):
            repository_id=asset_of(body.repositoryAssetId,'repository').id
        elif isinstance(body,ArtifactInput):
            build=context_of(body.buildAssetId,'build')
            repository_id=build.repository_id;build_id=build.asset_id
            payload.update(repositoryAssetId=repository_id,commitSha=build.payload['commitSha'],buildContextSha256=build.sha256)
        else:
            artifact=context_of(body.artifactAssetId,'artifact')
            repository_id=artifact.repository_id;build_id=artifact.build_id;artifact_id=artifact.asset_id
            payload.update(repositoryAssetId=repository_id,commitSha=artifact.payload['commitSha'],buildAssetId=build_id,
                digest=artifact.payload['digest'],artifactContextSha256=artifact.sha256,buildContextSha256=artifact.payload['buildContextSha256'])
        checksum=digest(payload)
        def replay(existing):
            if existing.sha256!=checksum:raise HTTPException(409,'Контекст уже зафиксирован. Для другой сборки, артефакта или развёртывания зарегистрируйте новый актив.')
            response.status_code=200;return public(existing)
        existing=db.get(SupplyChainContext,asset.id)
        if existing:return replay(existing)
        row=SupplyChainContext(asset_id=asset.id,repository_id=repository_id,build_id=build_id,artifact_id=artifact_id,
            payload=payload,sha256=checksum,recorded_at=datetime.now(timezone.utc).isoformat(),recorded_by=db.info.get('actor','system'))
        db.add(row);audit(db,'supply-chain.recorded',asset.id,'kind='+body.kind+'; sha256='+checksum)
        try:db.commit()
        except IntegrityError:
            db.rollback()
            existing=db.get(SupplyChainContext,asset.id)
            if existing:return replay(existing)
            raise
        return public(row)
    return router

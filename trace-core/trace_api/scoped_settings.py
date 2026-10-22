"""Workspace settings and a small server-side secret resolver."""
import hashlib
import os
import re
from sqlalchemy import String, ForeignKeyConstraint
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON
from .database import Base

class WorkspaceSetting(Base):
    __tablename__ = 'workspace_settings'
    __table_args__ = (ForeignKeyConstraint(['organization_id','workspace_id'], ['workspaces.organization_id','workspaces.id']),)
    organization_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)

def scope(db):
    organization=db.info.get('organization_id','default')
    workspace=db.info.get('workspace_id','default')
    from .workspace_models import Workspace
    row=db.get(Workspace,workspace)
    if organization!='default' or row is None or row.organization_id!=organization:
        raise ValueError('Invalid settings scope')
    return organization,workspace

def read(db,key):
    organization,workspace=scope(db)
    from .models import AppSetting
    data={}
    legacy=db.get(AppSetting,key) if workspace=='default' else None
    if legacy and isinstance(legacy.value,dict):data.update(legacy.value)
    row=db.get(WorkspaceSetting,(organization,workspace,key))
    if row and isinstance(row.value,dict):data.update(row.value)
    return data

def write(db,key,value):
    organization,workspace=scope(db)
    row=db.get(WorkspaceSetting,(organization,workspace,key))
    if row is None:db.add(WorkspaceSetting(organization_id=organization,workspace_id=workspace,key=key,value=dict(value)))
    else:row.value=dict(value)
    from .platform import audit
    audit(db,'settings.updated',key,'Updated fields: '+', '.join(sorted(value)))
    db.commit()

def validate_ref(value):
    if not isinstance(value,str) or (value and not re.fullmatch(r'env:[A-Z][A-Z0-9_]{0,47}',value)):
        raise ValueError('Ссылка на секрет: env:NAME (заглавные латинские буквы, цифры, подчёркивание)')
    return value

def environment_name(db,reference):
    validate_ref(reference)
    if not reference:return ''
    organization,workspace=scope(db)
    prefix=hashlib.sha256((organization+':'+workspace).encode()).hexdigest()[:16].upper()
    return 'TRACE_WS_'+prefix+'_'+reference[4:]

def resolve_secret(db,reference):
    name=environment_name(db,reference)
    return os.environ.get(name,'') if name else ''

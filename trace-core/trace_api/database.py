"""Database engine and session management."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine, inspect, text, event
from fastapi import Request
from sqlalchemy.orm import with_loader_criteria
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import DATABASE_URL

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True, future=True)

class OrganizationSession(Session):
    """Every request/worker session is bound to the default organization."""

SessionLocal = sessionmaker(bind=engine, class_=OrganizationSession, autoflush=False, autocommit=False, future=True)

@event.listens_for(OrganizationSession, "do_orm_execute")
def _organization_filter(state):
    from .models import Project, Scan, Finding, TriageEvent
    from .platform import Asset, AssetLink, PlatformAudit
    from .scoped_settings import WorkspaceSetting
    from .security_work import SecurityRecord,SecurityChange,SecurityLink
    from .sast_jobs import SastExecution
    from .semgrep_batch import SemgrepBatch
    from .module_intake import ResultSource, ModuleResult, ResultWorkflow, ResultContextBinding
    from .result_retests import ResultRetest
    from .supply_chain import SupplyChainContext
    from .signed_intake import SourceWebhookConfig, WebhookDelivery
    from .result_evidence import ResultEvidence
    from .result_provenance import ResultIntakeReceipt
    from .inventory_intake import InventorySource,InventoryRun,InventoryNode,InventoryObservation
    from .inventory_reconciliation import InventoryReview,InventoryReviewEvent
    organization_id = state.session.info.get("organization_id", "default")
    workspace_id = state.session.info.get("workspace_id", "default")
    for model in (SecurityRecord,SecurityChange,SecurityLink,SastExecution,SemgrepBatch,Project, Scan, Finding, TriageEvent, Asset, AssetLink, PlatformAudit, WorkspaceSetting, ResultSource, ModuleResult, ResultWorkflow, ResultRetest, SupplyChainContext, ResultContextBinding, SourceWebhookConfig, WebhookDelivery, ResultEvidence, ResultIntakeReceipt, InventorySource, InventoryRun, InventoryNode, InventoryObservation, InventoryReview, InventoryReviewEvent):
        if state.is_select:
            state.statement = state.statement.options(with_loader_criteria(model, (model.organization_id == organization_id) & (model.workspace_id == workspace_id), include_aliases=True))
        elif (state.is_update or state.is_delete) and state.bind_mapper is not None and state.bind_mapper.class_ is model:
            if model in (SecurityChange,SecurityLink,SastExecution,SemgrepBatch,ModuleResult,ResultRetest,SupplyChainContext,ResultContextBinding,WebhookDelivery,ResultEvidence,ResultIntakeReceipt,InventoryRun,InventoryNode,InventoryObservation,InventoryReview,InventoryReviewEvent):
                raise ValueError('imported results are immutable')
            if model is SecurityRecord and state.is_delete:raise ValueError('security records cannot be deleted')
            if model is SecurityRecord and state.is_update:
                state.statement=state.statement.where(SecurityRecord.kind!='event')
            if state.is_update:
                changed = {getattr(key, "key", str(key)) for key in (state.statement._values or {})}
                if model is SecurityRecord and changed-{"state","revision"}:
                    raise ValueError("security record observation is immutable")
                if changed & {"organization_id", "workspace_id", "project_id", "scan_id", "source_id", "target_id", "result_id"}:
                    raise ValueError("bulk changes to ownership or references are forbidden")
            state.statement = state.statement.where(model.organization_id == organization_id, model.workspace_id == workspace_id)

@event.listens_for(OrganizationSession, "before_flush")
def _organization_writes(db, context, instances):
    from .models import Project, Scan, Finding, TriageEvent
    from .platform import Asset, AssetLink, PlatformAudit
    from .scoped_settings import WorkspaceSetting
    from .security_work import SecurityRecord,SecurityChange,SecurityLink
    from .sast_jobs import SastExecution
    from .semgrep_batch import SemgrepBatch
    from .module_intake import ResultSource, ModuleResult, ResultWorkflow, ResultContextBinding
    from .result_retests import ResultRetest
    from .supply_chain import SupplyChainContext
    from .signed_intake import SourceWebhookConfig, WebhookDelivery
    from .result_evidence import ResultEvidence
    from .result_provenance import ResultIntakeReceipt
    from .inventory_intake import InventorySource,InventoryRun,InventoryNode,InventoryObservation
    from .inventory_reconciliation import InventoryReview,InventoryReviewEvent
    organization_id = db.info.get("organization_id", "default")
    workspace_id = db.info.get("workspace_id", "default")
    owned = (SecurityRecord,SecurityChange,SecurityLink,SastExecution,SemgrepBatch,Project, Scan, Finding, TriageEvent, Asset, AssetLink, PlatformAudit, WorkspaceSetting, ResultSource, ModuleResult, ResultWorkflow, ResultRetest, SupplyChainContext, ResultContextBinding, SourceWebhookConfig, WebhookDelivery, ResultEvidence, ResultIntakeReceipt, InventorySource, InventoryRun, InventoryNode, InventoryObservation, InventoryReview, InventoryReviewEvent)
    for obj in list(db.new) + list(db.dirty) + list(db.deleted):
        if not isinstance(obj, owned):
            continue
        if isinstance(obj,(SecurityChange,SecurityLink)) and (obj in db.dirty or obj in db.deleted):
            raise ValueError('security history and links are immutable')
        if isinstance(obj,SecurityRecord):
            if obj in db.deleted:raise ValueError('security records cannot be deleted')
            if obj in db.dirty:
                if obj.kind=='event':raise ValueError('events are immutable')
                from sqlalchemy import inspect as inspect_object
                if any(a.history.has_changes() and a.key not in ('state','revision') for a in inspect_object(obj).attrs):
                    raise ValueError('security record observation is immutable')
        if isinstance(obj,InventoryReviewEvent) and (obj in db.dirty or obj in db.deleted):
            raise ValueError("inventory review history is immutable")
        if isinstance(obj,InventoryReview) and obj in db.deleted:
            raise ValueError("inventory reviews cannot be deleted")
        if isinstance(obj,InventoryReview) and obj in db.dirty:
            from sqlalchemy import inspect as inspect_object
            changed={field.key for field in inspect_object(obj).attrs if field.history.has_changes()}
            if changed-{'revision','state','updated_at','updated_by'}:
                raise ValueError("inventory review context is immutable")
        if isinstance(obj,(InventoryRun,InventoryNode,InventoryObservation)) and (obj in db.dirty or obj in db.deleted):
            raise ValueError("inventory history and bindings are immutable")
        if isinstance(obj,ResultIntakeReceipt) and (obj in db.dirty or obj in db.deleted):
            raise ValueError("intake receipts are immutable")
        if isinstance(obj,ResultEvidence) and (obj in db.dirty or obj in db.deleted):
            raise ValueError("stored evidence is immutable")
        if isinstance(obj,WebhookDelivery) and (obj in db.dirty or obj in db.deleted):
            raise ValueError("webhook deliveries are immutable")
        if isinstance(obj,SastExecution) and (obj in db.dirty or obj in db.deleted):
            raise ValueError('SAST execution receipts are immutable')
        if isinstance(obj,SemgrepBatch) and (obj in db.dirty or obj in db.deleted):
            raise ValueError('batch receipts are immutable')
        if isinstance(obj,ModuleResult) and (obj in db.dirty or obj in db.deleted):
            raise ValueError('imported results are immutable')
        if isinstance(obj,SupplyChainContext) and (obj in db.dirty or obj in db.deleted):
            raise ValueError('supply chain context is immutable')
        if isinstance(obj,ResultContextBinding) and (obj in db.dirty or obj in db.deleted):
            raise ValueError('result context binding is immutable')
        if isinstance(obj,ResultRetest) and obj in db.deleted:
            raise ValueError('retest links cannot be deleted')
        if isinstance(obj,ResultRetest) and obj in db.dirty:
            from sqlalchemy import inspect as inspect_object
            changed={field.key for field in inspect_object(obj).attrs if field.history.has_changes()}
            if changed-{'withdrawn_at','withdrawn_by','withdrawal_reason'}:
                raise ValueError('retest link references are immutable')
        if obj.organization_id not in (None, organization_id):
            raise ValueError("organization ownership mismatch")
        if obj.workspace_id not in (None, workspace_id):
            raise ValueError("workspace ownership mismatch")
        obj.organization_id = organization_id
        obj.workspace_id = workspace_id
        if isinstance(obj, TriageEvent) and obj in db.new:
            obj.actor = db.info.get("actor", "system")
        if isinstance(obj, PlatformAudit) and obj in db.new:
            obj.actor = db.info.get("actor", "system")
        # Validate references independently of SQLite foreign-key settings.
        refs = []
        if isinstance(obj,(SecurityChange,SecurityLink)):
            refs.append((SecurityRecord,obj.record_id))
            if obj in db.new:
                if isinstance(obj,SecurityChange):obj.actor=db.info.get('actor','system')
                else:obj.created_by=db.info.get('actor','system')
        if isinstance(obj,SecurityLink):
            from .security_work import TARGETS
            if obj.target_kind not in TARGETS:raise ValueError('invalid security link kind')
            refs.append((TARGETS[obj.target_kind],obj.target_id))

        if isinstance(obj,InventoryReview):
            refs.extend([(InventorySource,obj.source_id),(InventoryRun,obj.before_id),(InventoryRun,obj.after_id),(InventoryNode,obj.node_id)])
            parents=[db.get(InventoryRun,obj.before_id),db.get(InventoryRun,obj.after_id),db.get(InventoryNode,obj.node_id)]
            if any(parent is None or parent.source_id!=obj.source_id for parent in parents):
                raise ValueError("inventory review source mismatch")
        if isinstance(obj,InventoryReviewEvent):
            refs.append((InventoryReview,obj.review_id))
            if obj in db.new:obj.actor=db.info.get('actor','system')
        if isinstance(obj,(InventoryRun,InventoryNode)):
            refs.append((InventorySource,obj.source_id))
        if isinstance(obj,InventoryNode):
            refs.append((Asset,obj.asset_id))
        if isinstance(obj,InventoryObservation):
            refs.extend([(InventoryRun,obj.run_id),(InventoryNode,obj.node_id)])
            run=db.get(InventoryRun,obj.run_id);node=db.get(InventoryNode,obj.node_id)
            if run is None or node is None or run.source_id!=node.source_id:
                raise ValueError("inventory source mismatch")
        if isinstance(obj,(ResultEvidence,ResultIntakeReceipt)):
            refs.append((ModuleResult,obj.result_id))
        if isinstance(obj,(SourceWebhookConfig,WebhookDelivery)):
            refs.append((ResultSource,obj.source_id))
        if isinstance(obj,WebhookDelivery):
            refs.append((ModuleResult,obj.result_id))
        if isinstance(obj,ResultContextBinding):
            refs.extend([(ModuleResult,obj.result_id),(SupplyChainContext,obj.context_asset_id)])
        if isinstance(obj,SupplyChainContext):
            refs.extend((Asset,id) for id in (obj.asset_id,obj.repository_id,obj.build_id,obj.artifact_id) if id)
        if isinstance(obj,ResultRetest):
            refs.extend([(ModuleResult,obj.original_id),(ModuleResult,obj.retest_id)])
        if isinstance(obj,ResultWorkflow):
            refs.append((ModuleResult,obj.result_id))
        if isinstance(obj,SastExecution):
            from .job_models import Job,JobAttempt
            refs.append((SemgrepBatch,obj.batch_id))
            job=db.get(Job,obj.job_id);attempt=db.get(JobAttempt,obj.attempt_id)
            from .result_contracts import digest
            batch=db.get(SemgrepBatch,obj.batch_id)
            if (batch is None or obj.payload.get('jobId')!=obj.job_id or obj.payload.get('attemptId')!=obj.attempt_id
                    or obj.payload.get('batchId')!=obj.batch_id or obj.payload.get('batchSha256')!=batch.sha256 or digest(obj.payload)!=obj.sha256):
                raise ValueError('invalid SAST receipt integrity')
            if job is None or attempt is None or attempt.job_id!=obj.job_id or job.workspace_id!=workspace_id or job.organization_id!=organization_id:
                raise ValueError('invalid SAST job receipt binding')
        if isinstance(obj,SemgrepBatch):
            refs.extend([(Asset,obj.asset_id),(ResultSource,obj.source_id)])
            for result_id in obj.receipt.get('resultIds',[]):
                refs.append((ModuleResult,result_id))
                result=db.get(ModuleResult,result_id)
                if result is None or result.source_id!=obj.source_id or result.asset_id!=obj.asset_id:
                    raise ValueError('batch result binding mismatch')
        if isinstance(obj,ModuleResult):
            refs.extend([(Asset,obj.asset_id),(ResultSource,obj.source_id)])
        if isinstance(obj, (Scan, Asset)) and obj.project_id is not None:
            refs.append((Project, obj.project_id))
        if isinstance(obj, (Finding, TriageEvent)) and obj.scan_id:
            refs.append((Scan, obj.scan_id))
        if isinstance(obj, AssetLink):
            refs.extend([(Asset, obj.source_id), (Asset, obj.target_id)])
        for model, key in refs:
            primary_key=model.__mapper__.primary_key[0].key
            pending = next((x for x in db.new if isinstance(x, model) and getattr(x,primary_key) == key), None)
            target = pending or db.get(model, key)
            if target is None or target.organization_id not in (None, organization_id) or target.workspace_id not in (None, workspace_id):
                raise ValueError("invalid organization reference")



class Base(DeclarativeBase):
    pass


def _migrate() -> None:
    """Additive, idempotent schema migrations for databases created before a
    column existed. ``create_all`` never ALTERs, so newer columns are patched in
    here — keeping existing scans/triage history intact across upgrades."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    additions = {
        "scans": {"project_id": "INTEGER", "scanner_results": "JSON"},
        "triage_events": {"scan_id": "VARCHAR(64)"},
        "findings": {"usage": "VARCHAR(16)", "assignee": "VARCHAR(128)", "workflow_status": "VARCHAR(24)", "due_date": "VARCHAR(10)", "triage_note": "TEXT"},
    }
    for table in ("projects", "scans", "findings", "triage_events", "platform_assets", "platform_asset_links", "platform_audit"):
        additions.setdefault(table, {})["organization_id"] = "VARCHAR(64) NOT NULL DEFAULT 'default'"
        additions[table]["workspace_id"] = "VARCHAR(64) NOT NULL DEFAULT 'default'"
    additions.setdefault("service_accounts", {})["workspace_id"] = "VARCHAR(64) NOT NULL DEFAULT 'default'"
    additions.setdefault("scan_job_outbox", {})["next_delivery_at"] = "FLOAT NOT NULL DEFAULT 0"
    additions.setdefault("platform_audit", {})["actor"] = "VARCHAR(128) NOT NULL DEFAULT 'legacy-unattributed'"
    with engine.begin() as conn:
        for table, columns in additions.items():
            if table not in tables:
                continue
            existing = {col["name"] for col in inspector.get_columns(table)}
            for name, ddl in columns.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def init_db() -> None:
    """Create tables. Idempotent — safe to call on every boot."""
    from . import models  # noqa: F401  (register mappers)
    from . import platform  # noqa: F401 (additive foundation tables)
    from . import access_models  # noqa: F401
    from . import workspace_models  # noqa: F401
    from . import job_models  # noqa: F401
    from . import scoped_settings  # noqa: F401
    from . import module_intake  # noqa: F401
    from . import semgrep_batch  # noqa: F401
    from . import sast_jobs  # noqa: F401
    from . import security_work  # noqa: F401
    from . import result_retests  # noqa: F401
    from . import supply_chain  # noqa: F401
    from . import signed_intake  # noqa: F401
    from . import result_evidence  # noqa: F401
    from . import result_provenance  # noqa: F401
    from . import inventory_intake  # noqa: F401
    from . import inventory_reconciliation  # noqa: F401

    Base.metadata.create_all(bind=engine)
    # create_all does not add indexes to an already existing table.
    for index in signed_intake.WebhookDelivery.__table__.indexes:
        index.create(bind=engine,checkfirst=True)
    _migrate()
    from .workspace_migrations import migrate_asset_identity
    migrate_asset_identity(engine)
    from .workspaces import ensure_default_workspace
    with SessionLocal() as db:
        ensure_default_workspace(db)
    from .job_dispatcher import ensure_control
    ensure_control(SessionLocal)


def get_db(request: Request = None) -> Iterator[Session]:
    db = SessionLocal()
    principal = getattr(request.state, "principal", None) if request else None
    db.info["user_id"] = principal.user_id if principal else None
    db.info.update(organization_id="default", workspace_id=principal.workspace_id if principal else "default", actor=principal.actor if principal else "system", principal_kind=principal.kind if principal else "system")
    try:
        yield db
    finally:
        db.close()

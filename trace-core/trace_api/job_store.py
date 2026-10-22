"""Transactional submission and at-most-once execution (no unsafe scan retries)."""
import threading
import time
from uuid import uuid4
from urllib.parse import urlsplit
from sqlalchemy import select, update, or_
from fastapi import HTTPException
from .job_models import Job, JobAttempt, JobOutbox, JobHeartbeat, RescanJob


def _safe_params(params):
    # This table is not a secret vault. Inline credentials must never be queued.
    def check(value):
        if isinstance(value, dict):
            for key, item in value.items():
                normalized = str(key).lower().replace('_', '').replace('-', '')
                if any(s in normalized for s in ('apikey', 'password', 'authorization', 'token', 'secret')) and item:
                    raise HTTPException(422, 'Inline credentials are not supported in background jobs; configure the integration server-side')
                check(item)
        elif isinstance(value, list):
            for item in value: check(item)
        elif isinstance(value, str) and '://' in value:
            parsed = urlsplit(value)
            if parsed.username or parsed.password or parsed.query or parsed.fragment:
                raise HTTPException(422, 'Credential-bearing or parameterized URLs are not supported in background jobs')
    check(params)
    return dict(params)


def public(job, heartbeat=None, rescan=None):
    from .job_recovery import execution_state
    data = {'jobId': job.id, 'workspaceId': job.workspace_id, 'status': job.status,
            'mode': job.mode, 'createdAt': job.created_at, **(job.result or {})}
    if job.started_at is not None: data['startedAt'] = job.started_at
    if job.finished_at is not None: data['finishedAt'] = job.finished_at
    data.update(execution_state(job, heartbeat))
    data['cancellable'] = job.status == 'queued'
    data['kind'] = 'sast' if (job.params or {}).get('_kind')=='sast' or (job.result or {}).get('kind')=='sast' else ('rescan' if rescan is not None else 'source')
    if rescan is not None: data['targetScanId'] = rescan.scan_id
    if job.status == 'failed' and (job.result or {}).get('terminalReason') == 'cancelled':
        data.update(status='cancelled', executionState='cancelled', requiresReview=False)
    return data


def cancel(factory, job_id, workspace_id, actor):
    """Serialize cancellation with worker admission; running jobs are never killed."""
    from .job_dispatcher import locked_control
    from .platform import audit
    with factory() as db:
        locked_control(db)
        job = db.scalar(select(Job).where(Job.id == job_id, Job.organization_id == 'default', Job.workspace_id == workspace_id))
        if job is None: raise HTTPException(404, 'Задание не найдено')
        if job.status == 'failed' and (job.result or {}).get('terminalReason') == 'cancelled': return public(job, rescan=db.get(RescanJob, job.id))
        if job.status != 'queued': raise HTTPException(409, 'Можно отменить только ожидающее задание. Выполнение уже началось или завершилось.')
        # The legacy CHECK allows four states. Keep the terminal disposition
        # explicit rather than rebuilding a referenced table just for this label.
        job.status = 'failed'
        job.result = {'terminalReason': 'cancelled',**({'kind':'sast'} if (job.params or {}).get('_kind')=='sast' else {})}
        job.finished_at = time.time()
        job.params = {}
        db.info.update(organization_id='default', workspace_id=workspace_id, actor=actor)
        audit(db, 'job.cancelled', job_id, 'Queued job cancelled before execution')
        db.commit()
        return public(job, rescan=db.get(RescanJob, job.id))


def submit(factory, mode, params):
    from .job_dispatcher import locked_control, count_status
    params = _safe_params(params)
    job_id = uuid4().hex
    with factory() as db:
        control = locked_control(db)
        if params.get('_kind') == 'rescan':
            from .models import Scan
            db.info['workspace_id'] = params.get('_workspace_id', 'default')
            if db.get(Scan, params['scan_id']) is None: raise HTTPException(404, 'Проверка не найдена')
            existing = db.scalar(select(Job).join(RescanJob, RescanJob.job_id == Job.id).where(
                Job.organization_id == 'default', Job.workspace_id == db.info['workspace_id'],
                Job.status.in_(('queued', 'running')), RescanJob.scan_id == params['scan_id']))
            if existing: return {'jobId': existing.id, 'mode': existing.mode, 'status': existing.status}
        if params.get('_kind')=='sast':
            existing=db.scalar(select(Job).where(Job.organization_id=='default',Job.workspace_id==params['_workspace_id'],Job.status.in_(('queued','running')),
                Job.params['_kind'].as_string()=='sast',Job.params['target_id'].as_string()==params['target_id'],Job.params['commit'].as_string()==params['commit'],
                Job.params['config_sha'].as_string()==params['config_sha'],Job.params['rules_sha'].as_string()==params['rules_sha']))
            if existing:return {'jobId':existing.id,'mode':existing.mode,'status':existing.status}
        if count_status(db, 'queued') >= control.max_queued:
            raise HTTPException(429, 'Очередь проверок заполнена. Повторите запрос позже.', headers={'Retry-After': '30'})
        db.add(Job(id=job_id, organization_id='default', workspace_id=params.get('_workspace_id', 'default'),
                   mode=mode, status='queued', created_at=time.time(), params=params, result={}))
        db.flush()
        if params.get('_kind') == 'rescan':
            db.add(RescanJob(job_id=job_id, scan_id=params['scan_id'], progress={'phase':'queue', 'progress':0, 'message':'постановка в очередь'}))
        db.add(JobOutbox(job_id=job_id, deliveries=0))
        db.commit()
    dispatch_one(factory, job_id)
    return {'jobId': job_id, 'mode': mode, 'status': 'queued'}


def _start_local(factory, job_id):
    threading.Thread(target=execute, args=(factory, job_id), name='scan-'+job_id, daemon=True).start()


def dispatch_one(factory, job_id, redeliver=False):
    from .job_dispatcher import available, DELIVERY_COOLDOWN
    if not available(factory): return
    with factory() as db:
        outbox = db.get(JobOutbox, job_id)
        job = db.get(Job, job_id)
        if outbox is None or job is None or job.organization_id != 'default' or job.status != 'queued': return
        if outbox.delivered_at is not None and not redeliver: return
        mode = job.mode
        now = time.time()
        deadline = now+DELIVERY_COOLDOWN
        claimed = db.execute(update(JobOutbox).where(JobOutbox.job_id == job_id,
            JobOutbox.next_delivery_at <= now).values(next_delivery_at=deadline)).rowcount
        if not claimed: db.rollback(); return
        db.commit()
    try:
        if mode == 'celery':
            from celery import Celery
            from .config import REDIS_URL
            app = Celery('trace_tasks', broker=REDIS_URL, backend=REDIS_URL)
            app.conf.update(broker_connection_timeout=3, broker_transport_options={'socket_timeout': 3, 'socket_connect_timeout': 3})
            app.send_task('trace_api.worker.run_scan_job', kwargs={'job_id': job_id}, task_id=job_id, retry=False)
        else:
            _start_local(factory, job_id)
    except Exception:
        # An uncertain broker delivery is not converted into a second local run.
        return
    with factory() as db:
        db.execute(update(JobOutbox).where(JobOutbox.job_id == job_id, JobOutbox.next_delivery_at == deadline).values(
            delivered_at=time.time(), deliveries=JobOutbox.deliveries+1))
        db.commit()


def dispatch_pending(factory, limit=100, redeliver=False):
    from .job_dispatcher import available
    limit = min(limit, available(factory))
    if limit <= 0: return 0
    with factory() as db:
        query = select(JobOutbox.job_id).join(Job).where(
            Job.organization_id == 'default', Job.status == 'queued',
            JobOutbox.next_delivery_at <= time.time())
        if not redeliver:
            query = query.where(or_(Job.mode != 'celery', JobOutbox.delivered_at.is_(None)))
        ids = db.scalars(query.order_by(Job.created_at, Job.id).limit(limit)).all()
    for job_id in ids: dispatch_one(factory, job_id, redeliver=True)
    return len(ids)


def status(factory, job_id, workspace_id):
    with factory() as db:
        job = db.scalar(select(Job).where(Job.id == job_id, Job.organization_id == 'default', Job.workspace_id == workspace_id))
        return public(job, db.get(JobHeartbeat, job_id), db.get(RescanJob, job_id)) if job else None


def listing(factory, limit, workspace_id):
    with factory() as db:
        return [public(j, h, r) for j, h, r in db.execute(select(Job, JobHeartbeat, RescanJob).outerjoin(
            JobHeartbeat, JobHeartbeat.job_id == Job.id).outerjoin(RescanJob, RescanJob.job_id == Job.id).where(Job.organization_id == 'default',
            Job.workspace_id == workspace_id).order_by(Job.created_at.desc(), Job.id).limit(limit))]


def execute(factory, job_id):
    from . import jobs
    from .job_recovery import Heartbeat, HEARTBEAT_TTL
    from .job_dispatcher import locked_control, count_status
    attempt_id = uuid4().hex
    now = time.time()
    with factory() as db:
        control = locked_control(db)
        candidate = db.get(Job, job_id)
        if candidate is None or candidate.organization_id != 'default' or candidate.status != 'queued':
            db.rollback()
            return {'jobId': job_id, 'status': 'not-claimed'}
        if count_status(db, 'running') >= control.max_running:
            # This message may be acknowledged by Celery; return it to the
            # durable outbox. Changing the deadline fences a late publish ack.
            db.execute(update(JobOutbox).where(JobOutbox.job_id == job_id).values(delivered_at=None, next_delivery_at=0))
            db.commit()
            return {'jobId': job_id, 'status': 'capacity-wait'}
        # Atomic compare-and-set protects against duplicate threads, messages and API instances.
        claimed = db.execute(update(Job).where(Job.id == job_id, Job.organization_id == 'default', Job.status == 'queued').values(status='running', started_at=now)).rowcount
        if not claimed:
            db.rollback()
            return {'jobId': job_id, 'status': 'not-claimed'}
        job = db.get(Job, job_id)
        params = dict(job.params)
        db.add(JobAttempt(id=attempt_id, job_id=job_id, started_at=now, status='running'))
        db.flush()
        db.add(JobHeartbeat(job_id=job_id, attempt_id=attempt_id, heartbeat_at=now, expires_at=now+HEARTBEAT_TTL))
        db.commit()
    # Use a fresh session for permission checks and pipeline commits.
    with Heartbeat(factory, job_id, attempt_id):
        result = jobs._run_pipeline(job_id, params, factory=factory, attempt_id=attempt_id)
    if params.get('_kind')=='sast':result['kind']='sast'
    with factory() as db:
        finished = time.time()
        changed = db.execute(update(Job).where(Job.id == job_id, Job.status == 'running').values(
            status=result['status'], finished_at=finished, params={},
            result={k: v for k, v in result.items() if k not in ('jobId', 'status')})).rowcount
        if not changed:
            db.rollback()
            return {'jobId': job_id, 'status': 'already-finalized'}
        attempt = db.get(JobAttempt, attempt_id)
        attempt.status = result['status']
        attempt.finished_at = finished
        db.commit()
    return result

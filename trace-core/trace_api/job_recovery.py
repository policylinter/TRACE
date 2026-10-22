"""Liveness observations and conservative reconciliation, never scan retries."""
import threading
import time
from sqlalchemy import select, update
from .job_models import Job, JobAttempt, JobHeartbeat, JobReceipt

HEARTBEAT_INTERVAL = 15
HEARTBEAT_TTL = 120


def renew(factory, job_id, attempt_id):
    with factory() as db:
        running = select(Job.id).where(Job.id == job_id, Job.status == 'running')
        now = time.time()
        changed = db.execute(update(JobHeartbeat).where(
            JobHeartbeat.job_id == job_id, JobHeartbeat.attempt_id == attempt_id,
            JobHeartbeat.job_id.in_(running)).values(heartbeat_at=now, expires_at=now+HEARTBEAT_TTL)).rowcount
        db.commit()
        return bool(changed)


class Heartbeat:
    def __init__(self, factory, job_id, attempt_id):
        self.factory, self.job_id, self.attempt_id = factory, job_id, attempt_id
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, name='heartbeat-'+job_id, daemon=True)

    def run(self):
        while not self.stop_event.wait(HEARTBEAT_INTERVAL):
            try:
                if not renew(self.factory, self.job_id, self.attempt_id): return
            except Exception:
                # A DB outage or write lock is uncertainty, not proof the worker died.
                continue

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop_event.set()
        self.thread.join(timeout=1)


def record_receipt(db, scan, scanners):
    job_id, attempt_id = db.info.get('job_id'), db.info.get('job_attempt_id')
    if not job_id or not attempt_id: return
    job, attempt = db.get(Job, job_id), db.get(JobAttempt, attempt_id)
    if (job is None or attempt is None or attempt.job_id != job_id or job.status != 'running'
            or scan.workspace_id != job.workspace_id or scan.organization_id != job.organization_id):
        raise ValueError('invalid job receipt context')
    db.add(JobReceipt(job_id=job_id, attempt_id=attempt_id, scan_id=scan.id,
                      scan_status=scan.status, scanners=list(scanners), saved_at=time.time()))


def execution_state(job, heartbeat, now=None):
    if job.status != 'running': return {'executionState': job.status, 'requiresReview': False}
    if heartbeat is None:
        return {'executionState': 'unknown', 'requiresReview': True}
    now = time.time() if now is None else now
    lost = heartbeat.expires_at < now
    return {'executionState': 'heartbeat-lost' if lost else 'responsive',
            'requiresReview': lost, 'lastHeartbeatAt': heartbeat.heartbeat_at,
            'heartbeatExpiresAt': heartbeat.expires_at}


def reconcile(factory, job_id, workspace_id='default'):
    """Repair terminal state only from a committed, scoped scan receipt."""
    from .models import Scan
    with factory() as db:
        job = db.get(Job, job_id)
        if job is None or job.organization_id != 'default' or job.workspace_id != workspace_id: return 'not-found'
        if job.status != 'running': return 'not-running'
        heartbeat = db.get(JobHeartbeat, job_id)
        if heartbeat is not None and heartbeat.expires_at >= time.time(): return 'worker-responsive'
        if (job.params or {}).get('_kind')=='sast':
            from .sast_jobs import reconcile as reconcile_sast
            return reconcile_sast(db,job,heartbeat)
        receipt = db.get(JobReceipt, job_id)
        if receipt is None: return 'no-receipt'
        attempt = db.get(JobAttempt, receipt.attempt_id)
        if attempt is None or attempt.job_id != job_id or attempt.status != 'running': return 'invalid-receipt'
        if heartbeat is not None and heartbeat.attempt_id != receipt.attempt_id: return 'invalid-receipt'
        db.info.update(organization_id=job.organization_id, workspace_id=job.workspace_id)
        scan = db.get(Scan, receipt.scan_id)
        if scan is None or scan.organization_id != job.organization_id or scan.workspace_id != job.workspace_id:
            return 'result-unavailable'
        # Freeze the heartbeat row before changing state. A concurrent renew wins
        # or loses this comparison; a healthy heartbeat cannot be overwritten.
        if heartbeat is not None:
            frozen = db.execute(update(JobHeartbeat).where(JobHeartbeat.job_id == job_id,
                JobHeartbeat.expires_at == heartbeat.expires_at, JobHeartbeat.expires_at < time.time()
                ).values(expires_at=0)).rowcount
            if not frozen: db.rollback(); return 'worker-responsive'
        now = time.time()
        result = {'scanId': receipt.scan_id, 'scanStatus': receipt.scan_status,
                  'scanners': receipt.scanners, 'sourceMeta': {}, 'reconciled': True}
        changed = db.execute(update(Job).where(Job.id == job_id, Job.status == 'running').values(
            status='completed', finished_at=now, result=result, params={})).rowcount
        if not changed: db.rollback(); return 'not-running'
        attempt.status, attempt.finished_at = 'completed', now
        from .platform import audit
        db.info['actor'] = 'system:job-recovery'
        audit(db, 'job.reconciled', job_id, 'Status restored from committed scan receipt')
        db.commit()
        return 'reconciled'

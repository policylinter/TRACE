import time
import unittest
from unittest.mock import patch
from sqlalchemy import select, func
import test_access as fixtures
from trace_api import job_retention as retention
from trace_api.job_models import Job, JobAttempt, JobOutbox, JobHeartbeat, JobReceipt, RescanJob
from trace_api.models import Scan, Finding
from trace_api.platform import PlatformAudit


class RetentionTests(unittest.TestCase):
    setUp = fixtures.AccessTests.setUp
    tearDown = fixtures.AccessTests.tearDown
    headers = fixtures.AccessTests.headers

    def seed(self, name='old', status='completed', age=100, children=False, cancelled=False):
        finished = time.time()-age*86400
        with self.factory() as db:
            db.add(Job(id=name, workspace_id='default', status=status, mode='local',
                created_at=finished-10, finished_at=finished, params={},
                result={'terminalReason':'cancelled'} if cancelled else {}))
            db.flush()
            if children:
                db.add(JobAttempt(id=name+'-attempt', job_id=name, started_at=finished-5,
                    finished_at=finished, status=status)); db.flush()
                db.add_all([JobOutbox(job_id=name),
                    JobHeartbeat(job_id=name, attempt_id=name+'-attempt', heartbeat_at=finished, expires_at=finished+120),
                    JobReceipt(job_id=name, attempt_id=name+'-attempt', scan_id='scan-8f21a3c', scan_status='completed', scanners=[], saved_at=finished),
                    RescanJob(job_id=name, scan_id='scan-8f21a3c', progress={})])
            db.commit()

    def plan(self):
        return retention.preview(self.factory).model_dump()

    def test_preview_excludes_active_recent_and_inconsistent_attempts(self):
        for name,status,age in [('old','completed',100),('failed','failed',100),('running','running',100),('queued','queued',100),('recent','completed',1)]:
            self.seed(name,status,age)
        self.seed('cancelled','failed',cancelled=True)
        self.seed('inconsistent',children=True)
        with self.factory() as db:
            db.get(JobAttempt,'inconsistent-attempt').finished_at=None; db.commit()
        plan=self.plan()
        self.assertEqual({c['jobId'] for c in plan['candidates']},{'old','failed','cancelled'})
        self.assertEqual(next(c for c in plan['candidates'] if c['jobId']=='cancelled')['terminalReason'],'cancelled')
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)),7)

    def test_apply_preserves_results_and_audit_and_is_idempotent(self):
        self.seed(children=True)
        with self.factory() as db:
            before=[db.scalar(select(func.count()).select_from(model)) for model in (Scan,Finding,PlatformAudit)]
        plan=self.plan()
        self.assertEqual(retention.apply_plan(self.factory,plan)['deleted'],1)
        self.assertEqual(retention.apply_plan(self.factory,plan)['status'],'already-applied')
        with self.factory() as db:
            for model in (Job,)+retention.CHILDREN:
                self.assertEqual(db.scalar(select(func.count()).select_from(model)),0,model.__name__)
            after=[db.scalar(select(func.count()).select_from(model)) for model in (Scan,Finding,PlatformAudit)]
        self.assertEqual(after,[before[0],before[1],before[2]+1])

    def test_changed_dependencies_reject_entire_plan(self):
        self.seed(); plan=self.plan()
        with self.factory() as db:
            db.add(JobOutbox(job_id='old'));db.commit()
        with self.assertRaises(ValueError):retention.apply_plan(self.factory,plan)
        with self.factory() as db:self.assertIsNotNone(db.get(Job,'old'))

    def test_invalid_expired_and_cross_workspace_plans_rejected(self):
        self.seed();plan=self.plan()
        with self.assertRaises(ValueError):retention.apply_plan(self.factory,plan,'other')
        with patch.object(retention.time,'time',return_value=plan['expiresAt']+1):
            with self.assertRaises(ValueError):retention.apply_plan(self.factory,plan)
        plan['candidates']*=2
        with self.assertRaises(ValueError):retention.apply_plan(self.factory,plan)

    def test_audit_failure_rolls_back_all_deletes(self):
        self.seed(children=True);plan=self.plan()
        with patch('trace_api.platform.audit',side_effect=RuntimeError('test audit unavailable')):
            with self.assertRaises(RuntimeError):retention.apply_plan(self.factory,plan)
        with self.factory() as db:
            for model in (Job,)+retention.CHILDREN:
                self.assertEqual(db.scalar(select(func.count()).select_from(model)),1)

    def test_http_preview_is_admin_only_and_bounded(self):
        self.seed()
        path='/api/v1/access/job-retention'
        self.assertEqual(self.client.get(path).status_code,401)
        for role in ('viewer','analyst'):
            self.assertEqual(self.client.get(path,headers=self.headers(role)).status_code,403)
        response=self.client.get(path,headers=self.headers())
        self.assertEqual(response.status_code,200)
        self.assertEqual(len(response.json()['candidates']),1)
        self.assertEqual(self.client.get(path+'?days=0',headers=self.headers()).status_code,422)
        self.assertEqual(self.client.post(path,headers=self.headers()).status_code,405)

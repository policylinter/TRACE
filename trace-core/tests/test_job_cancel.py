"""Queued cancellation is scoped, audited, and serialized with worker claim."""
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch
from sqlalchemy import select,func,event
from fastapi import HTTPException
import test_access as fixtures
import test_jobs as jobfixtures
from trace_api import jobs,services,job_store,job_dispatcher
from trace_api.job_models import Job,JobAttempt,JobOutbox
from trace_api.platform import PlatformAudit


class CancellationTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    submit=jobfixtures.DurableJobTests.submit

    def cancel(self,jid,headers=None):
        return self.client.post('/api/v1/jobs/'+jid+'/cancel',headers=headers or self.headers(),json={'actor':'forged-client'})

    def test_cancel_is_idempotent_audited_and_removes_private_parameters(self):
        jid=self.submit(repository='private-fixture')
        for _ in range(2):
            response=self.cancel(jid)
            self.assertEqual(response.status_code,200,response.text)
            self.assertEqual(response.json()['status'],'cancelled')
            self.assertFalse(response.json()['cancellable'])
            self.assertFalse(response.json()['requiresReview'])
        self.assertEqual(jobs.job_status(jid)['status'],'cancelled')
        self.assertEqual(jobs.list_jobs()[0]['status'],'cancelled')
        with self.factory() as db:
            self.assertEqual(db.get(Job,jid).params,{})
            self.assertIsNotNone(db.get(JobOutbox,jid))
            self.assertEqual(db.scalar(select(func.count()).select_from(JobAttempt)),0)
            audit=db.scalars(select(PlatformAudit).where(PlatformAudit.action=='job.cancelled')).all()
            self.assertEqual(len(audit),1)
            self.assertEqual(audit[0].actor,'user:admin')
        with patch.object(services,'scan_source') as scanner:
            self.assertEqual(jobs.run_scan_job(jid)['status'],'not-claimed')
            self.assertEqual(job_store.dispatch_pending(self.factory),0)
            scanner.assert_not_called()

    def test_cancel_requires_admin_and_conceals_foreign_workspace(self):
        jid=self.submit()
        for user in ('viewer','analyst'):
            self.assertEqual(self.cancel(jid,self.headers(user)).status_code,403)
        self.assertEqual(self.client.post('/api/v1/jobs/'+jid+'/cancel').status_code,401)
        space=self.client.post('/api/v1/workspaces',headers=self.headers(),json={'name':'cancel-foreign'}).json()['id']
        self.assertEqual(self.cancel(jid,{**self.headers(),'X-Trace-Workspace':space}).status_code,404)
        self.assertEqual(self.cancel('unknown').status_code,404)
        self.assertEqual(jobs.job_status(jid)['status'],'queued')

    def test_running_job_is_not_killed_or_marked_cancelled(self):
        jid=self.submit();entered=threading.Event();release=threading.Event()
        def scan(db,**params):
            entered.set()
            if not release.wait(5):raise RuntimeError('fixture timeout')
            return SimpleNamespace(id='fixture',status='completed'),{},[]
        with patch.object(services,'scan_source',side_effect=scan),ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(jobs.run_scan_job,jid)
            try:
                self.assertTrue(entered.wait(3))
                self.assertEqual(self.cancel(jid).status_code,409)
                self.assertEqual(jobs.job_status(jid)['status'],'running')
            finally:release.set()
            self.assertEqual(future.result(timeout=3)['status'],'completed')
        self.assertEqual(self.cancel(jid).status_code,409)

    def test_worker_cancel_race_has_only_one_winner(self):
        for _ in range(3):
            jid=self.submit()
            def cancel():
                try:return job_store.cancel(self.factory,jid,'default','user:admin')['status']
                except HTTPException as exc:return exc.status_code
            with patch.object(services,'scan_source',return_value=(SimpleNamespace(id='fixture',status='completed'),{},[])) as scanner,ThreadPoolExecutor(max_workers=2) as pool:
                worker=pool.submit(jobs.run_scan_job,jid);request=pool.submit(cancel)
                result=worker.result(timeout=5);cancelled=request.result(timeout=5)
            if cancelled=='cancelled':
                self.assertEqual(result['status'],'not-claimed');self.assertEqual(scanner.call_count,0)
            else:
                self.assertEqual(cancelled,409);self.assertEqual(result['status'],'completed');self.assertEqual(scanner.call_count,1)

    def test_delayed_delivery_after_cancellation_cannot_start_scan(self):
        jid=self.submit()
        def delayed(factory,job_id):
            job_store.cancel(factory,job_id,'default','user:admin')
            self.assertEqual(jobs.run_scan_job(job_id)['status'],'not-claimed')
        with patch.object(job_store,'_start_local',side_effect=delayed),patch.object(services,'scan_source') as scanner:
            job_store.dispatch_one(self.factory,jid)
            scanner.assert_not_called()
        self.assertEqual(jobs.job_status(jid)['status'],'cancelled')

    def test_audit_failure_rolls_back_cancellation_and_queue_capacity_is_reusable(self):
        job_dispatcher.configure(self.factory,max_queued=1)
        jid=self.submit()
        def fail(conn,cursor,statement,parameters,context,many):
            if statement.startswith('INSERT INTO platform_audit'):raise RuntimeError('fixture audit failure')
        event.listen(self.engine,'before_cursor_execute',fail)
        try:
            with self.assertRaises(RuntimeError):job_store.cancel(self.factory,jid,'default','user:admin')
        finally:event.remove(self.engine,'before_cursor_execute',fail)
        self.assertEqual(jobs.job_status(jid)['status'],'queued')
        self.assertEqual(self.cancel(jid).status_code,200)
        self.assertEqual(jobs.job_status(self.submit())['status'],'queued')

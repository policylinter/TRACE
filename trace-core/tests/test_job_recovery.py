"""Heartbeat uncertainty and committed-result repair without scanner retries."""
import threading
import unittest
from unittest.mock import patch
from sqlalchemy import select, event
import test_access as fixtures
import test_jobs as jobfixtures
from trace_api import jobs, services, sources, scanners, job_recovery
from trace_api.job_models import Job, JobAttempt, JobHeartbeat, JobReceipt
from trace_api.models import Scan


class RecoveryTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    submit=jobfixtures.DurableJobTests.submit

    def interrupted(self):
        jid=self.submit()
        with patch.object(services,'scan_source',side_effect=SystemExit('fixture interruption')):
            with self.assertRaises(SystemExit): jobs.run_scan_job(jid)
        with self.factory() as db:
            aid=db.scalar(select(JobAttempt.id).where(JobAttempt.job_id==jid))
        return jid,aid

    def expire(self,jid):
        with self.factory() as db:
            db.get(JobHeartbeat,jid).expires_at=0;db.commit()

    def saved_scan(self,jid,aid,fail=False):
        sid='receipt-'+jid
        with self.factory() as db:
            db.add(Scan(id=sid,repository='local-fixture',status='completed'));db.commit()
        def fleet(path,results):
            results.append({'id':'fixture','status':'failed'})
            return [],['fixture'],[]
        def fail_receipt(conn,cursor,statement,parameters,context,many):
            if statement.startswith('INSERT INTO scan_job_receipts'): raise RuntimeError('fixture transaction failure')
        if fail:event.listen(self.engine,'before_cursor_execute',fail_receipt)
        try:
            with self.factory() as db, patch.object(sources,'fetch',return_value=('.',{})), patch.object(scanners,'run_available',side_effect=fleet), patch.object(services,'build_usage_index',return_value={}), patch.object(services,'run_scan',side_effect=lambda db,**kwargs:db.get(Scan,sid)):
                db.info.update(job_id=jid,job_attempt_id=aid,workspace_id='default')
                services.scan_source(db,source='local-fixture')
        finally:
            if fail:event.remove(self.engine,'before_cursor_execute',fail_receipt)
        return sid

    def test_lost_heartbeat_is_uncertainty_not_permission_to_retry(self):
        jid,aid=self.interrupted()
        self.assertEqual(jobs.job_status(jid)['executionState'],'responsive')
        self.expire(jid)
        response=self.client.get('/api/v1/jobs/'+jid,headers=self.headers()).json()
        self.assertEqual(response['status'],'running')
        self.assertEqual(response['executionState'],'heartbeat-lost')
        self.assertTrue(response['requiresReview'])
        with patch.object(services,'scan_source') as scanner:
            self.assertEqual(jobs.run_scan_job(jid)['status'],'not-claimed')
            self.assertEqual(job_recovery.reconcile(self.factory,jid),'no-receipt')
            scanner.assert_not_called()
        self.assertTrue(job_recovery.renew(self.factory,jid,aid))
        self.assertFalse(jobs.job_status(jid)['requiresReview'])

    def test_heartbeat_thread_renews_and_stops(self):
        called=threading.Event()
        def renew(*args):called.set();return True
        with patch.object(job_recovery,'HEARTBEAT_INTERVAL',0.005),patch.object(job_recovery,'renew',side_effect=renew):
            heartbeat=job_recovery.Heartbeat(self.factory,'fixture','fixture')
            with heartbeat:self.assertTrue(called.wait(2))
            self.assertFalse(heartbeat.thread.is_alive())

    def test_receipt_reconciles_job_and_attempt_without_rerunning_scan(self):
        jid,aid=self.interrupted();sid=self.saved_scan(jid,aid)
        self.assertEqual(job_recovery.reconcile(self.factory,jid),'worker-responsive')
        self.expire(jid)
        with patch.object(services,'scan_source') as scanner:
            self.assertEqual(job_recovery.reconcile(self.factory,jid),'reconciled')
            self.assertEqual(job_recovery.reconcile(self.factory,jid),'not-running')
            scanner.assert_not_called()
        result=jobs.job_status(jid)
        self.assertEqual(result['scanId'],sid)
        self.assertEqual(result['scanStatus'],'partial')
        self.assertEqual(result['status'],'completed')
        self.assertTrue(result['reconciled'])
        with self.factory() as db:
            self.assertEqual(db.get(JobAttempt,aid).status,'completed')
            self.assertEqual(db.get(Job,jid).params,{})
            from trace_api.platform import PlatformAudit
            entry=db.scalar(select(PlatformAudit).where(PlatformAudit.action=='job.reconciled',PlatformAudit.object_id==jid))
            self.assertEqual(entry.actor,'system:job-recovery')
        self.assertFalse(job_recovery.renew(self.factory,jid,aid))

    def test_receipt_and_final_scan_changes_rollback_together(self):
        jid,aid=self.interrupted()
        with self.assertRaises(RuntimeError):self.saved_scan(jid,aid,fail=True)
        with self.factory() as db:
            self.assertIsNone(db.get(JobReceipt,jid))
            self.assertEqual(db.get(Scan,'receipt-'+jid).status,'completed')
        self.expire(jid)
        self.assertEqual(job_recovery.reconcile(self.factory,jid),'no-receipt')

    def test_missing_result_and_foreign_workspace_are_not_reconciled(self):
        jid,aid=self.interrupted();sid=self.saved_scan(jid,aid);self.expire(jid)
        self.assertEqual(job_recovery.reconcile(self.factory,jid,'foreign'),'not-found')
        with self.factory() as db:
            db.delete(db.get(Scan,sid));db.commit()
        self.assertEqual(job_recovery.reconcile(self.factory,jid),'result-unavailable')
        self.assertEqual(jobs.job_status(jid)['status'],'running')

    def test_old_running_jobs_without_heartbeat_are_explicitly_unknown(self):
        jid,aid=self.interrupted()
        with self.factory() as db:
            db.delete(db.get(JobHeartbeat,jid));db.commit()
        self.assertEqual(jobs.job_status(jid)['executionState'],'unknown')
        self.assertTrue(jobs.job_status(jid)['requiresReview'])
        self.assertFalse(job_recovery.renew(self.factory,jid,'wrong-attempt'))

    def test_late_worker_cannot_overwrite_reconciled_result(self):
        jid=self.submit()
        def delayed(job_id,params,factory,attempt_id):
            self.saved_scan(job_id,attempt_id)
            self.expire(job_id)
            self.assertEqual(job_recovery.reconcile(factory,job_id),'reconciled')
            return {'jobId':job_id,'status':'failed','error':'late worker result'}
        with patch.object(jobs,'_run_pipeline',side_effect=delayed):
            self.assertEqual(jobs.run_scan_job(jid)['status'],'already-finalized')
        result=jobs.job_status(jid)
        self.assertEqual(result['status'],'completed')
        self.assertTrue(result['reconciled'])
        self.assertNotIn('error',result)

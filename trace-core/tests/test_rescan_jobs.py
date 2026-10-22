"""Background rescan uses durable scope, admission, progress and receipts."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func
import test_access as fixtures
from trace_api import jobs,services,job_store,rescan_jobs,job_dispatcher
from trace_api.job_models import Job,RescanJob,JobAttempt,JobReceipt
from trace_api.models import User


class RescanTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    sid='scan-8f21a3c'

    def enqueue(self,user='analyst'):
        with patch.object(job_store,'dispatch_one'):
            response=self.client.post(f'/api/v1/scans/{self.sid}/rescan?wait=false',headers=self.headers(user))
        self.assertEqual(response.status_code,200,response.text)
        return response.json()['jobId']

    def test_analyst_rescan_persists_progress_and_receipt_without_source_scanners(self):
        jid=self.enqueue()
        self.assertNotEqual(jid,self.sid)
        progress=self.client.get(f'/api/v1/scans/{self.sid}/progress?jobId={jid}',headers=self.headers()).json()
        self.assertEqual(progress['phase'],'queue')
        self.assertTrue(progress['active'])
        with patch.object(services,'assess',return_value={'verdict':'needs_review','confidence':80,'evidence':{}}),patch.object(services,'scan_source') as source:
            result=jobs.run_scan_job(jid)
            self.assertEqual(result['status'],'completed',result)
            source.assert_not_called()
        with self.factory() as db:
            self.assertIsNotNone(db.get(JobReceipt,jid))
            self.assertEqual(db.scalar(select(JobAttempt.status)),'completed')
            self.assertEqual(db.get(RescanJob,jid).progress['phase'],'done')
        progress=self.client.get(f'/api/v1/scans/{self.sid}/progress?jobId={jid}',headers=self.headers()).json()
        self.assertEqual(progress['phase'],'done')
        self.assertFalse(progress['active'])

    def test_duplicate_requests_reuse_active_job_even_when_queue_is_full(self):
        job_dispatcher.configure(self.factory,max_queued=1)
        jid=self.enqueue()
        self.assertEqual(self.enqueue(),jid)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(RescanJob)),1)

    def test_cancelled_progress_is_terminal_and_next_request_creates_new_job(self):
        jid=self.enqueue()
        self.assertEqual(self.client.post(f'/api/v1/jobs/{jid}/cancel',headers=self.headers()).status_code,200)
        progress=rescan_jobs.progress(self.factory,self.sid,'default',jid)
        self.assertEqual(progress['phase'],'cancelled')
        self.assertFalse(progress['active'])
        next_id=self.enqueue();self.assertNotEqual(jid,next_id)
        self.assertEqual(rescan_jobs.progress(self.factory,self.sid,'default',jid)['phase'],'cancelled')
        self.assertEqual(rescan_jobs.progress(self.factory,self.sid,'default',next_id)['phase'],'queue')

    def test_progress_pin_conceals_wrong_job_and_foreign_scan(self):
        jid=self.enqueue()
        response=self.client.get(f'/api/v1/scans/{self.sid}/progress?jobId=missing',headers=self.headers())
        self.assertEqual(response.status_code,404)
        space=self.client.post('/api/v1/workspaces',headers=self.headers(),json={'name':'private-rescan'}).json()['id']
        headers={**self.headers(),'X-Trace-Workspace':space}
        self.assertEqual(self.client.get(f'/api/v1/scans/{self.sid}/progress?jobId={jid}',headers=headers).status_code,404)
        self.assertEqual(self.client.post(f'/api/v1/scans/{self.sid}/rescan?wait=false',headers=headers).status_code,404)
        self.assertEqual(self.client.post(f'/api/v1/scans/{self.sid}/rescan?wait=false',headers=self.headers('viewer')).status_code,403)

    def test_lost_heartbeat_is_not_reported_as_completed_progress(self):
        from trace_api.job_models import JobHeartbeat
        jid=self.enqueue()
        with patch.object(services,'rescan',side_effect=SystemExit('fixture crash')):
            with self.assertRaises(SystemExit):jobs.run_scan_job(jid)
        with self.factory() as db:
            db.get(JobHeartbeat,jid).expires_at=0;db.commit()
        progress=rescan_jobs.progress(self.factory,self.sid,'default',jid)
        self.assertEqual(progress['phase'],'interrupted')
        self.assertFalse(progress['active'])
        self.assertTrue(progress['requiresReview'])

    def test_concurrent_submission_deduplicates_in_database(self):
        with self.factory() as db:uid=db.scalar(select(User.id).where(User.username=='analyst'))
        with patch.object(job_store,'dispatch_one'),patch.object(jobs,'queue_mode',return_value='in-process'),ThreadPoolExecutor(max_workers=2) as pool:
            result=list(pool.map(lambda _:jobs.submit_rescan(self.sid,actor='user:analyst',workspace_id='default',user_id=uid)['jobId'],range(2)))
        self.assertEqual(result[0],result[1])

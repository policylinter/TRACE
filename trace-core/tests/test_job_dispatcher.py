"""Shared queue admission and recovery; no external scanners or broker."""
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch
from sqlalchemy import select,func
from fastapi import HTTPException
import test_access as fixtures
import test_jobs as jobfixtures
from trace_api import jobs,services,job_store,job_dispatcher
from trace_api.job_models import Job,JobAttempt,JobOutbox,QueueControl


class DispatcherTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    submit=jobfixtures.DurableJobTests.submit

    def test_periodic_dispatch_drains_waiting_jobs_when_capacity_is_released(self):
        job_dispatcher.configure(self.factory,max_running=1)
        with patch.object(jobs,'queue_mode',return_value='in-process'):
            ids=[self.submit() for _ in range(2)]
        entered=threading.Event();release=threading.Event();calls=[]
        def scan(db,**params):
            calls.append(1)
            if len(calls)==1:
                entered.set()
                if not release.wait(5):raise RuntimeError('fixture timed out')
            return SimpleNamespace(id='fixture',status='completed'),{},[]
        with patch.object(services,'scan_source',side_effect=scan),patch.object(job_dispatcher,'ENABLED',True),patch.object(job_dispatcher,'INTERVAL',0.01):
            with job_dispatcher.Dispatcher(self.factory):
                try:
                    self.assertTrue(entered.wait(3))
                    self.assertEqual(jobs.job_status(ids[1])['status'],'queued')
                    self.assertEqual(len(calls),1)
                finally:release.set()
                deadline=time.monotonic()+5
                while jobs.job_status(ids[1])['status']!='completed' and time.monotonic()<deadline:time.sleep(.01)
                self.assertEqual(jobs.job_status(ids[1])['status'],'completed')
        self.assertEqual(len(calls),2)

    def test_concurrent_workers_share_capacity_and_queued_job_runs_after_release(self):
        job_dispatcher.configure(self.factory,max_running=1)
        ids=[self.submit() for _ in range(2)]
        entered=threading.Event();release=threading.Event()
        def scan(db,**params):
            entered.set()
            if not release.wait(5):raise RuntimeError('fixture timed out')
            return SimpleNamespace(id='fixture',status='completed'),{},[]
        with patch.object(services,'scan_source',side_effect=scan) as scanner:
            with ThreadPoolExecutor(max_workers=2) as pool:
                first=pool.submit(jobs.run_scan_job,ids[0])
                try:
                    self.assertTrue(entered.wait(3))
                    self.assertEqual(pool.submit(jobs.run_scan_job,ids[1]).result(timeout=3)['status'],'capacity-wait')
                    self.assertEqual(jobs.job_status(ids[1])['status'],'queued')
                    with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(JobAttempt)),1)
                finally:release.set()
                self.assertEqual(first.result(timeout=3)['status'],'completed')
            self.assertEqual(jobs.run_scan_job(ids[1])['status'],'completed')
            self.assertEqual(scanner.call_count,2)

    def test_admission_limit_is_atomic_and_returns_429_without_orphan_outbox(self):
        job_dispatcher.configure(self.factory,max_queued=1)
        def submit(_):
            try:return jobs.submit_scan(source='local-fixture',_actor='local-operator')['jobId']
            except HTTPException as exc:return exc.status_code
        with patch.object(job_store,'dispatch_one'),patch.object(jobs,'queue_mode',return_value='in-process'),ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(submit,range(2)))
        self.assertEqual(results.count(429),1)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(JobOutbox)),1)

    def test_shared_delivery_cooldown_prevents_duplicate_dispatchers(self):
        jid=self.submit()
        with patch.object(job_store,'_start_local') as thread:
            with ThreadPoolExecutor(max_workers=2) as pool:
                list(pool.map(lambda _:job_store.dispatch_one(self.factory,jid,redeliver=True),range(2)))
            self.assertEqual(thread.call_count,1)
            self.assertEqual(job_store.dispatch_pending(self.factory),0)
        with self.factory() as db:
            outbox=db.get(JobOutbox,jid)
            self.assertEqual(outbox.deliveries,1)
            self.assertGreater(outbox.next_delivery_at,0)

    def test_periodic_dispatch_survives_failed_delivery_and_stops(self):
        attempted=threading.Event()
        calls=[]
        def tick(factory):
            calls.append(1)
            if len(calls)==1: raise RuntimeError('fixture transient DB error')
            attempted.set();return 0
        with patch.object(job_dispatcher,'ENABLED',True),patch.object(job_dispatcher,'INTERVAL',0.01),patch.object(job_store,'dispatch_pending',side_effect=tick):
            dispatcher=job_dispatcher.Dispatcher(self.factory)
            with self.assertLogs(job_dispatcher.logger,level='WARNING'),dispatcher:self.assertTrue(attempted.wait(3))
            self.assertFalse(dispatcher.thread.is_alive())
        self.assertGreaterEqual(len(calls),2)

    def test_http_queue_full_returns_retry_after(self):
        job_dispatcher.configure(self.factory,max_queued=1)
        self.submit()
        response=self.client.post('/api/v1/scans/from-source',headers=self.headers(),json={'source':'local-fixture','wait':False})
        self.assertEqual(response.status_code,429,response.text)
        self.assertEqual(response.headers['retry-after'],'30')

    def test_lost_worker_still_holds_capacity_and_limits_are_persisted(self):
        job_dispatcher.configure(self.factory,max_running=1,max_queued=3)
        jid=self.submit();waiting=self.submit()
        with patch.object(services,'scan_source',side_effect=SystemExit('fixture worker died')):
            with self.assertRaises(SystemExit):jobs.run_scan_job(jid)
        with patch.object(services,'scan_source') as scanner:
            self.assertEqual(jobs.run_scan_job(waiting)['status'],'capacity-wait')
            self.assertEqual(job_store.dispatch_pending(self.factory),0)
            scanner.assert_not_called()
        with self.factory() as db:
            control=db.get(QueueControl,'default')
            self.assertEqual((control.max_running,control.max_queued),(1,3))
        job_dispatcher.ensure_control(self.factory)
        with self.factory() as db:self.assertEqual(db.get(QueueControl,'default').max_running,1)

    def test_acknowledged_celery_messages_are_not_periodically_duplicated(self):
        jid=self.submit()
        with self.factory() as db:
            db.get(Job,jid).mode='celery'
            outbox=db.get(JobOutbox,jid);outbox.delivered_at=1;outbox.next_delivery_at=0
            db.commit()
        with patch.object(job_store,'dispatch_one') as deliver:
            self.assertEqual(job_store.dispatch_pending(self.factory),0)
            deliver.assert_not_called()
            self.assertEqual(job_store.dispatch_pending(self.factory,redeliver=True),1)
            deliver.assert_called_once()

    def test_capacity_rejection_cannot_be_lost_to_late_publish_ack(self):
        import sys
        from unittest.mock import Mock
        job_dispatcher.configure(self.factory,max_running=1)
        running=self.submit();waiting=self.submit()
        with patch.object(services,'scan_source',side_effect=SystemExit('fixture stopped')):
            with self.assertRaises(SystemExit):jobs.run_scan_job(running)
        with self.factory() as db:
            db.get(Job,waiting).mode='celery';db.commit()
        app=Mock()
        app.send_task.side_effect=lambda *a,**kw:jobs.run_scan_job(waiting)
        with patch.dict(sys.modules,{'celery':SimpleNamespace(Celery=lambda *a,**kw:app)}),patch.object(job_dispatcher,'available',return_value=1):
            job_store.dispatch_one(self.factory,waiting)
        with self.factory() as db:
            outbox=db.get(JobOutbox,waiting)
            self.assertIsNone(outbox.delivered_at)
            self.assertEqual(outbox.next_delivery_at,0)
            self.assertEqual(db.get(Job,waiting).status,'queued')

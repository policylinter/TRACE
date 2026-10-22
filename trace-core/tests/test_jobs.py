"""Durable jobs contract, no actual scanners or external broker."""
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import patch
from sqlalchemy import select, func
import test_access as fixtures
from trace_api import jobs, services
from trace_api import job_store
from trace_api.job_models import Job, JobAttempt, JobOutbox
from trace_api.models import User


class DurableJobTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers

    def submit(self, **extra):
        with self.factory() as db:
            uid=db.scalar(select(User.id).where(User.username=='admin'))
        params={'source':'local-fixture','_actor':'user:admin','_user_id':uid,'_workspace_id':'default',**extra}
        with patch.object(job_store,'dispatch_one'):
            return jobs.submit_scan(**params)['jobId']

    def test_status_survives_new_sessions_and_does_not_expose_private_parameters(self):
        with patch.object(jobs,'queue_mode',return_value='in-process'):
            jid=self.submit(repository='private-repository-location')
        self.assertEqual(jobs.job_status(jid)['status'],'queued')
        self.assertIsNone(jobs.job_status(jid,'foreign-workspace'))
        response=self.client.get('/api/v1/jobs/'+jid,headers=self.headers()).json()
        self.assertNotIn('private-repository-location',str(response))
        self.assertNotIn('params',response)
        with self.factory() as db:
            self.assertIsNotNone(db.get(JobOutbox,jid))
            self.assertEqual(db.scalar(select(func.count()).select_from(JobAttempt)),0)
        with patch.object(services,'scan_source',return_value=(SimpleNamespace(id='fixture-result',status='partial'),{'private':'source'},['fixture-scanner'])):
            self.assertEqual(jobs.run_scan_job(jid)['status'],'completed')
        self.assertEqual(jobs.job_status(jid)['scanStatus'],'partial')
        with self.factory() as db:
            self.assertEqual(db.get(Job,jid).params,{})
            self.assertEqual(db.scalar(select(JobAttempt.status)),'completed')

    def test_duplicate_delivery_is_claimed_once_even_with_forged_broker_params(self):
        jid=self.submit()
        with patch.object(services,'scan_source',return_value=(SimpleNamespace(id='fixture-result',status='completed'),{},[])) as scanner:
            with ThreadPoolExecutor(max_workers=2) as pool:
                results=list(pool.map(lambda _: jobs.run_scan_job(jid,{'source':'forged-external-target'}),range(2)))
            self.assertEqual(scanner.call_count,1)
            self.assertEqual({r['status'] for r in results},{'completed','not-claimed'})
            self.assertEqual(scanner.call_args.kwargs['source'],'local-fixture')
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(JobAttempt)),1)

    def test_failed_dispatch_keeps_outbox_and_recovery_redelivers_only_queued(self):
        jid=self.submit()
        with patch.object(job_store.threading,'Thread',side_effect=RuntimeError('fixture delivery failure')):
            job_store.dispatch_one(self.factory,jid)
        with self.factory() as db:
            self.assertIsNone(db.get(JobOutbox,jid).delivered_at)
            db.get(JobOutbox,jid).next_delivery_at=0;db.commit()
        with patch.object(job_store.threading,'Thread') as thread:
            self.assertEqual(job_store.dispatch_pending(self.factory),1)
            self.assertEqual(thread.call_count,1)
            # Simulate API crash after thread.start but before claim.
            with self.factory() as db:
                db.get(JobOutbox,jid).next_delivery_at=0;db.commit()
            self.assertEqual(job_store.dispatch_pending(self.factory),1)
        with patch.object(services,'scan_source',return_value=(SimpleNamespace(id='fixture',status='completed'),{},[])):
            jobs.run_scan_job(jid)
        self.assertEqual(job_store.dispatch_pending(self.factory),0)

    def test_unknown_job_and_revoked_author_never_start_pipeline(self):
        jid=self.submit()
        with self.factory() as db:
            user=db.scalar(select(User).where(User.username=='admin'));user.is_active=False;db.commit()
        with patch.object(services,'scan_source') as scanner:
            self.assertEqual(jobs.run_scan_job('unknown')['status'],'not-claimed')
            self.assertEqual(jobs.run_scan_job(jid)['status'],'failed')
            self.assertEqual(jobs.run_scan_job(jid)['status'],'not-claimed')
            scanner.assert_not_called()
        self.assertEqual(jobs.job_status(jid)['error'],'Execution denied')

    def test_credentials_are_rejected_before_storage_and_errors_are_redacted(self):
        from fastapi import HTTPException
        for params in ({'ai_settings':{'api_key':'fixture-secret'}},{'source':'https://user:fixture@example.test/repo'}, {'source':'https://example.test/repo?token=fixture'}):
            with self.subTest(params=params), self.assertRaises(HTTPException): self.submit(**params)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)),0)
        jid=self.submit()
        with patch.object(services,'scan_source',side_effect=RuntimeError('fixture-private-error')):
            jobs.run_scan_job(jid)
        self.assertNotIn('fixture-private-error',str(jobs.job_status(jid)))

    def test_job_and_outbox_rollback_together(self):
        from sqlalchemy import event
        def fail(conn,cursor,statement,parameters,context,many):
            if statement.startswith('INSERT INTO scan_job_outbox'): raise RuntimeError('fixture rollback')
        event.listen(self.engine,'before_cursor_execute',fail)
        try:
            with self.assertRaises(RuntimeError): self.submit()
        finally: event.remove(self.engine,'before_cursor_execute',fail)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Job)),0)

    def test_interrupted_running_job_is_not_automatically_reexecuted(self):
        jid=self.submit()
        with patch.object(services,'scan_source',side_effect=SystemExit('fixture worker interruption')):
            with self.assertRaises(SystemExit): jobs.run_scan_job(jid)
        self.assertEqual(jobs.job_status(jid)['status'],'running')
        with patch.object(services,'scan_source') as scanner:
            self.assertEqual(job_store.dispatch_pending(self.factory),0)
            self.assertEqual(jobs.run_scan_job(jid)['status'],'not-claimed')
            scanner.assert_not_called()
        with self.factory() as db:
            self.assertEqual(db.scalar(select(JobAttempt.status)),'running')

    def test_job_scope_foreign_key_is_enforced_with_sqlite_foreign_keys_enabled(self):
        from sqlalchemy.exc import IntegrityError
        with self.factory() as db:
            db.connection().exec_driver_sql('PRAGMA foreign_keys=ON')
            self.assertEqual(db.connection().exec_driver_sql('PRAGMA foreign_keys').scalar(),1)
            db.add(Job(id='invalid-scope',organization_id='default',workspace_id='missing',status='queued',mode='in-process',created_at=0,params={},result={}))
            with self.assertRaises(IntegrityError): db.commit()

    def test_http_submission_uses_server_identity_and_rejects_credentials_before_project_write(self):
        from trace_api.models import Project
        with self.factory() as db:
            before=db.scalar(select(func.count()).select_from(Project))
        response=self.client.post('/api/v1/scans/from-source',headers=self.headers('admin'),json={
            'source':'https://user:fixture@example.test/repo','wait':False})
        self.assertEqual(response.status_code,422,response.text)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Project)),before)
        with patch.object(job_store,'dispatch_one'),patch.object(jobs,'queue_mode',return_value='in-process'):
            response=self.client.post('/api/v1/scans/from-source',headers=self.headers('admin'),json={
                'source':'local-fixture','wait':False,'_actor':'user:analyst','_user_id':999,'_workspace_id':'forged'})
        self.assertEqual(response.status_code,201,response.text)
        jid=response.json()['jobId']
        with self.factory() as db:
            params=db.get(Job,jid).params
            self.assertEqual(params['_actor'],'user:admin')
            self.assertEqual(params['_workspace_id'],'default')
            self.assertNotEqual(params['_user_id'],999)
        with patch.object(services,'scan_source',return_value=(SimpleNamespace(id='fixture',status='completed'),{},[])):
            self.assertEqual(jobs.run_scan_job(jid)['status'],'completed')

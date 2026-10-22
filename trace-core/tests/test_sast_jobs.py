import json,os,hashlib,time,unittest
from pathlib import Path
from datetime import datetime,timezone
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_access as fixtures
from test_semgrep_converter import convert,report
from trace_api import jobs,job_store,job_recovery
from trace_api.sast_jobs import SastExecution
from trace_api.job_models import Job,JobAttempt,JobHeartbeat
from trace_api.module_intake import ModuleResult
from trace_api.semgrep_batch import SemgrepBatch

class SastJobsTests(unittest.TestCase):
    setUpBase=fixtures.AccessTests.setUp
    tearDownBase=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    root='/api/v1/platform/sast/'
    def setUp(self):
        self.setUpBase()
        root=Path(self.temp.name);rules=root/'rules.yaml';rules.write_text('rules: []')
        source=self.client.post('/api/v1/platform/result-sources',headers=self.headers(),json={'name':'QA SAST job','module':'appsec'}).json()
        asset=self.client.post('/api/v1/platform/assets',headers=self.headers(),json={'name':'QA repo','kind':'repository','externalKey':'qa:sast-job'}).json()
        self.target=dict(id='qa',name='QA test executor',workspaceId='default',sourceId=source['id'],assetId=asset['id'],repositoryPath=str(root),rulesPath=str(rules))
        self.config=root/'targets.json';self.config.write_text(json.dumps([self.target]))
        import sys
        self.stack.enter_context(patch.dict(os.environ,TRACE_SAST_TARGETS_FILE=str(self.config),TRACE_SAST_EXECUTABLE=sys.executable))
        self.stack.enter_context(patch('trace_api.job_store.dispatch_one'))
        self.stack.enter_context(patch('trace_api.jobs.queue_mode',return_value='in-process'))
    def tearDown(self):self.tearDownBase()
    def submit(self,role='admin',**fields):
        return self.client.post(self.root+'jobs',headers=self.headers(role),json={'targetId':'qa','commit':'a'*40,**fields})
    def fake(self,**kwargs):
        manifest,documents=convert(report(),source_id=kwargs['source_id'],asset_id=kwargs['asset_id'],run_id=kwargs['run_id'],commit=kwargs['commit'])
        output=kwargs['output_dir'];output.mkdir()
        for name,document in zip(manifest['files'],documents):(output/name).write_text(json.dumps(document))
        receipt=dict(finishedAt=datetime.now(timezone.utc).isoformat(),reportState=manifest['reportState'],rulesSha256=hashlib.sha256(Path(kwargs['rules']).read_bytes()).hexdigest(),executor='TEST_ONLY',source={'commit':kwargs['commit']},attested=False)
        return receipt,manifest
    def test_readiness_paths_private_roles_and_default_disabled(self):
        value=self.client.get(self.root+'targets',headers=self.headers('viewer')).json()
        self.assertTrue(value['toolsAvailable']);self.assertEqual(value['targets'][0]['id'],'qa')
        self.assertNotIn(self.temp.name,json.dumps(value))
        for role in ('viewer','analyst'):self.assertEqual(self.submit(role).status_code,403)
        self.assertEqual(self.submit(repositoryPath=self.temp.name).status_code,422)
        self.assertEqual(self.submit(commit='main').status_code,422)
        with patch.dict(os.environ,TRACE_SAST_TARGETS_FILE=''):
            self.assertEqual(self.client.get(self.root+'targets',headers=self.headers()).json()['targets'],[])
            self.assertEqual(self.submit().status_code,404)
    def test_job_dedup_cancel_and_sast_kind(self):
        first=self.submit();self.assertEqual(first.status_code,202,first.text)
        id=first.json()['jobId'];self.assertEqual(self.submit().json()['jobId'],id)
        self.assertEqual(job_store.status(self.factory,id,'default')['kind'],'sast')
        cancelled=job_store.cancel(self.factory,id,'default','user:admin')
        self.assertEqual(cancelled['kind'],'sast');self.assertEqual(cancelled['status'],'cancelled')
        with patch('tools.run_sast_local.execute') as execute:job_store.execute(self.factory,id);execute.assert_not_called()
    def test_worker_receipt_batch_atomic_and_no_legacy_scan(self):
        id=self.submit().json()['jobId']
        from trace_api.models import Scan
        with self.factory() as db:before=db.scalar(select(func.count()).select_from(Scan))
        with patch('tools.run_sast_local.execute',side_effect=self.fake):value=job_store.execute(self.factory,id)
        self.assertEqual(value['status'],'completed',value);self.assertEqual(value['kind'],'sast')
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(Scan)),before)
            self.assertEqual(db.scalar(select(func.count()).select_from(SastExecution)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(SemgrepBatch)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),1)
        rows=self.client.get(self.root+'executions',headers=self.headers('viewer')).json()
        self.assertEqual(rows[0]['jobId'],id)
        self.assertNotIn(self.temp.name,json.dumps(rows))
        from trace_api.job_retention import preview,apply_plan
        with self.factory() as db:job=db.get(Job,id);job.finished_at=time.time()-3*86400;db.commit()
        plan=preview(self.factory,days=1)
        self.assertEqual(apply_plan(self.factory,plan.model_dump())['deleted'],1)
        self.assertEqual(len(self.client.get(self.root+'executions',headers=self.headers()).json()),1)
    def test_changed_rules_or_revoked_author_fail_before_process(self):
        id=self.submit().json()['jobId'];Path(self.target['rulesPath']).write_text('changed')
        with patch('tools.run_sast_local.execute') as execute:
            self.assertEqual(job_store.execute(self.factory,id)['status'],'failed');execute.assert_not_called()
        id=self.submit().json()['jobId']
        from trace_api.access_models import Membership
        from trace_api.models import User
        with self.factory() as db:
            user=db.scalar(select(User).where(User.username=='admin'));member=db.scalar(select(Membership).where(Membership.user_id==user.id));member.is_active=False;db.commit()
        with patch('tools.run_sast_local.execute') as execute:
            self.assertEqual(job_store.execute(self.factory,id)['status'],'failed');execute.assert_not_called()
    def test_changed_rules_after_process_prevent_all_result_writes(self):
        id=self.submit().json()['jobId']
        def change(**kwargs):
            result=self.fake(**kwargs);Path(self.target['rulesPath']).write_text('changed after run');return result
        with patch('tools.run_sast_local.execute',side_effect=change):self.assertEqual(job_store.execute(self.factory,id)['status'],'failed')
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(SemgrepBatch)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)
        id=self.submit().json()['jobId']
        def revoke(**kwargs):
            value=self.fake(**kwargs)
            from trace_api.access_models import Membership
            from trace_api.models import User
            with self.factory() as db:
                user=db.scalar(select(User).where(User.username=='admin'));db.scalar(select(Membership).where(Membership.user_id==user.id)).is_active=False;db.commit()
            return value
        with patch('tools.run_sast_local.execute',side_effect=revoke):self.assertEqual(job_store.execute(self.factory,id)['status'],'failed')
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(SastExecution)),0)
    def test_audit_failure_rolls_back_batch_and_receipt(self):
        id=self.submit().json()['jobId']
        with patch('tools.run_sast_local.execute',side_effect=self.fake),patch('trace_api.sast_jobs.audit',side_effect=RuntimeError('failure')):
            self.assertEqual(job_store.execute(self.factory,id)['status'],'failed')
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(SemgrepBatch)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(SastExecution)),0)
    def test_recovery_from_committed_sast_receipt_never_reexecutes(self):
        id=self.submit().json()['jobId']
        with patch('tools.run_sast_local.execute',side_effect=self.fake):self.assertEqual(job_store.execute(self.factory,id)['status'],'completed')
        with self.factory() as db:
            job=db.get(Job,id);job.status='running';job.params={'_kind':'sast'}
            attempt=db.scalar(select(JobAttempt).where(JobAttempt.job_id==id));attempt.status='running';attempt.finished_at=None
            heartbeat=db.get(JobHeartbeat,id);heartbeat.expires_at=time.time()-1;db.commit()
        with patch('tools.run_sast_local.execute') as execute:
            self.assertEqual(job_recovery.reconcile(self.factory,id),'reconciled');execute.assert_not_called()
        self.assertEqual(job_store.status(self.factory,id,'default')['kind'],'sast')
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(SastExecution).values(created_by='forged'))
    def test_scope_and_capacity_apply(self):
        from trace_api.workspace_models import Workspace
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        headers={**self.headers(),'X-Trace-Workspace':'other'}
        self.assertEqual(self.client.get(self.root+'targets',headers=headers).json()['targets'],[])
        self.assertEqual(self.client.post(self.root+'jobs',headers=headers,json={'targetId':'qa','commit':'a'*40}).status_code,404)
        from trace_api.job_dispatcher import configure
        configure(self.factory,max_queued=1)
        self.assertEqual(self.submit().status_code,202)
        self.assertEqual(self.submit(commit='b'*40).status_code,429)

if __name__=='__main__':unittest.main()

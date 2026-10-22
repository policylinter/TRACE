import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func
import test_module_intake as fixtures
from trace_api.module_intake import ModuleResult,ResultWorkflow
from trace_api.platform import PlatformAudit
from trace_api.workspace_models import Workspace

class ModuleWorkflowTests(unittest.TestCase):
    setUp=fixtures.ModuleIntakeTests.setUp
    tearDown=fixtures.ModuleIntakeTests.tearDown
    headers=fixtures.ModuleIntakeTests.headers
    prepare=fixtures.ModuleIntakeTests.prepare
    ingest=fixtures.ModuleIntakeTests.ingest
    root=fixtures.ModuleIntakeTests.root
    def result(self):
        body=self.prepare();return self.ingest(body).json(),body
    def change(self,id,body,role='analyst',extra=None):
        return self.client.put(self.root+'module-results/'+id+'/workflow',headers={**self.headers(role),**(extra or {})},json=body)
    def test_read_default_then_persist_with_actor_history_and_original_untouched(self):
        result,body=self.result();path=self.root+'module-results/'+result['id']
        detail=self.client.get(path,headers=self.headers('viewer')).json()
        self.assertEqual(detail['result']['workflow']['revision'],0);self.assertEqual(detail['history'],[])
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultWorkflow)),0)
        update={'expectedRevision':0,'status':'in_progress','assignee':'tester','note':'Inspect report','dueDate':'2099-01-01'}
        response=self.change(result['id'],update)
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['revision'],1)
        self.assertEqual(response.json()['updatedBy'],'user:analyst')
        detail=self.client.get(path,headers=self.headers('viewer')).json()
        self.assertEqual(detail['result']['sha256'],result['sha256'])
        self.assertEqual(detail['result']['payload'],result['payload'])
        self.assertEqual(len(detail['history']),1)
        self.assertEqual(detail['history'][0]['actor'],'user:analyst')
        replay=self.ingest(body)
        self.assertEqual(replay.status_code,200)
        self.assertEqual(replay.json()['workflow']['revision'],1)
        with self.factory() as db:self.assertEqual(db.get(ModuleResult,result['id']).payload,result['payload'])

    def test_concurrent_edits_and_stale_revision_have_one_winner(self):
        result,_=self.result()
        def edit(name):return self.change(result['id'],{'expectedRevision':0,'status':'in_progress','assignee':name})
        with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(edit,['one','two']))
        self.assertEqual(sorted(r.status_code for r in responses),[200,409])
        with self.factory() as db:
            self.assertEqual(db.get(ResultWorkflow,result['id']).revision,1)
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit).where(PlatformAudit.action=='module-result.workflow')),1)

    def test_decisions_require_reason_and_risk_future_review(self):
        result,_=self.result()
        for patch_body in ({'status':'resolved'},{'status':'accepted_risk','note':'reason'},{'status':'accepted_risk','note':'reason','dueDate':'2020-01-01'},{'status':'invalid'},{'actor':'forged','status':'new'}):
            self.assertEqual(self.change(result['id'],{'expectedRevision':0,**patch_body}).status_code,422)
        response=self.change(result['id'],{'expectedRevision':0,'status':'accepted_risk','note':'Temporary exception','dueDate':'2099-01-01'})
        self.assertEqual(response.status_code,200,response.text)
        self.assertEqual(response.json()['status'],'accepted_risk')

    def test_read_only_cross_scope_and_missing_result(self):
        result,_=self.result()
        body={'expectedRevision':0,'status':'in_progress'}
        self.assertEqual(self.change(result['id'],body,'viewer').status_code,403)
        self.assertEqual(self.change('missing',body).status_code,404)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        headers={'X-Trace-Workspace':'other'}
        self.assertEqual(self.change(result['id'],body,'admin',headers).status_code,404)
        self.assertEqual(self.client.get(self.root+'module-results/'+result['id'],headers={**self.headers(),**headers}).status_code,404)

    def test_audit_failure_rolls_back_and_disabled_source_can_be_processed(self):
        result,body=self.result()
        self.client.put(self.root+'result-sources/'+body['sourceId'],headers=self.headers(),json={'active':False})
        update={'expectedRevision':0,'status':'in_progress'}
        with patch('trace_api.module_intake.audit',side_effect=RuntimeError('audit unavailable')):
            with self.assertRaises(RuntimeError):self.change(result['id'],update)
        with self.factory() as db:self.assertIsNone(db.get(ResultWorkflow,result['id']))
        self.assertEqual(self.change(result['id'],update).status_code,200)

    def test_noop_does_not_create_state_or_audit(self):
        result,_=self.result()
        response=self.change(result['id'],{'expectedRevision':0,'status':'new'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['revision'],0)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ResultWorkflow)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit).where(PlatformAudit.action=='module-result.workflow')),0)

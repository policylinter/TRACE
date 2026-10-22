import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_module_intake as fixtures
from trace_api.result_retests import ResultRetest
from trace_api.module_intake import ResultWorkflow
from trace_api.platform import PlatformAudit
from trace_api.workspace_models import Workspace

class RetestTests(unittest.TestCase):
    setUp=fixtures.ModuleIntakeTests.setUp
    tearDown=fixtures.ModuleIntakeTests.tearDown
    headers=fixtures.ModuleIntakeTests.headers
    prepare=fixtures.ModuleIntakeTests.prepare
    ingest=fixtures.ModuleIntakeTests.ingest
    root=fixtures.ModuleIntakeTests.root
    def reports(self):
        body=self.prepare()
        first=self.ingest(body).json()
        second=self.ingest({**body,'externalId':'second','observedAt':'2026-10-18T12:00:00Z'}).json()
        return first,second,body
    def link(self,original,target,reason='Repeat observation',role='analyst',extra=None):
        return self.client.post(self.root+'module-results/'+original+'/retests',headers={**self.headers(role),**(extra or {})},json={'targetResultId':target,'reason':reason})
    def withdraw(self,id,reason='Wrong association'):
        return self.client.post(self.root+'module-retests/'+id+'/withdraw',headers=self.headers('analyst'),json={'reason':reason})

    def test_link_is_idempotent_visible_both_sides_and_does_not_close(self):
        original,target,_=self.reports()
        response=self.link(original['id'],target['id'])
        self.assertEqual(response.status_code,201,response.text)
        value=response.json();self.assertEqual(value['createdBy'],'user:analyst')
        self.assertEqual(value['originalSha256'],original['sha256'])
        self.assertEqual(value['retestSha256'],target['sha256'])
        self.assertEqual(self.link(original['id'],target['id']).status_code,200)
        for result in (original,target):
            detail=self.client.get(self.root+'module-results/'+result['id'],headers=self.headers('viewer')).json()
            self.assertEqual(detail['retests'],[value]);self.assertEqual(detail['result']['sha256'],result['sha256'])
            self.assertEqual(detail['result']['workflow']['status'],'new')
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ResultWorkflow)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit).where(PlatformAudit.action=='module-result.retest')),1)

    def test_self_equal_time_backwards_and_mismatched_rule_rejected(self):
        original,target,body=self.reports()
        self.assertEqual(self.link(original['id'],original['id']).status_code,422)
        self.assertEqual(self.link(target['id'],original['id']).status_code,422)
        equal=self.ingest({**body,'externalId':'same-time'}).json()
        self.assertEqual(self.link(original['id'],equal['id']).status_code,422)
        mismatch=self.ingest({**body,'externalId':'mismatch','ruleId':'other','observedAt':'2026-10-19T12:00:00Z'}).json()
        self.assertEqual(self.link(original['id'],mismatch['id']).status_code,422)
        source=self.client.post(self.root+'result-sources',headers=self.headers(),json={'name':'Another','module':'infrastructure'}).json()
        other_source=self.ingest({**body,'sourceId':source['id'],'externalId':'source-mismatch','observedAt':'2026-10-19T12:00:00Z'}).json()
        self.assertEqual(self.link(original['id'],other_source['id']).status_code,422)
        asset=self.client.post(self.root+'assets',headers=self.headers(),json={'name':'Another','kind':'server','externalKey':'test:another'}).json()
        other_asset=self.ingest({**body,'assetId':asset['id'],'externalId':'asset-mismatch','observedAt':'2026-10-19T12:00:00Z'}).json()
        self.assertEqual(self.link(original['id'],other_asset['id']).status_code,422)

    def test_withdrawal_preserves_history_and_allows_new_association(self):
        original,target,body=self.reports()
        value=self.link(original['id'],target['id']).json()
        self.assertEqual(self.withdraw(value['id']).status_code,200)
        self.assertEqual(self.withdraw(value['id']).status_code,200)
        self.assertEqual(self.withdraw(value['id'],'Different reason').status_code,409)
        earlier=self.ingest({**body,'externalId':'earlier','observedAt':'2026-10-16T12:00:00Z'}).json()
        self.assertEqual(self.link(earlier['id'],target['id']).status_code,201)
        detail=self.client.get(self.root+'module-results/'+target['id'],headers=self.headers()).json()
        self.assertEqual(len(detail['retests']),2)
        self.assertEqual(sum(link['withdrawnAt'] is None for link in detail['retests']),1)

    def test_concurrent_predecessors_have_one_winner(self):
        original,target,body=self.reports()
        earlier=self.ingest({**body,'externalId':'earlier','observedAt':'2026-10-16T12:00:00Z'}).json()
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda id:self.link(id,target['id']),[original['id'],earlier['id']]))
        self.assertEqual(sorted(r.status_code for r in responses),[201,409])

    def test_permissions_scope_and_strict_body(self):
        original,target,_=self.reports()
        self.assertEqual(self.link(original['id'],target['id'],role='viewer').status_code,403)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        self.assertEqual(self.link(original['id'],target['id'],role='admin',extra={'X-Trace-Workspace':'other'}).status_code,404)
        self.assertEqual(self.link(original['id'],'missing').status_code,404)
        response=self.client.post(self.root+'module-results/'+original['id']+'/retests',headers=self.headers(),json={'targetResultId':target['id'],'reason':'test','actor':'forged'})
        self.assertEqual(response.status_code,422)

    def test_audit_failure_rolls_back_link_and_withdrawal(self):
        original,target,_=self.reports()
        with patch('trace_api.result_retests.audit',side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):self.link(original['id'],target['id'])
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultRetest)),0)
        value=self.link(original['id'],target['id']).json()
        with patch('trace_api.result_retests.audit',side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):self.withdraw(value['id'])
        with self.factory() as db:self.assertIsNone(db.get(ResultRetest,value['id']).withdrawn_at)

    def test_reference_rewrite_delete_and_bulk_changes_rejected(self):
        original,target,_=self.reports();value=self.link(original['id'],target['id']).json()
        with self.factory() as db:
            db.get(ResultRetest,value['id']).original_id=target['id']
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            db.delete(db.get(ResultRetest,value['id']))
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(ResultRetest).values(reason='changed'))

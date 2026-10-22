import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_inventory_comparison as fixtures
from trace_api.inventory_reconciliation import InventoryReview,InventoryReviewEvent
from trace_api.inventory_intake import InventoryRun,InventoryObservation
from trace_api.platform import Asset,PlatformAudit

class ReconciliationTests(unittest.TestCase):
    setUp=fixtures.InventoryComparisonTests.setUp
    tearDown=fixtures.InventoryComparisonTests.tearDown
    headers=fixtures.InventoryComparisonTests.headers
    source=fixtures.InventoryComparisonTests.source
    body=fixtures.InventoryComparisonTests.body
    send=fixtures.InventoryComparisonTests.send
    pair=fixtures.InventoryComparisonTests.pair
    root=fixtures.InventoryComparisonTests.root
    def view(self,source,a,b,node='absent',headers=None):
        return self.client.get(self.root+'/'+source+'/reconciliation',headers=headers or self.headers(),params={'before':a,'after':b,'externalId':node})
    def save(self,source,a,b,revision=0,status='in_progress',reason='QA reason',node='absent',role='analyst',extra=None):
        return self.client.put(self.root+'/'+source+'/reconciliation',headers=self.headers(role),json=dict(beforeRunId=a,afterRunId=b,externalId=node,expectedRevision=revision,status=status,reason=reason,**(extra or {})))
    def test_read_default_then_save_history_without_changing_assets(self):
        source,a,b=self.pair()
        with self.factory() as db:
            counts={model.__name__:db.scalar(select(func.count()).select_from(model)) for model in (Asset,InventoryObservation,PlatformAudit)}
        result=self.view(source,a,b);self.assertEqual(result.status_code,200,result.text)
        self.assertEqual(result.json()['review']['revision'],0);self.assertEqual(result.json()['history'],[])
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(InventoryReview)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit)),counts['PlatformAudit'])
        saved=self.save(source,a,b,reason='  QA explanation  ')
        self.assertEqual(saved.status_code,200,saved.text);self.assertEqual(saved.json()['revision'],1)
        self.assertEqual(saved.json()['updatedBy'],'user:analyst');self.assertEqual(saved.json()['reason'],'QA explanation')
        detail=self.view(source,a,b).json()
        self.assertEqual(detail['historyTotal'],1);self.assertEqual(detail['history'][0]['actor'],'user:analyst')
        self.assertEqual(detail['history'][0]['change']['before']['status'],'open')
        with self.factory() as db:
            for model in (Asset,InventoryObservation):self.assertEqual(db.scalar(select(func.count()).select_from(model)),counts[model.__name__])
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit)),counts['PlatformAudit']+1)
    def test_noop_stale_version_and_concurrent_first_write(self):
        source,a,b=self.pair()
        with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(lambda _:self.save(source,a,b),range(2)))
        self.assertEqual(sorted(response.status_code for response in responses),[200,409])
        self.assertEqual(self.save(source,a,b,revision=1).json()['revision'],1)
        self.assertEqual(self.save(source,a,b).status_code,409)
        self.assertEqual(self.view(source,a,b).json()['historyTotal'],1)
    def test_reopen_and_decision_only_affects_selected_pair(self):
        from datetime import datetime,timezone,timedelta
        source,a,b=self.pair();self.save(source,a,b,status='explained',reason='Outside reported scope')
        next_run=self.send(source,self.body('later',at=datetime.now(timezone.utc)-timedelta(minutes=30),items=[])).json()['id']
        self.assertEqual(self.view(source,a,next_run).json()['review']['revision'],0)
        self.assertEqual(self.save(source,a,b,revision=1,status='open',reason='Explanation needs review').json()['revision'],2)
        history=self.view(source,a,b).json()['history'];self.assertEqual([event['revision'] for event in history],[2,1])
    def test_partial_is_eligible_but_error_or_present_nodes_are_not(self):
        source,a,b=self.pair('partial')
        self.assertEqual(self.view(source,a,b).json()['observationKind'],'not_observed_partial')
        self.assertEqual(self.save(source,a,b,status='needs_observation').status_code,200)
        self.assertEqual(self.save(source,a,b,node='changed').status_code,409)
        self.assertEqual(self.save(source,a,b,node='added').status_code,404)
        source,a,b=self.pair('error')
        self.assertEqual(self.save(source,a,b).status_code,409)
        self.assertEqual(self.view(source,a,b).status_code,409)
    def test_reason_strict_schema_and_permissions(self):
        source,a,b=self.pair()
        for reason in ('','   '):self.assertEqual(self.save(source,a,b,reason=reason).status_code,422)
        for extra in ({'actor':'forged'},{'assetId':'forged'},{'workspaceId':'other'}):self.assertEqual(self.save(source,a,b,extra=extra).status_code,422)
        self.assertEqual(self.save(source,a,b,revision=True).status_code,422)
        self.assertEqual(self.save(source,a,b,status='deleted').status_code,422)
        self.assertEqual(self.save(source,a,b,role='viewer').status_code,403)
        self.assertEqual(self.view(source,a,b,headers=self.headers('viewer')).status_code,200)
        url=self.root+'/'+source+'/reconciliation?before='+a+'&after='+b+'&externalId=absent'
        self.assertEqual(self.client.get(url).status_code,401)
        token=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'Inventory','scopes':['inventory:read','inventory:write']}).json()['token']
        self.assertEqual(self.view(source,a,b,headers={'Authorization':'Bearer '+token}).status_code,403)
    def test_cross_scope_source_and_disabled_source(self):
        from trace_api.workspace_models import Workspace
        source,a,b=self.pair();other=self.source()
        self.assertEqual(self.view(other,a,b).status_code,404)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        self.assertEqual(self.view(source,a,b,headers={**self.headers(),'X-Trace-Workspace':'other'}).status_code,404)
        body=dict(beforeRunId=a,afterRunId=b,externalId='absent',expectedRevision=0,status='explained',reason='QA')
        self.assertEqual(self.client.put(self.root+'/'+source+'/reconciliation',headers={**self.headers(),'X-Trace-Workspace':'other'},json=body).status_code,404)
        self.client.put(self.root+'/'+source,headers=self.headers(),json={'active':False,'freshnessHours':24})
        self.assertEqual(self.save(source,a,b).status_code,200)
    def test_audit_failure_rolls_back_head_and_event(self):
        source,a,b=self.pair()
        with patch('trace_api.inventory_reconciliation.audit',side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):self.save(source,a,b)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(InventoryReview)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(InventoryReviewEvent)),0)
        self.assertEqual(self.save(source,a,b).json()['revision'],1)
    def test_context_and_history_cannot_be_rewritten_or_deleted(self):
        source,a,b=self.pair();self.save(source,a,b)
        with self.factory() as db:
            row=db.scalar(select(InventoryReview));row.before_id=b
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            db.delete(db.scalar(select(InventoryReview)))
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(InventoryReview).values(state={}))
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(InventoryReviewEvent).values(change={}))
        with self.factory() as db:
            db.delete(db.scalar(select(InventoryReviewEvent)))
            with self.assertRaises(ValueError):db.commit()
    def test_snapshot_binding_corruption_blocks_further_decisions(self):
        source,a,b=self.pair();self.save(source,a,b)
        with self.engine.begin() as connection:connection.execute(InventoryReview.__table__.update().values(after_sha256='0'*64))
        self.assertEqual(self.view(source,a,b).status_code,409)
        self.assertEqual(self.save(source,a,b,revision=1,status='explained').status_code,409)

import unittest
from datetime import datetime,timezone,timedelta
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_access as fixtures
from trace_api.inventory_intake import InventorySource,InventoryRun,InventoryNode,InventoryObservation
from trace_api.platform import Asset,PlatformAudit

class InventoryTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    root='/api/v1/platform/inventory/sources'
    def source(self):
        response=self.client.post(self.root,headers=self.headers(),json={'name':'QA inventory','freshnessHours':24})
        self.assertEqual(response.status_code,201,response.text);return response.json()['id']
    def body(self,id='run-1',at=None,items=None,status='complete',errors=None):
        return dict(schemaVersion='trace.inventory/1',externalRunId=id,observedAt=(at or datetime.now(timezone.utc)-timedelta(minutes=1)).isoformat(),
            status=status,items=items if items is not None else [{'externalId':'host-1','name':'QA host','kind':'server','owner':'reported-owner','platform':'TestOS'}],errors=errors or [])
    def send(self,source,body,role='admin'):
        return self.client.post(self.root+'/'+source+'/snapshots',headers=self.headers(role),json=body)
    def detail(self,id,**kwargs):return self.client.get(self.root+'/'+id,headers=self.headers(),**kwargs).json()
    def test_import_namespaced_assets_idempotency_and_manual_data_preserved(self):
        self.client.post('/api/v1/platform/assets',headers=self.headers(),json={'name':'Manual','kind':'server','externalKey':'host-1','owner':'real-owner'})
        source=self.source();body=self.body();first=self.send(source,body)
        self.assertEqual(first.status_code,201,first.text)
        self.assertEqual(self.send(source,body).status_code,200)
        self.assertEqual(self.send(source,{**body,'items':[]}).status_code,409)
        detail=self.detail(source);self.assertEqual(detail['total'],1)
        self.assertEqual(detail['items'][0]['freshness'],'current')
        self.assertEqual(detail['items'][0]['observation']['owner'],'reported-owner')
        with self.factory() as db:
            manual=db.scalar(select(Asset).where(Asset.external_key=='host-1'))
            self.assertEqual((manual.name,manual.owner),('Manual','real-owner'))
            imported=db.get(Asset,detail['items'][0]['assetId']);self.assertEqual(imported.source,'inventory');self.assertEqual(imported.owner,'')
            self.assertEqual(db.scalar(select(func.count()).select_from(InventoryRun)),1)
    def test_error_and_empty_snapshot_do_not_refresh_or_delete_nodes(self):
        source=self.source();old=datetime.now(timezone.utc)-timedelta(days=4)
        self.assertEqual(self.send(source,self.body(at=old)).status_code,201)
        error=self.body('failed',at=old+timedelta(days=1),status='error',items=[],errors=[{'code':'access_denied','message':'QA only'}])
        self.assertEqual(self.send(source,error).status_code,201)
        detail=self.detail(source);self.assertEqual(detail['source']['latestAttempt']['status'],'error')
        self.assertEqual(detail['items'][0]['freshness'],'stale')
        self.assertEqual(detail['items'][0]['runId'],detail['recentRuns'][1]['id'])
        self.assertEqual(self.send(source,self.body('empty',at=old+timedelta(days=2),items=[])).status_code,201)
        self.assertEqual(self.detail(source)['total'],1)
        self.assertEqual(self.detail(source)['items'][0]['freshness'],'stale')
    def test_partial_updates_only_observed_nodes_and_keeps_registry_fields(self):
        source=self.source();old=datetime.now(timezone.utc)-timedelta(days=2)
        nodes=[{'externalId':str(i),'name':'Original '+str(i)} for i in (1,2)]
        self.send(source,self.body(at=old,items=nodes));asset_id=self.detail(source)['items'][0]['assetId']
        partial=self.body('partial',items=[{'externalId':'1','name':'Renamed observation'}],status='partial',errors=[{'code':'collection_failed','message':'second node unavailable'}])
        self.assertEqual(self.send(source,partial).status_code,201)
        detail=self.detail(source)
        self.assertEqual([item['freshness'] for item in detail['items']],['current','stale'])
        self.assertEqual(detail['items'][0]['observation']['name'],'Renamed observation')
        with self.factory() as db:self.assertEqual(db.get(Asset,asset_id).name,'Original 1')
    def test_time_order_contract_and_body_limits(self):
        source=self.source();body=self.body();self.send(source,body)
        self.assertEqual(self.send(source,{**body,'externalRunId':'older'}).status_code,409)
        for changes in ({'status':'partial'},{'status':'error'},{'actor':'forged'},{'items':[body['items'][0]]*2},{'observedAt':datetime.now(timezone.utc).replace(tzinfo=None).isoformat()},{'observedAt':(datetime.now(timezone.utc)+timedelta(hours=1)).isoformat()},{'items':body['items']*101}):
            self.assertEqual(self.send(source,{**body,'externalRunId':'invalid',**changes}).status_code,422)
        self.assertEqual(self.client.post(self.root+'/'+source+'/snapshots',headers=self.headers(),content=b'a'*262145).status_code,413)
    def test_roles_disabled_source_scope_and_service_account(self):
        from trace_api.workspace_models import Workspace
        source=self.source();body=self.body()
        self.assertEqual(self.client.get(self.root).status_code,401)
        for role in ('analyst','viewer'):
            self.assertEqual(self.send(source,body,role).status_code,403)
            self.assertEqual(self.client.get(self.root+'/'+source,headers=self.headers(role)).status_code,200)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        headers={**self.headers(),'X-Trace-Workspace':'other'}
        self.assertEqual(self.client.post(self.root+'/'+source+'/snapshots',headers=headers,json=body).status_code,404)
        self.assertEqual(self.client.get(self.root+'/'+source,headers=headers).status_code,404)
        self.client.put(self.root+'/'+source,headers=self.headers(),json={'active':False,'freshnessHours':12})
        self.assertEqual(self.send(source,body).status_code,409)
        token=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'Inventory','scopes':['inventory:read','inventory:write']}).json()['token']
        self.assertEqual(self.client.get(self.root,headers={'Authorization':'Bearer '+token}).status_code,403)
    def test_concurrent_retry_one_run_and_atomic_audit_failure(self):
        source=self.source();body=self.body()
        with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(lambda _:self.send(source,body),range(2)))
        self.assertEqual(sorted(row.status_code for row in responses),[200,201])
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(InventoryObservation)),1)
        other=self.source()
        with patch('trace_api.inventory_intake.audit',side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):self.send(other,body)
        self.assertEqual(self.detail(other)['total'],0)
        self.assertIsNone(self.detail(other)['source']['latestAttempt'])
    def test_kind_conflict_rolls_back_all_new_nodes_and_history_immutable(self):
        source=self.source();old=datetime.now(timezone.utc)-timedelta(days=1)
        self.send(source,self.body(at=old))
        next_body=self.body('next',items=[{'externalId':'temporary','name':'Rollback'}, {'externalId':'host-1','name':'Wrong kind','kind':'cloud'}])
        self.assertEqual(self.send(source,next_body).status_code,409)
        self.assertEqual(self.detail(source)['total'],1)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(InventoryRun)),1)
            self.assertIsNone(db.scalar(select(Asset).where(Asset.name=='Rollback')))
            for model in (InventoryRun,InventoryNode,InventoryObservation):
                with self.assertRaises(ValueError):db.execute(update(model).values(organization_id='forged'))
        with self.factory() as db:
            node=db.scalar(select(InventoryNode));db.delete(node)
            with self.assertRaises(ValueError):db.commit()
    def test_sources_have_separate_identity_namespaces_and_pagination(self):
        a=self.source();b=self.source();body=self.body()
        self.send(a,body);self.send(b,body)
        self.assertNotEqual(self.detail(a)['items'][0]['assetId'],self.detail(b)['items'][0]['assetId'])
        self.assertEqual(self.detail(a,params={'offset':1})['items'],[])
        self.assertEqual(self.detail(a)['total'],1)
    def test_local_collector_outputs_strict_contract_without_network(self):
        import importlib.util
        from pathlib import Path
        from trace_api.inventory_intake import SnapshotInput
        spec=importlib.util.spec_from_file_location('local_collector',Path(__file__).resolve().parents[1]/'tools/collect_host_inventory.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with patch.object(module.platform,'node',return_value='QA node'),patch.object(module.platform,'system',return_value='QA OS'),patch.object(module.platform,'release',return_value='1'):
            body=module.collect('stable-node','run-local')
        parsed=SnapshotInput.model_validate(body)
        self.assertEqual(parsed.items[0].externalId,'stable-node');self.assertEqual(parsed.items[0].platform,'QA OS')
        with patch.object(module.platform,'system',side_effect=OSError('sensitive internal detail')):
            failed=module.collect('stable-node','run-error','QA node')
        self.assertEqual(SnapshotInput.model_validate(failed).status,'error')
        self.assertEqual(failed['items'],[]);self.assertNotIn('sensitive',str(failed))

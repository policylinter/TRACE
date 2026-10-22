import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_module_intake as fixtures
from trace_api.module_intake import ModuleResult,ResultContextBinding
from trace_api.result_contracts import digest
from trace_api.workspace_models import Workspace

class ContextBindingTests(unittest.TestCase):
    setUp=fixtures.ModuleIntakeTests.setUp
    tearDown=fixtures.ModuleIntakeTests.tearDown
    headers=fixtures.ModuleIntakeTests.headers
    prepare=fixtures.ModuleIntakeTests.prepare
    ingest=fixtures.ModuleIntakeTests.ingest
    root=fixtures.ModuleIntakeTests.root
    def asset(self,kind,key):
        response=self.client.post(self.root+'assets',headers=self.headers(),json={'name':key,'kind':kind,'externalKey':key})
        self.assertEqual(response.status_code,201,response.text);return response.json()['id']
    def context(self,key='one'):
        repo=self.asset('repository',key+':repo');build=self.asset('build',key+':build');artifact=self.asset('artifact',key+':artifact')
        common={'observedAt':'2026-10-17T10:00:00Z','evidenceRef':'manifest:'+key}
        response=self.client.post(self.root+'assets/'+build+'/supply-chain',headers=self.headers(),json={**common,'kind':'build','repositoryAssetId':repo,'commitSha':'a'*40,'buildExternalId':key})
        self.assertEqual(response.status_code,201,response.text)
        response=self.client.post(self.root+'assets/'+artifact+'/supply-chain',headers=self.headers(),json={**common,'kind':'artifact','buildAssetId':build,'digest':'sha256:'+'b'*64})
        self.assertEqual(response.status_code,201,response.text)
        return artifact,response.json()

    def test_legacy_payload_hash_and_explicit_null_remain_compatible(self):
        body=self.prepare();first=self.ingest(body)
        self.assertEqual(first.status_code,201,first.text)
        self.assertEqual(first.json()['sha256'],digest(body))
        self.assertNotIn('supplyChainSnapshot',first.json()['payload'])
        replay=self.ingest({**body,'contextAssetId':None,'contextReason':None})
        self.assertEqual(replay.status_code,200)
        self.assertEqual(first.json(),replay.json())
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultContextBinding)),0)

    def test_snapshot_is_server_generated_and_bound_atomically(self):
        body=self.prepare();asset,context=self.context()
        response=self.ingest({**body,'contextAssetId':asset,'contextReason':'Deployment assessment'})
        self.assertEqual(response.status_code,201,response.text)
        result=response.json();snapshot=result['payload']['supplyChainSnapshot']
        self.assertEqual(snapshot,context)
        self.assertEqual(snapshot['context']['digest'],'sha256:'+'b'*64)
        self.assertEqual(result['sha256'],digest(result['payload']))
        self.assertEqual(snapshot['verification'],'operator_declared')
        with self.factory() as db:
            row=db.get(ResultContextBinding,result['id'])
            self.assertEqual(row.context_asset_id,asset);self.assertEqual(row.context_sha256,context['sha256'])
        self.assertEqual(len(self.client.get(self.root+'module-results?contextAssetId='+asset,headers=self.headers()).json()),1)
        self.assertEqual(self.ingest({**body,'externalId':'unbound-second'}).status_code,201)
        filtered=self.client.get(self.root+'module-results?contextAssetId='+asset,headers=self.headers('viewer')).json()
        self.assertEqual([item['id'] for item in filtered],[result['id']])

    def test_partial_missing_or_forged_binding_is_rejected(self):
        body=self.prepare();asset,_=self.context()
        for change in ({'contextAssetId':asset},{'contextReason':'reason'},{'supplyChainSnapshot':{'sha256':'fake'}}):
            self.assertEqual(self.ingest({**body,**change}).status_code,422)
        missing=self.asset('artifact','unregistered')
        self.assertEqual(self.ingest({**body,'contextAssetId':missing,'contextReason':'reason'}).status_code,409)
        self.assertEqual(self.ingest({**body,'contextAssetId':'missing','contextReason':'reason'}).status_code,404)
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)

    def test_foreign_context_and_other_artifact_context_are_rejected(self):
        body=self.prepare();asset,_=self.context()
        own_artifact=self.asset('artifact','another-artifact')
        self.assertEqual(self.ingest({**body,'assetId':own_artifact,'contextAssetId':asset,'contextReason':'reason'}).status_code,422)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        # Admin may access either workspace, but cannot reference an asset from the other one.
        response=self.client.post(self.root+'result-sources',headers={**self.headers(),'X-Trace-Workspace':'other'},json={'name':'Other','module':'appsec'})
        source=response.json()['id']
        other_asset=self.client.post(self.root+'assets',headers={**self.headers(),'X-Trace-Workspace':'other'},json={'name':'Other','kind':'service','externalKey':'other'}).json()['id']
        response=self.client.post(self.root+'module-results',headers={**self.headers(),'X-Trace-Workspace':'other'},json={**body,'sourceId':source,'assetId':other_asset,'contextAssetId':asset,'contextReason':'reason'})
        self.assertEqual(response.status_code,404)
        self.assertEqual(self.client.get(self.root+'module-results?contextAssetId='+asset,headers={**self.headers(),'X-Trace-Workspace':'other'}).status_code,404)

    def test_replay_cannot_attach_context_retroactively(self):
        body=self.prepare();old=self.ingest(body).json();asset,_=self.context()
        self.assertEqual(self.ingest({**body,'contextAssetId':asset,'contextReason':'reason'}).status_code,409)
        with self.factory() as db:
            self.assertNotIn('supplyChainSnapshot',db.get(ModuleResult,old['id']).payload)
            self.assertEqual(db.scalar(select(func.count()).select_from(ResultContextBinding)),0)

    def test_audit_failure_rolls_back_both_and_binding_is_immutable(self):
        body=self.prepare();asset,_=self.context();bound={**body,'contextAssetId':asset,'contextReason':'reason'}
        with patch('trace_api.module_intake.audit',side_effect=RuntimeError('audit failure')):
            with self.assertRaises(RuntimeError):self.ingest(bound)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)
            self.assertEqual(db.scalar(select(func.count()).select_from(ResultContextBinding)),0)
        result=self.ingest(bound).json()
        with self.factory() as db:
            db.get(ResultContextBinding,result['id']).context_sha256='0'*64
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(ResultContextBinding).values(context_sha256='0'*64))

    def test_concurrent_identical_bound_import_has_one_receipt_and_binding(self):
        body=self.prepare();asset,_=self.context();bound={**body,'contextAssetId':asset,'contextReason':'reason'}
        with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(lambda _:self.ingest(bound),range(2)))
        self.assertEqual(sorted(response.status_code for response in responses),[200,201])
        self.assertEqual(responses[0].json(),responses[1].json())
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ResultContextBinding)),1)

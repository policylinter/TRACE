import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_access as fixtures
from trace_api.module_intake import ModuleResult,ResultSource
from trace_api.platform import Asset,PlatformAudit
from trace_api.workspace_models import Workspace

class ModuleIntakeTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    root='/api/v1/platform/'
    def prepare(self):
        source=self.client.post(self.root+'result-sources',headers=self.headers(),json={'name':'Test source','module':'infrastructure'})
        self.assertEqual(source.status_code,201,source.text)
        asset=self.client.post(self.root+'assets',headers=self.headers(),json={'name':'Test asset','kind':'server','externalKey':'test:server'})
        self.assertEqual(asset.status_code,201,asset.text)
        return {'schemaVersion':'trace.intake/1','objectType':'finding','sourceId':source.json()['id'],
            'externalId':'external-1','assetId':asset.json()['id'],'ruleId':'test-rule',
            'title':'Reported exposure','description':'Test only','severity':'high',
            'observedAt':'2026-10-17T12:00:00Z','evidence':[{'label':'Report','reference':'opaque-report-1','sha256':'a'*64}]}
    def ingest(self,body,headers=None):return self.client.post(self.root+'module-results',headers=headers or self.headers(),json=body)

    def test_idempotency_conflict_and_provenance(self):
        body=self.prepare();first=self.ingest(body)
        self.assertEqual(first.status_code,201,first.text)
        second=self.ingest(body);self.assertEqual(second.status_code,200)
        self.assertEqual(first.json(),second.json())
        self.assertEqual(first.json()['receivedBy'],'user:admin')
        self.assertEqual(first.json()['verification'],'not_attested')
        self.assertEqual(self.ingest({**body,'title':'Changed'}).status_code,409)
        with self.factory() as db:
            self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),1)
            self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit).where(PlatformAudit.action=='module-result.received')),1)

    def test_concurrent_replay_inserts_one_result(self):
        body=self.prepare()
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses=list(pool.map(lambda _:self.ingest(body),range(2)))
        self.assertEqual(sorted(r.status_code for r in responses),[200,201])
        self.assertEqual(responses[0].json()['id'],responses[1].json()['id'])

    def test_disabled_source_and_cross_scope_rejected(self):
        body=self.prepare()
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        headers={**self.headers(),'X-Trace-Workspace':'other'}
        self.assertEqual(self.ingest(body,headers).status_code,404)
        self.assertEqual(self.client.get(self.root+'module-results?assetId='+body['assetId'],headers=headers).status_code,404)
        response=self.client.put(self.root+'result-sources/'+body['sourceId'],headers=self.headers(),json={'active':False})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.ingest(body).status_code,409)

    def test_permissions_and_strict_contract(self):
        body=self.prepare()
        self.assertEqual(self.client.get(self.root+'module-results').status_code,401)
        for role in ('analyst','viewer'):
            self.assertEqual(self.ingest(body,self.headers(role)).status_code,403)
            self.assertEqual(self.client.get(self.root+'module-results',headers=self.headers(role)).status_code,200)
        for changes in ({'actor':'forged'},{'objectType':'incident'},{'observedAt':'2026-10-17T12:00:00'},{'evidence':[]},{'organizationId':'other'}):
            self.assertEqual(self.ingest({**body,**changes}).status_code,422)
        token=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'Inventory','scopes':['inventory:write','inventory:read']}).json()['token']
        self.assertEqual(self.ingest(body,{'Authorization':'Bearer '+token}).status_code,403)

    def test_audit_failure_rolls_back_receipt(self):
        body=self.prepare()
        with patch('trace_api.module_intake.audit',side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):self.ingest(body)
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(ModuleResult)),0)

    def test_receipts_are_immutable_and_foreign_references_blocked(self):
        body=self.prepare();result=self.ingest(body).json()
        with self.factory() as db:
            db.get(ModuleResult,result['id']).payload={}
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(ModuleResult).values(payload={}))
        with self.factory() as db:
            db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        with self.factory() as db:
            db.info['workspace_id']='other'
            db.add(Asset(id='other-asset',name='Other',kind='server',external_key='other'));db.commit()
        self.assertEqual(self.ingest({**body,'externalId':'different','assetId':'other-asset'}).status_code,404)

import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from sqlalchemy import select,func,update
import test_access as fixtures
from trace_api.supply_chain import SupplyChainContext
from trace_api.platform import Asset,PlatformAudit
from trace_api.workspace_models import Workspace

class SupplyChainTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    root='/api/v1/platform/assets/'
    def asset(self,kind,key):
        response=self.client.post('/api/v1/platform/assets',headers=self.headers(),json={'name':key,'kind':kind,'externalKey':key})
        self.assertEqual(response.status_code,201,response.text);return response.json()['id']
    def post(self,id,body,role='analyst',extra=None):
        return self.client.post(self.root+id+'/supply-chain',headers={**self.headers(role),**(extra or {})},json=body)
    def setup_chain(self):
        repo=self.asset('repository','repo');build=self.asset('build','build')
        artifact=self.asset('artifact','artifact');deployment=self.asset('deployment','deploy')
        common={'observedAt':'2026-10-18T10:00:00Z','evidenceRef':'operator-report'}
        b={**common,'kind':'build','repositoryAssetId':repo,'commitSha':'a'*40,'buildExternalId':'build-1'}
        a={**common,'kind':'artifact','buildAssetId':build,'digest':'sha256:'+'b'*64}
        d={**common,'kind':'deployment','artifactAssetId':artifact,'environment':'staging','deploymentExternalId':'deploy-1'}
        return (repo,build,artifact,deployment),(b,a,d)

    def test_chain_pins_upstream_digests_and_actor_without_generic_links(self):
        ids,bodies=self.setup_chain();records=[]
        for id,body in zip(ids[1:],bodies):
            response=self.post(id,body);self.assertEqual(response.status_code,201,response.text);records.append(response.json())
        self.assertEqual(records[1]['context']['buildContextSha256'],records[0]['sha256'])
        self.assertEqual(records[2]['context']['artifactContextSha256'],records[1]['sha256'])
        self.assertEqual(records[2]['context']['digest'],'sha256:'+'b'*64)
        self.assertEqual(records[2]['context']['commitSha'],'a'*40)
        self.assertEqual(records[2]['context']['repositoryAssetId'],ids[0])
        self.assertEqual(records[2]['recordedBy'],'user:analyst')
        self.assertEqual(records[2]['verification'],'operator_declared')
        response=self.client.get(self.root+ids[-1]+'/supply-chain',headers=self.headers('viewer'))
        self.assertEqual(response.json()['context'],records[-1])

    def test_no_context_get_is_read_only_and_duplicate_has_single_audit(self):
        ids,bodies=self.setup_chain()
        self.assertIsNone(self.client.get(self.root+ids[1]+'/supply-chain',headers=self.headers()).json()['context'])
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(SupplyChainContext)),0)
        first=self.post(ids[1],bodies[0]);second=self.post(ids[1],bodies[0])
        self.assertEqual(first.status_code,201);self.assertEqual(second.status_code,200)
        self.assertEqual(first.json(),second.json())
        self.assertEqual(self.post(ids[1],{**bodies[0],'commitSha':'c'*40}).status_code,409)
        with self.factory() as db:self.assertEqual(db.scalar(select(func.count()).select_from(PlatformAudit).where(PlatformAudit.action=='supply-chain.recorded')),1)

    def test_concurrent_identical_registration_has_one_snapshot(self):
        ids,bodies=self.setup_chain()
        with ThreadPoolExecutor(max_workers=2) as pool:responses=list(pool.map(lambda _:self.post(ids[1],bodies[0]),range(2)))
        self.assertEqual(sorted(r.status_code for r in responses),[200,201])
        self.assertEqual(responses[0].json(),responses[1].json())

    def test_kind_validation_full_sha_strict_fields_and_missing_upstream(self):
        ids,bodies=self.setup_chain()
        self.assertEqual(self.post(ids[2],bodies[1]).status_code,409)
        self.assertEqual(self.post(ids[0],bodies[0]).status_code,422)
        for body in ({**bodies[0],'commitSha':'abcdef0'},{**bodies[0],'recordedBy':'forged'},{**bodies[0],'observedAt':'2026-10-18T10:00:00'},{**bodies[1],'digest':'latest'}):
            self.assertEqual(self.post(ids[1],body).status_code,422)
        self.assertEqual(self.post(ids[1],{**bodies[0],'repositoryAssetId':ids[2]}).status_code,422)

    def test_scope_and_service_permissions(self):
        ids,bodies=self.setup_chain()
        self.assertEqual(self.post(ids[1],bodies[0],'viewer').status_code,403)
        self.assertEqual(self.client.get(self.root+ids[1]+'/supply-chain').status_code,401)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        self.assertEqual(self.post(ids[1],bodies[0],'admin',{'X-Trace-Workspace':'other'}).status_code,404)
        token=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'Inventory reader','scopes':['inventory:read','inventory:write']}).json()['token']
        headers={'Authorization':'Bearer '+token}
        self.assertEqual(self.client.get(self.root+ids[1]+'/supply-chain',headers=headers).status_code,200)
        self.assertEqual(self.client.post(self.root+ids[1]+'/supply-chain',headers=headers,json=bodies[0]).status_code,403)

    def test_audit_failure_rolls_back_and_context_cannot_be_rewritten(self):
        ids,bodies=self.setup_chain()
        with patch('trace_api.supply_chain.audit',side_effect=RuntimeError('audit failed')):
            with self.assertRaises(RuntimeError):self.post(ids[1],bodies[0])
        with self.factory() as db:self.assertIsNone(db.get(SupplyChainContext,ids[1]))
        self.assertEqual(self.post(ids[1],bodies[0]).status_code,201)
        with self.factory() as db:
            db.get(SupplyChainContext,ids[1]).payload={}
            with self.assertRaises(ValueError):db.commit()
        with self.factory() as db:
            with self.assertRaises(ValueError):db.execute(update(SupplyChainContext).values(payload={}))

    def test_foreign_upstream_and_direct_cross_scope_reference_are_denied(self):
        ids,bodies=self.setup_chain()
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        with self.factory() as db:
            db.info['workspace_id']='other';db.add(Asset(id='foreign-repo',kind='repository',name='Foreign',external_key='foreign'));db.commit()
        self.assertEqual(self.post(ids[1],{**bodies[0],'repositoryAssetId':'foreign-repo'}).status_code,404)
        with self.factory() as db:
            db.add(SupplyChainContext(asset_id=ids[1],repository_id='foreign-repo',payload={},sha256='a'*64,recorded_at='test',recorded_by='test'))
            with self.assertRaises(ValueError):db.commit()

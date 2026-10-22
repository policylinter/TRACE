import unittest
from sqlalchemy import select
import test_access as fixtures
from trace_api.module_intake import ModuleResult
from trace_api.result_contracts import digest
from trace_api.workspace_models import Workspace

class SastIntakeTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    root='/api/v1/platform/'
    def body(self,module='appsec',kind='repository'):
        source=self.client.post(self.root+'result-sources',headers=self.headers(),json={'name':'QA SAST','module':module}).json()
        asset=self.client.post(self.root+'assets',headers=self.headers(),json={'name':'QA repo','kind':kind,'externalKey':'qa:'+source['id']}).json()
        return dict(schemaVersion='trace.intake/1',objectType='finding',sourceId=source['id'],assetId=asset['id'],externalId='qa-1',
            ruleId='python.test.rule',title='Reported test rule',severity='high',observedAt='2026-10-19T10:00:00Z',
            evidence=[dict(label='QA report',reference='qa-only',sha256='a'*64)],
            analysis=dict(kind='sast',scanner='semgrep',location=dict(path='src/api.py',startLine=7,endLine=9)))
    def send(self,body,role='admin'):
        return self.client.post(self.root+'module-results',headers=self.headers(role),json=body)
    def test_roundtrip_hash_and_conflicting_location(self):
        body=self.body();result=self.send(body)
        self.assertEqual(result.status_code,201,result.text)
        record=result.json()
        self.assertEqual(record['payload']['analysis'],body['analysis'])
        self.assertEqual(record['sha256'],digest(record['payload']))
        self.assertEqual(self.send(body).status_code,200)
        changed={**body,'analysis':{**body['analysis'],'location':dict(path='src/api.py',startLine=8,endLine=9)}}
        self.assertEqual(self.send(changed).status_code,409)
        self.assertEqual(self.client.get(self.root+'module-results/'+record['id'],headers=self.headers()).json()['result']['payload'],record['payload'])
    def test_invalid_locations_and_unknown_fields(self):
        body=self.body()
        for path in ('../secret','/etc/passwd','C:/secret','src\\secret.py','a//b','a/./b','a/../b','a\nb',' '):
            with self.subTest(path=path):
                changed={**body,'analysis':{**body['analysis'],'location':dict(path=path,startLine=1,endLine=1)}}
                self.assertEqual(self.send(changed).status_code,422)
        for location in (dict(path='a',startLine=0,endLine=1),dict(path='a',startLine=True,endLine=1),dict(path='a',startLine=9,endLine=8),dict(path='a',startLine=1,endLine=1,code='secret')):
            self.assertEqual(self.send({**body,'analysis':{**body['analysis'],'location':location}}).status_code,422)
        self.assertEqual(self.send({**body,'analysis':{**body['analysis'],'scanner':'unknown'}}).status_code,422)
    def test_source_asset_roles_and_scope(self):
        for module,kind in [('infrastructure','repository'),('appsec','server')]:
            self.assertEqual(self.send(self.body(module,kind)).status_code,422)
        body=self.body()
        for role in ('viewer','analyst'):self.assertEqual(self.send(body,role).status_code,403)
        self.assertEqual(self.send(body).status_code,201)
        self.assertEqual(len(self.client.get(self.root+'module-results?analysisKind=sast',headers=self.headers('viewer')).json()),1)
        with self.factory() as db:db.add(Workspace(id='other',organization_id='default',name='Other'));db.commit()
        headers={**self.headers(),'X-Trace-Workspace':'other'}
        self.assertEqual(self.client.get(self.root+'module-results?analysisKind=sast',headers=headers).json(),[])
        self.assertEqual(self.client.post(self.root+'module-results',headers=headers,json=body).status_code,404)
    def test_exact_filters_pagination_and_legacy_excluded(self):
        body=self.body()
        for n in range(3):
            item={**body,'externalId':'qa-'+str(n),'ruleId':'rule-'+str(n)}
            self.assertEqual(self.send(item).status_code,201)
        legacy={k:v for k,v in body.items() if k!='analysis'};legacy['externalId']='legacy'
        self.assertEqual(self.send(legacy).status_code,201)
        def get(query):return self.client.get(self.root+'module-results?analysisKind=sast&'+query,headers=self.headers()).json()
        first=get('limit=2');second=get('limit=2&offset=2')
        self.assertEqual(len(first),2);self.assertEqual(len(second),1)
        self.assertEqual(len({x['id'] for x in first+second}),3)
        self.assertEqual(len(get('ruleId=rule-1&path=src%2Fapi.py')),1)
        self.assertEqual(get('path=elsewhere.py'),[])
        self.assertEqual(self.client.get(self.root+'module-results?analysisKind=dast',headers=self.headers()).status_code,422)
        with self.factory() as db:
            row=db.scalar(select(ModuleResult).where(ModuleResult.external_id=='legacy'))
            self.assertNotIn('analysis',row.payload)
    def test_read_does_not_modify_payload_or_audit(self):
        body=self.body();self.send(body)
        from trace_api.platform import PlatformAudit
        with self.factory() as db:
            before=[(r.id,r.sha256,r.payload) for r in db.scalars(select(ModuleResult))]
            audits=[r.id for r in db.scalars(select(PlatformAudit))]
        for _ in range(2):self.client.get(self.root+'module-results?analysisKind=sast',headers=self.headers())
        with self.factory() as db:
            self.assertEqual(before,[(r.id,r.sha256,r.payload) for r in db.scalars(select(ModuleResult))])
            self.assertEqual(audits,[r.id for r in db.scalars(select(PlatformAudit))])

if __name__=='__main__':unittest.main()

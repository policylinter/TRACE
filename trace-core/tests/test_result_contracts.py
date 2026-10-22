import unittest
from sqlalchemy import select,func
import test_access as fixtures
from trace_api.models import Finding,Scan,TriageEvent
from trace_api.platform import PlatformAudit
from trace_api.result_contracts import adapt,digest
from trace_api.workspace_models import Workspace

class ResultContractTests(unittest.TestCase):
    setUp=fixtures.AccessTests.setUp
    tearDown=fixtures.AccessTests.tearDown
    headers=fixtures.AccessTests.headers
    path='/api/v1/findings/FND-8F21A3/result'

    def test_read_only_deterministic_and_category_hashes(self):
        with self.factory() as db:
            before=[db.scalar(select(func.count()).select_from(m)) for m in (Finding,TriageEvent,PlatformAudit)]
        first=self.client.get(self.path,headers=self.headers('viewer'))
        self.assertEqual(first.status_code,200,first.text)
        data=first.json()
        self.assertEqual(data,self.client.get(self.path,headers=self.headers('viewer')).json())
        self.assertEqual(data['schemaVersion'],'trace.result/1')
        self.assertEqual(data['objectType'],'finding');self.assertTrue(data['demo'])
        self.assertIsNone(data['observedAt'])
        self.assertEqual(data['snapshotSha256'],digest({k:v for k,v in data.items() if k!='snapshotSha256'}))
        for item in data['evidence']:
            self.assertEqual(item['sha256'],digest(item['payload']))
            self.assertEqual(item['verification'],'not_attested')
        with self.factory() as db:
            self.assertEqual(before,[db.scalar(select(func.count()).select_from(m)) for m in (Finding,TriageEvent,PlatformAudit)])

    def test_workflow_changes_snapshot_without_rewriting_observation(self):
        first=self.client.get(self.path,headers=self.headers()).json()
        response=self.client.put('/api/v1/findings/FND-8F21A3/workflow',headers=self.headers(),json={'status':'in_progress','assignee':'tester','note':'test'})
        self.assertEqual(response.status_code,200,response.text)
        second=self.client.get(self.path,headers=self.headers()).json()
        self.assertNotEqual(first['snapshotSha256'],second['snapshotSha256'])
        self.assertEqual(first['evidence'][0],second['evidence'][0])
        team=next(e for e in second['evidence'] if e['category']=='team_decision')
        self.assertEqual(team['payload']['assignee'],'tester')
        self.assertEqual(team['verification'],'not_attested')

    def test_unknown_engine_and_review_are_not_promoted_to_proof(self):
        with self.factory() as db:
            finding=db.get(Finding,'FND-8F21A3')
            finding.evidence={'model':'claimed-model','headline':'untrusted claim'}
            finding.reviewed=True;finding.confidence=float('inf')
            result=adapt(finding,db.get(Scan,finding.scan_id))
            self.assertIsNone(result.reportedConfidence)
            assessment=next(e for e in result.evidence if e.category=='engine_assessment')
            self.assertEqual(assessment.source,'unknown')
            self.assertTrue(all(e.verification=='not_attested' for e in result.evidence))

    def test_auth_scope_unknown_and_cross_workspace(self):
        self.assertEqual(self.client.get(self.path).status_code,401)
        self.assertEqual(self.client.get('/api/v1/findings/missing/result',headers=self.headers()).status_code,404)
        with self.factory() as db:
            db.add(Workspace(id='second',organization_id='default',name='Second'));db.commit()
        h={**self.headers(),'X-Trace-Workspace':'second'}
        self.assertEqual(self.client.get(self.path,headers=h).status_code,404)
        self.assertEqual(self.client.post(self.path,headers=self.headers(),json={}).status_code,405)

    def test_service_requires_findings_read_and_is_workspace_bound(self):
        for scopes,expected in [(['inventory:read'],403),(['findings:read'],200)]:
            response=self.client.post('/api/v1/access/service-accounts',headers=self.headers(),json={'name':'result reader','scopes':scopes,'expiresInDays':1})
            self.assertEqual(response.status_code,201,response.text)
            headers={'Authorization':'Bearer '+response.json()['token']}
            self.assertEqual(self.client.get(self.path,headers=headers).status_code,expected)

    def test_reported_payload_and_engine_assessment_stay_separate(self):
        with self.factory() as db:
            finding=db.get(Finding,'FND-8F21A3')
            finding.evidence={'usageHits':['reported-path'], 'reasoning':'assessment', 'deepAnalysis':{'source':'rules'}}
            result=adapt(finding,db.get(Scan,finding.scan_id))
            observation=next(e for e in result.evidence if e.category=='reported_observation')
            assessment=next(e for e in result.evidence if e.category=='engine_assessment')
            self.assertNotIn('reasoning',observation.payload)
            self.assertEqual(observation.payload['usageHits'],['reported-path'])
            self.assertEqual(assessment.source,'rules')

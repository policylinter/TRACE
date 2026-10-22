import os,sys,unittest
from pathlib import Path
from unittest.mock import patch
import tempfile
_test_dir = tempfile.TemporaryDirectory(prefix="trace-tests-")
os.environ['TRACE_DATABASE_URL'] = 'sqlite:///' + str(Path(_test_dir.name) / 'test.db').replace('\\', '/')
os.environ['TRACE_AI_PROVIDER'] = 'rules'
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from trace_api import scanners
class ScannerResultsTests(unittest.TestCase):
 def test_missing_scanners_are_explicitly_skipped(self):
  statuses=[]
  with patch.object(scanners,'is_available',return_value=False):
   payloads,used,components=scanners.run_available(Path('.'),statuses)
  self.assertEqual(len(statuses),len(scanners.SCANNERS));self.assertTrue(all(s['status']=='skipped' for s in statuses));self.assertEqual(used,[])
 def test_failed_scanner_is_not_reported_as_completed(self):
  statuses=[]
  with patch.object(scanners,'is_available',side_effect=lambda sid:sid=='trivy'),patch.dict(scanners._RUNNERS,{'trivy':lambda p:None}):
   _,used,_=scanners.run_available(Path('.'),statuses)
  self.assertEqual(statuses[0]['status'],'failed');self.assertEqual(used,[])
 def test_empty_successful_report_is_completed(self):
  statuses=[]
  with patch.object(scanners,'is_available',side_effect=lambda sid:sid=='trivy'),patch.dict(scanners._RUNNERS,{'trivy':lambda p:('trivy.json',{'Results':[]})}):
   payloads,used,_=scanners.run_available(Path('.'),statuses)
  self.assertEqual(statuses[0]['status'],'completed');self.assertEqual(used,['Trivy']);self.assertEqual(len(payloads),1)
 def test_api_returns_additive_scan_status(self):
  from fastapi.testclient import TestClient
  from trace_api.main import app
  with TestClient(app) as client:
   response=client.get('/api/v1/scans');self.assertEqual(response.status_code,200)
   scan=response.json()[0];self.assertIn('scannerResults',scan)
   self.assertEqual(client.get('/api/v1/scans/'+scan['id']+'/sbom').status_code,200)
   self.assertEqual(client.get('/api/v1/scans/'+scan['id']+'/findings').status_code,200)
class WorkflowTests(unittest.TestCase):
 def test_workflow_persists_and_validates_risk(self):
  from fastapi.testclient import TestClient
  from trace_api.main import app
  with TestClient(app) as client:
   scan=client.get('/api/v1/scans').json()[0]
   f=client.get('/api/v1/scans/'+scan['id']+'/findings').json()[0]
   endpoint='/api/v1/findings/'+f['id']+'/workflow'
   self.assertEqual(client.put(endpoint,json={'status':'accepted_risk'}).status_code,422)
   self.assertEqual(client.put(endpoint,json={'status':'invalid'}).status_code,422)
   body={'assignee':'test-developer','status':'in_progress','dueDate':'2026-12-01','note':'Regression test'}
   response=client.put(endpoint,json=body);self.assertEqual(response.status_code,200)
   updated=response.json();self.assertEqual(updated['assignee'],'test-developer');self.assertEqual(updated['workflowStatus'],'in_progress')
   self.assertTrue(any(e['action']=='workflow' for e in client.get('/api/v1/events').json()))
   self.assertEqual(client.post('/api/v1/scans',json={'files':[]}).status_code,422)
   self.assertEqual(client.post('/api/v1/scans',json={'files':[{'name':'unknown.json','json':{}}]}).status_code,422)
class DeduplicationTests(unittest.TestCase):
 def test_different_artifacts_are_not_silently_merged(self):
  from trace_api.pipeline.ingest import RawRecord
  from trace_api.pipeline.dedup import deduplicate
  records=[RawRecord(scanner='Trivy',cve='CVE-TEST',package='org.example:core',version='1'),RawRecord(scanner='Grype',cve='CVE-TEST',package='org.example:api',version='1')]
  self.assertEqual(len(deduplicate(records)),2)
 def test_identical_coordinates_merge_across_scanners(self):
  from trace_api.pipeline.ingest import RawRecord
  from trace_api.pipeline.dedup import deduplicate
  records=[RawRecord(scanner=name,cve='CVE-TEST',package='org.example:core',version='1') for name in ['Trivy','Grype']]
  result=deduplicate(records);self.assertEqual(len(result),1);self.assertEqual(result[0].raw_count,2)

class DeepAnalysisTests(unittest.TestCase):
 def sample(self):
  from trace_api.pipeline.dedup import Candidate
  return Candidate(cve='CVE-TEST', package='example:library', version='1', ecosystem='maven')
 def test_unknown_reachability_cannot_be_cleared_by_model(self):
  from trace_api.pipeline import ai
  from trace_api.pipeline.reachability import ReachabilityResult
  fake=ai.AiProvider();fake.name='fake';fake.complete=lambda *args:{'verdict':'not_affected','confidence':1,'headline':'safe','deepAnalysis':{}}
  with patch.object(ai,'active_provider',return_value=fake):result=ai.assess(self.sample(),ReachabilityResult(reachability='unknown'),[],settings={'models':['test']})
  self.assertEqual(result['verdict'],'needs_review');self.assertTrue(result['evidence']['clamped']);self.assertEqual(result['evidence']['deepAnalysis']['source'],'rules')
 def test_report_rejects_unknown_evidence_references(self):
  from trace_api.pipeline.analysis_report import context_for,normalize_report
  from trace_api.pipeline.reachability import ReachabilityResult
  reached=ReachabilityResult(reachability='unknown')
  context=context_for(self.sample(),reached,[],'test',{})
  report=normalize_report({'observations':[{'statement':'unsupported','evidenceRefs':['frame-999']}]},context,reached,'model')
  self.assertFalse(any(o['statement']=='unsupported' for o in report['observations']));self.assertTrue(report['missingEvidence'])
 def test_prompt_contains_artifacts_and_does_not_assert_live_runtime(self):
  from trace_api.pipeline import ai
  from trace_api.pipeline.reachability import ReachabilityResult
  import json
  reached=ReachabilityResult(reachability='unknown',frames=[{'symbol':'read','location':'app.py','note':'untrusted comment','edge':'data'}],usage_hits=['app.py:3'])
  data=json.loads(ai._build_user_prompt(self.sample(),reached,[],'prod',{'response_language':'ru'}))
  self.assertEqual(data['artifacts']['frames'][0]['evidenceId'],'frame-1');self.assertFalse(data['artifacts']['deploymentProfile']['runtimeVerified']);self.assertEqual(data['artifacts']['usage']['hits'],['app.py:3'])
 def test_incomplete_reachable_path_needs_review(self):
  from trace_api.pipeline import ai
  from trace_api.pipeline.reachability import ReachabilityResult
  with patch.object(ai,'active_provider',return_value=None):result=ai.assess(self.sample(),ReachabilityResult(reachability='reachable'),[])
  self.assertEqual(result['verdict'],'needs_review')
 def test_failed_last_model_is_not_claimed_as_successful(self):
  from trace_api.pipeline import ai
  from trace_api.pipeline.reachability import ReachabilityResult
  fake=ai.AiProvider();fake.name='fake';fake.complete=lambda model,*args:{'verdict':'needs_review','deepAnalysis':{}} if model=='first' else None
  with patch.object(ai,'active_provider',return_value=fake):result=ai.assess(self.sample(),ReachabilityResult(reachability='unknown'),[],settings={'models':['first','failed']})
  self.assertEqual(result['engine'],'fake:first')
 def test_analysis_endpoint_and_settings_validation(self):
  from fastapi.testclient import TestClient
  from trace_api.main import app
  from trace_api.pipeline import ai
  with TestClient(app) as client:
   self.assertEqual(client.put('/api/v1/ai/settings',json={'analysisDepth':'invalid'}).status_code,422)
   self.assertEqual(client.put('/api/v1/ai/settings',json={'temperature':-2}).status_code,422)
   saved=client.put('/api/v1/ai/settings',json={'provider':'rules','analysisDepth':'deep','responseLanguage':'ru','temperature':0,'reviewPass':False})
   self.assertEqual(saved.status_code,200);self.assertEqual(saved.json()['settings']['temperature'],0)
   scan=client.get('/api/v1/scans').json()[0];f=client.get('/api/v1/scans/'+scan['id']+'/findings').json()[0]
   with patch.object(ai,'active_provider',return_value=None):res=client.post('/api/v1/findings/'+f['id']+'/analyze',json={'analysisDepth':'deep'})
   self.assertEqual(res.status_code,200,res.text);self.assertEqual(res.json()['source'],'rules');self.assertIn('missingEvidence',res.json()['finding']['evidence']['deepAnalysis'])

def tearDownModule():
 from trace_api.database import engine
 engine.dispose()
 _test_dir.cleanup()

if __name__=='__main__':unittest.main(verbosity=2)

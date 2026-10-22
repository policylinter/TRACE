import copy,unittest
from unittest.mock import patch
from trace_api.pipeline.ingest import detect_and_parse
from trace_api.pipeline.dedup import deduplicate
import test_access as fixtures

REPORT={'@version':'2.16.0','site':[{'@name':'http://127.0.0.1:9123','alerts':[{'alertRef':'10020','alert':'Missing security header','riskcode':'2','desc':'<p>QA report only</p>','solution':'Configure the header','instances':[{'uri':'http://127.0.0.1:9123/demo?secret=redacted#fragment','method':'GET'}]}]}]}

class ZapParserTests(unittest.TestCase):
 def test_normalizes_without_fetching_or_inventing_cvss(self):
  with patch('urllib.request.urlopen',side_effect=AssertionError('No network')):
   batch=detect_and_parse('report.json',REPORT)
  self.assertEqual(batch.scanner,'ZAP');row=batch.records[0]
  self.assertEqual(row.package,'http://127.0.0.1:9123/demo');self.assertEqual(row.cvss,0);self.assertEqual(row.severity,'medium')
  self.assertEqual(row.dataflow['web']['description'],'QA report only')
  doubled=deduplicate(batch.records*2);self.assertEqual(len(doubled),1);self.assertEqual(len(doubled[0].web_observations),1)
 def test_rejects_bad_report_coordinates(self):
  for value in ['file:///etc/passwd','https://user:password@example.com/a','http://other.test/a','javascript:alert(1)']:
   doc=copy.deepcopy(REPORT);doc['site'][0]['alerts'][0]['instances'][0]['uri']=value
   with self.assertRaises(ValueError):detect_and_parse('report.json',doc)
  for key,value in [('riskcode','9'),('alertRef','bad'),('instances',[])]:
   doc=copy.deepcopy(REPORT);doc['site'][0]['alerts'][0][key]=value
   with self.assertRaises(ValueError):detect_and_parse('report.json',doc)
 def test_empty_report_is_valid_import_not_proof_of_safety(self):
  self.assertEqual(detect_and_parse('report.json',{'@version':'2.16.0','site':[]}).records,[])

class ZapJourneyTests(unittest.TestCase):
 setUp=fixtures.AccessTests.setUp
 tearDown=fixtures.AccessTests.tearDown
 headers=fixtures.AccessTests.headers
 def test_import_review_workflow_vex_and_reassessment(self):
  h=self.headers('admin');base='/api/v1/'
  p=self.client.post(base+'projects',headers=h,json={'name':'ZAP QA','repoUrl':'local:zap-qa'});self.assertEqual(p.status_code,201)
  r=self.client.post(base+'scans',headers=h,json={'projectId':p.json()['id'],'repository':'local:zap-qa','files':[{'name':'zap.json','json':REPORT}]});self.assertEqual(r.status_code,201,r.text)
  scan=r.json();self.assertEqual(scan['scannerResults'][0]['role'],'dast');self.assertEqual(scan['scannerResults'][0]['status'],'imported')
  path=base+'scans/'+scan['id']+'/findings';f=self.client.get(path,headers=h).json()[0]
  self.assertEqual(f['cve'],'ZAP-10020');self.assertEqual(f['verdict'],'needs_review');self.assertEqual(f['reachability'],'unknown');self.assertEqual(f['cvss'],0)
  self.assertNotIn('secret',str(f));self.assertFalse(f['frames']);self.assertTrue(f['evidence']['webObservations'])
  self.assertEqual(self.client.post(base+'findings/'+f['id']+'/review',headers=h,json={'reviewed':True}).status_code,200)
  vex=self.client.get(base+'vex?scan_id='+scan['id']+'&scope=all',headers=h).json()['vulnerabilities'][0]
  self.assertNotIn('scores',vex);self.assertNotIn('cve',vex);self.assertIn('under_investigation',vex['product_status'])
  from trace_api.services import rescan
  with self.factory() as db:
   db.info.update(workspace_id='default',actor='user:admin');from trace_api.models import Scan
   rescan(db,db.get(Scan,scan['id']))
  again=self.client.get(path,headers=h).json()[0];self.assertTrue(again['reviewed']);self.assertEqual(again['evidence']['webObservations'],f['evidence']['webObservations']);self.assertEqual(again['verdict'],'needs_review')
 def test_mixed_invalid_report_is_atomic(self):
  h=self.headers('admin');base='/api/v1/';before=self.client.get(base+'scans',headers=h).json()
  broken=copy.deepcopy(REPORT);broken['site'][0]['alerts'][0]['riskcode']='invalid'
  r=self.client.post(base+'scans',headers=h,json={'project':'No partial import','repository':'local:qa','files':[{'name':'a.json','json':REPORT},{'name':'b.json','json':broken}]})
  self.assertEqual(r.status_code,422);self.assertEqual(self.client.get(base+'scans',headers=h).json(),before)

import copy,unittest
import test_access as fixtures
from test_release_journeys import REPORT
from trace_api.pipeline.ingest import detect_and_parse
class ReportValidationTests(unittest.TestCase):
 setUp=fixtures.AccessTests.setUp
 tearDown=fixtures.AccessTests.tearDown
 headers=fixtures.AccessTests.headers
 def post(self,data,name='qa-report.json',extra=None):
  return self.client.post('/api/v1/scans',headers=self.headers(),json=dict(project='QA invalid must not persist',files=[dict(name=name,json=data)]+(extra or [])))
 def counts(self):
  return tuple(len(self.client.get('/api/v1/'+path,headers=self.headers()).json()) for path in ('projects','scans'))
 def test_filename_cannot_disguise_unknown_json_as_clean_report(self):
  before=self.counts()
  for name in ('trivy.json','grype.json','semgrep.json'):
   self.assertEqual(self.post({},name).status_code,422)
  self.assertEqual(self.counts(),before)
 def test_malformed_structures_return_422_without_partial_writes(self):
  before=self.counts()
  for data in ({'Results':'wrong'},{'Results':[None]},{'Results':[{'Vulnerabilities':[None]}]}, {'matches':[{'vulnerability':'wrong'}]}, {'results':[{'packages':'wrong'}]}, {'results':[{'package':{},'vulnerabilities':[None]}]}, {'results':[],'errors':'wrong'}):
   result=self.post(data);self.assertEqual(result.status_code,422,(data,result.text))
  self.assertEqual(self.counts(),before)
 def test_multi_file_failure_is_atomic(self):
  before=self.counts();result=self.post(REPORT,extra=[dict(name='trivy.json',json={})]);self.assertEqual(result.status_code,422);self.assertEqual(self.counts(),before)
 def test_real_nested_osv_and_legacy_flat_format(self):
  package=dict(package=dict(name='qa-package',version='1.0.0',ecosystem='npm'),vulnerabilities=[dict(id='GHSA-QA-ONLY',database_specific=dict(severity='HIGH'))])
  flat=dict(results=[package]);nested=dict(results=[dict(source=dict(path='qa/package-lock.json'),packages=[package])])
  a=detect_and_parse('osv.json',flat);b=detect_and_parse('osv.json',nested);self.assertEqual(a.records,b.records);self.assertEqual(len(b.records),1)
  result=self.post(nested);self.assertEqual(result.status_code,201,result.text)
  findings=self.client.get('/api/v1/scans/'+result.json()['id']+'/findings',headers=self.headers()).json();self.assertEqual(len(findings),1);self.assertEqual(findings[0]['packageName'],'qa-package')
 def test_nonfinite_scores_and_invalid_file_envelopes_rejected(self):
  value=copy.deepcopy(REPORT);value['Results'][0]['Vulnerabilities'][0]['CVSS']={'vendor':{'V3Score':'Infinity'}}
  self.assertEqual(self.post(value).status_code,422)
  for files in ([None],'wrong',[dict(name=12,json=REPORT)]):
   result=self.client.post('/api/v1/scans',headers=self.headers(),json=dict(files=files));self.assertEqual(result.status_code,422,result.text)

 def test_fixed_versions_preserved_when_reports_merge(self):
  from trace_api.pipeline.dedup import deduplicate
  a=detect_and_parse('trivy.json',REPORT).records
  b=detect_and_parse('grype.json',{'matches':[{'artifact':{'name':'qa-package','version':'1.0.0','type':'npm'},'vulnerability':{'id':'CVE-2024-0001','severity':'HIGH','fix':{'versions':['2.0.0']}}}]}).records
  merged=deduplicate(a+b);self.assertEqual(len(merged),1);self.assertEqual(merged[0].fixed_versions,{'1.0.1','2.0.0'})

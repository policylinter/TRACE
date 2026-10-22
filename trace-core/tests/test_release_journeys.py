"""User journeys across real API contracts, isolated storage and built frontend."""
import json,re,unittest
import test_access as fixtures
from trace_api.pipeline import ai

REPORT={'SchemaVersion':2,'ArtifactName':'QA/package-lock.json','ArtifactType':'filesystem','Results':[{'Target':'QA/package-lock.json','Class':'lang-pkgs','Type':'npm','Vulnerabilities':[{'VulnerabilityID':'CVE-2024-0001','PkgName':'qa-package','InstalledVersion':'1.0.0','FixedVersion':'1.0.1','Severity':'HIGH','Title':'Explicit QA fixture only'}]}]}
class ReleaseJourneyTests(unittest.TestCase):
 setUp=fixtures.AccessTests.setUp
 tearDown=fixtures.AccessTests.tearDown
 headers=fixtures.AccessTests.headers
 def request(self,method,path,body=None,role='admin',status=200):
  result=self.client.request(method,'/api/v1/'+path,headers=self.headers(role),json=body)
  self.assertEqual(result.status_code,status,(method,path,result.text[:500]));return result
 def imported(self):
  project=self.request('POST','projects',dict(name='QA acceptance project',repoUrl='local:qa-acceptance'),status=201).json()
  scan=self.request('POST','scans',dict(projectId=project['id'],repository='local:qa-acceptance',branch='qa',commit='a'*40,files=[dict(name='trivy-qa.json',json=REPORT)]),status=201).json()
  self.assertTrue(any(x['status']=='imported' for x in scan['scannerResults']))
  rows=self.request('GET','scans/'+scan['id']+'/findings').json();self.assertEqual(len(rows),1)
  self.assertEqual(rows[0]['fixedIn'],'1.0.1')
  return project,scan,rows[0]
 def test_import_triage_export_and_linked_investigation(self):
  project,scan,finding=self.imported();fid=finding['id'];sid=scan['id']
  reviewed=self.request('POST','findings/'+fid+'/review',dict(reviewed=True),role='analyst').json();self.assertTrue(reviewed['reviewed'])
  original=finding['reachability'];self.request('POST','findings/'+fid+'/suppress',dict(reason='QA operator exclusion'),role='analyst')
  restored=self.request('POST','findings/'+fid+'/unsuppress',role='analyst').json();self.assertEqual(restored['reachability'],original)
  decision=self.request('PUT','findings/'+fid+'/workflow',dict(status='in_progress',assignee='QA owner',dueDate='2099-01-01',note='QA journey'),role='analyst').json();self.assertEqual(decision['assignee'],'QA owner')
  for path in ['scans/'+sid+'/sbom','scans/'+sid+'/reachability','scans/'+sid+'/funnel','scans/'+sid+'/compliance','scans/'+sid+'/policy','findings/'+fid+'/result','vex/meta?scan_id='+sid]:self.request('GET',path,role='viewer')
  vex=self.request('GET','vex?scan_id='+sid+'&scope=all&download=1',role='viewer').json();self.assertEqual(vex['document']['csaf_version'],'2.0');self.assertEqual(len(vex['vulnerabilities']),1);self.assertIn('under_investigation',vex['vulnerabilities'][0]['product_status'])
  case=self.request('POST','platform/security-records',dict(kind='incident',title='QA incident from import',description='Manual assessment, no exploitation claim',links=[dict(targetKind='finding',targetId=fid,reason='QA imported finding')]),role='analyst',status=201).json()
  related=self.request('GET','platform/security-records/related?targetKind=finding&targetId='+fid,role='viewer').json();self.assertEqual(related[0]['id'],case['id'])
  self.request('PUT','platform/security-records/'+case['id']+'/decision',dict(expectedRevision=0,status='investigating',owner='QA owner',reason='QA investigation'),role='analyst')
  detail=self.request('GET','platform/security-records/'+case['id'],role='viewer').json();self.assertEqual(detail['historyTotal'],2)
  persisted=self.request('GET','scans/'+sid+'/findings',role='viewer').json()[0];self.assertEqual(persisted['workflowStatus'],'in_progress')
 def test_invalid_import_never_creates_scan_or_project(self):
  before=self.request('GET','scans').json();projects=self.request('GET','projects').json()
  for files in ([],[dict(name='unknown.json',json={})],[dict(name='bad.json',content='{broken')]):
   self.request('POST','scans',dict(project='Should not exist',repository='QA only',files=files),status=422)
  self.assertEqual(self.request('GET','scans').json(),before);self.assertEqual(self.request('GET','projects').json(),projects)
 def test_all_page_read_contracts_and_missing_objects(self):
  paths=['health','projects','scans','events','integrations','advisories','compliance/standards','platform/assets','platform/modules','platform/result-sources','platform/module-results','platform/semgrep-batches','platform/sast/targets','platform/sast/jobs','platform/sast/executions','platform/security-records/schema','platform/security-records?kind=incident','platform/security-records?kind=risk','workspaces','access/context']
  for path in paths:self.request('GET',path,role='viewer')
  for path in ['ai/settings','settings/policy']:
   self.request('GET',path,role='viewer',status=403);self.request('GET',path,role='admin')
  for path in ['scans/missing','findings/missing/result','platform/assets/missing','platform/security-records/missing']:
   self.request('GET',path,role='viewer',status=404)
 def test_production_html_and_every_referenced_asset_exist(self):
  response=self.client.get('/');self.assertEqual(response.status_code,200)
  self.assertIn('<html',response.text.lower());self.assertNotIn('/@vite/client',response.text)
  assets=re.findall(r'(?:src|href)=[\"\'](/assets/[^\"\']+)',response.text);self.assertTrue(assets)
  for asset in assets:
   reply=self.client.get(asset);self.assertEqual(reply.status_code,200,asset);self.assertIn('immutable',reply.headers.get('cache-control',''))
  self.assertIn('no-cache',response.headers.get('cache-control',''))

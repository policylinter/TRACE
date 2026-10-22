import tempfile,unittest,json
from pathlib import Path
from unittest.mock import patch
from trace_api.python_sast import scan
from trace_api.pipeline.ingest import detect_and_parse
import test_access as fixtures
class PythonAstTests(unittest.TestCase):
 def test_rules_aliases_and_safe_variants(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);(root/'app.py').write_text('import pickle as p\nfrom subprocess import run as run_cmd\nimport yaml\neval(value)\np.loads(value)\nyaml.load(value)\nrun_cmd(value,shell=True)\nyaml.load(value,Loader=yaml.SafeLoader)\nrun_cmd(value,shell=False)\n')
   value=scan(root);self.assertEqual([x['ruleId'] for x in value['results']],['TRACE-PY-001','TRACE-PY-002','TRACE-PY-003','TRACE-PY-004']);self.assertEqual([x['line'] for x in value['results']],[4,5,6,7]);self.assertFalse(value['coverage']['exploitationVerified'])
   records=detect_and_parse('native.json',value).records;self.assertEqual(len(records),4);self.assertTrue(all(x.ecosystem=='code' for x in records))
 def test_dependency_directories_skipped_source_never_executed(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);(root/'.venv').mkdir();(root/'.venv/x.py').write_text('eval(value)');(root/'app.py').write_text('raise RuntimeError("MUST NOT EXECUTE")\n')
   value=scan(root);self.assertEqual(value['results'],[]);self.assertEqual(value['coverage']['filesScanned'],1)
 def test_syntax_size_and_result_limits_are_reported(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);(root/'a.py').write_text('def broken(');(root/'b.py').write_text('eval(x)\neval(y)\n');(root/'c.py').write_text('x'*300000)
   value=scan(root);self.assertEqual(len(value['errors']),1);self.assertEqual(value['coverage']['filesSkipped'],1)
   with patch('trace_api.python_sast.MAX_RESULTS',1):self.assertTrue(scan(root)['coverage']['limited'])
 def test_invalid_internal_report_rejected(self):
  for data in ({'schemaVersion':'trace.python-sast/1'},{'schemaVersion':'trace.python-sast/1','scanner':'TRACE Python AST','results':[{'ruleId':'TRACE-PY-001','path':'../secret.py','line':1}],'errors':[],'coverage':{}}):
   with self.assertRaises(ValueError):detect_and_parse('native.json',data)
class PythonAstJourneyTests(unittest.TestCase):
 setUp=fixtures.AccessTests.setUp
 tearDown=fixtures.AccessTests.tearDown
 headers=fixtures.AccessTests.headers
 def test_real_local_source_to_saved_finding_review_and_export(self):
  root=Path(self.temp.name)/'source';root.mkdir();(root/'app.py').write_text('def handler(value):\n    return eval(value)\n')
  with patch('trace_api.scanners.is_available',side_effect=lambda id:id=='python-ast'):
   response=self.client.post('/api/v1/scans/from-source',headers=self.headers(),json={'source':str(root),'project':'Native AST QA','wait':True,'ai':{'provider':'rules'}})
  self.assertEqual(response.status_code,201,response.text[:800]);value=response.json();self.assertEqual(value['scanners'],['TRACE Python AST']);sid=value['scan']['id']
  rows=self.client.get('/api/v1/scans/'+sid+'/findings',headers=self.headers()).json();self.assertEqual(len(rows),1);f=rows[0];self.assertEqual(f['verdict'],'needs_review');self.assertEqual(f['reachability'],'unknown');self.assertEqual(f['evidence']['nativeObservations'][0]['line'],2);self.assertEqual(f['frames'][0]['location'],'app.py')
  self.assertEqual(self.client.post('/api/v1/findings/'+f['id']+'/review',headers=self.headers('analyst'),json={'reviewed':True}).status_code,200)
  vex=self.client.get('/api/v1/vex?scan_id='+sid+'&scope=all',headers=self.headers()).json();self.assertIn('under_investigation',vex['vulnerabilities'][0]['product_status']);self.assertNotIn('cve',vex['vulnerabilities'][0]);self.assertNotIn('scores',vex['vulnerabilities'][0]);self.assertEqual(vex['vulnerabilities'][0]['ids'][0]['text'],'TRACE-PY-001')
  from trace_api import services
  with self.factory() as db:
   from trace_api.models import Scan
   item=db.get(Scan,sid);services.rescan(db,item,ai_settings={'provider':'rules'});self.assertTrue(item.findings[0].evidence['nativeObservations']);self.assertEqual(item.findings[0].verdict,'needs_review')

class TimestampTests(unittest.TestCase):
 def test_sqlite_utc_timestamps_are_not_interpreted_as_local_time(self):
  from datetime import datetime,timezone
  from trace_api.serializers import _iso
  self.assertEqual(_iso(datetime(2026,10,21,17,53)), '2026-10-21T17:53:00Z')
  self.assertEqual(_iso(datetime(2026,10,21,17,53,tzinfo=timezone.utc)), '2026-10-21T17:53:00Z')
  self.assertEqual(_iso(None),'')

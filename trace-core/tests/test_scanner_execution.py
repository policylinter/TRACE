import json,subprocess,unittest
from pathlib import Path
from unittest.mock import patch
from trace_api import scanners as s
class ScannerExecutionTests(unittest.TestCase):
 def run_report(self,id,payload):
  spec=s.SPECS[id];statuses=[]
  with patch.object(s,'SCANNERS',[spec]),patch.object(s,'is_available',return_value=True),patch.dict(s._RUNNERS,{id:lambda path:(id+'.json',payload)}):
   result=s.run_available(Path('.'),statuses)
  return result,statuses[0]
 def test_wrong_or_unknown_report_cannot_be_successful(self):
  for name,payload in [('trivy',{}),('trivy',{'matches':[]}),('grype',{'matches':'bad'}),('osv',{'results':[None]}),('semgrep',{'results':[],'errors':'bad'}),('syft',{'bomFormat':'CycloneDX','components':[None]})]:
   with self.subTest(name=name):
    result,status=self.run_report(name,payload);self.assertEqual(status['status'],'failed');self.assertEqual(result,([],[],[]))
 def test_valid_empty_report_means_engine_executed(self):
  result,status=self.run_report('trivy',{'Results':[]});self.assertEqual(status['status'],'completed');self.assertEqual(result[1],['Trivy'])
 def test_semgrep_errors_and_skips_are_partial(self):
  for extra in ({'errors':[{'type':'ParseError'}]},{'paths':{'skipped':[{'path':'too-large.py'}]}},{'skipped_rules':['rule']}):
   data={'results':[],'errors':[],**extra};result,status=self.run_report('semgrep',data);self.assertEqual(status['status'],'partial');self.assertEqual(result[1],['Semgrep'])
 def test_osv_and_syft_process_failure_never_accepted_as_clean(self):
  for runner in (s.run_osv,s.run_syft):
   with patch.object(s,'_run',return_value=subprocess.CompletedProcess([],2,json.dumps({'results':[]}),'')):
    self.assertIsNone(runner(Path('.')))
 def test_trivy_failure_never_accepted_even_when_output_exists(self):
  def run(cmd,**kwargs):
   Path(cmd[cmd.index('--output')+1]).write_text('{"Results":[]}');return subprocess.CompletedProcess(cmd,2,'','')
  with patch.object(s,'_run',side_effect=run):self.assertIsNone(s.run_trivy(Path('.')))

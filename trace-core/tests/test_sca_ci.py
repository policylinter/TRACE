import unittest
from tools.run_sca_ci import gate
class ScaCiTests(unittest.TestCase):
 def report(self,severity=None):
  return {'results':[{'packages':[{'package':{'name':'qa-only','version':'1','ecosystem':'npm'},'vulnerabilities':[] if severity is None else [{'id':'QA-1','database_specific':{'severity':severity}}]}]}]}
 def test_clean_covered_report_passes(self):self.assertEqual(gate(self.report())['status'],'passed')
 def test_high_blocks_and_unknown_does_not_silently_pass(self):
  self.assertEqual(gate(self.report('HIGH'))['blocking'],1);self.assertEqual(gate(self.report('UNKNOWN'))['blocking'],1)
  self.assertEqual(gate(self.report('MODERATE'))['blocking'],0)
 def test_missing_package_coverage_fails(self):
  with self.assertRaises(ValueError):gate({'results':[]})

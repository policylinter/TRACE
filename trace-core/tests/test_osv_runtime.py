import copy,unittest
from trace_api.pipeline.ingest import detect_and_parse

class OsvRuntimeTests(unittest.TestCase):
 def report(self):
  return {'results':[{'packages':[{'package':{'name':'lodash','version':'4.17.20','ecosystem':'npm'},'vulnerabilities':[{'id':'GHSA-qa-only','database_specific':{'severity':'MODERATE'},'affected':[{'package':{'name':'lodash','ecosystem':'npm'},'ranges':[{'events':[{'introduced':'0'},{'fixed':'4.17.21'}]}]},{'package':{'name':'different-package','ecosystem':'npm'},'ranges':[{'events':[{'fixed':'99.0'}]}]}]}]}]}]}
 def test_moderate_and_package_specific_fixed_version(self):
  rows=detect_and_parse('osv.json',self.report()).records
  self.assertEqual(rows[0].severity,'medium');self.assertEqual(rows[0].fixed_versions,('4.17.21',))
 def test_rejects_malformed_fixed_version(self):
  data=self.report();data['results'][0]['packages'][0]['vulnerabilities'][0]['affected'][0]['ranges'][0]['events'][1]['fixed']=17
  with self.assertRaises(ValueError):detect_and_parse('osv.json',data)

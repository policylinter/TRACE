import json,threading,unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest.mock import patch
import test_access as fixtures
from tools.dast_demo_app import Demo
from trace_api.http_baseline import probe,validate_url

class Handler(Demo):
 requests=[]
 def do_GET(self):
  self.requests.append(self.path)
  if self.path=='/redirect':
   self.send_response(302);self.send_header('Location','http://example.com/');self.end_headers();return
  super().do_GET()

class HttpBaselineTests(unittest.TestCase):
 setUp=fixtures.AccessTests.setUp
 tearDown=fixtures.AccessTests.tearDown
 headers=fixtures.AccessTests.headers
 def start(self):
  server=ThreadingHTTPServer(('127.0.0.1',0),Handler);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
  self.addCleanup(server.server_close);self.addCleanup(server.shutdown);Handler.requests=[]
  return 'http://127.0.0.1:'+str(server.server_port)
 def config(self,url):
  h=self.headers('admin');r=self.client.post('/api/v1/projects',headers=h,json={'name':'Local HTTP fixture','repoUrl':'local:http-fixture'});self.assertEqual(r.status_code,201)
  target={'id':'fixture','name':'Local HTTP test','workspaceId':'default','projectId':r.json()['id'],'url':url}
  path=Path(self.temp.name)/'dast.json';path.write_text(json.dumps([target]),encoding='utf-8');self.stack.enter_context(patch.dict('os.environ',{'TRACE_DAST_TARGETS_FILE':str(path)}));return path
 def test_real_get_persisted_unknown_findings_and_clean_variant(self):
  url=self.start();path=self.config(url+'/missing');h=self.headers('admin')
  for role in ('viewer','analyst'):
   self.assertEqual(self.client.post('/api/v1/platform/dast/checks',headers=self.headers(role),json={'targetId':'fixture'}).status_code,403)
  r=self.client.post('/api/v1/platform/dast/checks',headers=h,json={'targetId':'fixture'});self.assertEqual(r.status_code,201,r.text)
  self.assertEqual(Handler.requests,['/missing']);s=r.json();self.assertEqual(s['status'],'partial');self.assertEqual(s['counts']['total'],3)
  rows=self.client.get('/api/v1/scans/'+s['id']+'/findings',headers=h).json()
  self.assertTrue(all(f['verdict']=='needs_review' and f['reachability']=='unknown' and f['cvss']==0 for f in rows));self.assertTrue(all(f['evidence']['model']=='TRACE HTTP Baseline' for f in rows))
  target=json.loads(path.read_text());target[0]['url']=url+'/secured';path.write_text(json.dumps(target))
  r=self.client.post('/api/v1/platform/dast/checks',headers=h,json={'targetId':'fixture'});self.assertEqual(r.status_code,201,r.text);self.assertEqual(r.json()['counts']['total'],0);self.assertEqual(r.json()['status'],'partial')
 def test_no_redirect_or_arbitrary_target(self):
  url=self.start();self.config(url+'/redirect');h=self.headers('admin')
  before=self.client.get('/api/v1/scans',headers=h).json()
  self.assertEqual(self.client.post('/api/v1/platform/dast/checks',headers=h,json={'targetId':'fixture'}).status_code,502)
  self.assertEqual(Handler.requests,['/redirect']);self.assertEqual(self.client.get('/api/v1/scans',headers=h).json(),before)
  self.assertEqual(self.client.post('/api/v1/platform/dast/checks',headers=h,json={'targetId':'missing'}).status_code,404)
  for url in ('http://example.com:8080/','http://localhost:8878/','http://127.0.0.1:80/','http://user:pass@127.0.0.1:8878/','http://127.0.0.1:8878/?secret=x','file:///tmp'):
   with self.assertRaises(ValueError):validate_url(url)
 def test_configuration_rechecked_before_save(self):
  url=self.start();path=self.config(url+'/missing');h=self.headers('admin')
  def changed(value):
   result=probe(value);path.write_text('[]');return result
  with patch('trace_api.http_baseline.probe',side_effect=changed):
   result=self.client.post('/api/v1/platform/dast/checks',headers=h,json={'targetId':'fixture'})
  self.assertEqual(result.status_code,404)

from contextlib import closing
import importlib.util,json,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('release_launcher',ROOT/'run_release.py');release=importlib.util.module_from_spec(spec);spec.loader.exec_module(release)
class ReleaseLauncherTests(unittest.TestCase):
 def setUp(self):
  self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.front=self.root/'dist';self.front.mkdir();(self.front/'assets').mkdir()
  (self.front/'assets/app.js').write_text('// QA');(self.front/'index.html').write_text('<script type="module" src="/assets/app.js"></script>')
  self.db=self.root/'trace.db'
  with closing(sqlite3.connect(self.db)) as db:
   for table in ('projects','scans','findings'):db.execute('create table '+table+' (id integer primary key)')
   db.execute('insert into findings values(42)');db.commit()
 def tearDown(self):self.temp.cleanup()
 def test_preflight_is_read_only(self):
  before=self.db.read_bytes();value=release.preflight(self.db,self.front,5173);self.assertEqual(value['mode'],'single_process_static_release');self.assertEqual(self.db.read_bytes(),before)
 def test_missing_asset_and_development_html_fail(self):
  (self.front/'assets/app.js').unlink()
  with self.assertRaises(release.ReleaseError):release.inspect_frontend(self.front)
  (self.front/'index.html').write_text('<script src="/src/main.tsx"></script>')
  with self.assertRaises(release.ReleaseError):release.inspect_frontend(self.front)
 def test_missing_or_wrong_database_fails_without_creating(self):
  path=self.root/'missing.db'
  with self.assertRaises(release.ReleaseError):release.preflight(path,self.front,5173)
  self.assertFalse(path.exists());self.assertEqual(release.preflight(path,self.front,5173,True)['databaseState'],'new_database_requested');self.assertFalse(path.exists())
  bad=self.root/'bad.db';bad.write_text('not sqlite')
  with self.assertRaises(release.ReleaseError):release.preflight(bad,self.front,5173)
 def test_asset_traversal_and_port_rejected(self):
  (self.front/'index.html').write_text('<script src="/../secret.js"></script>');(self.root/'secret.js').write_text('QA')
  with self.assertRaises(release.ReleaseError):release.inspect_frontend(self.front)
  with self.assertRaises(release.ReleaseError):release.preflight(self.db,self.front,1)
 def test_explicit_bad_frontend_does_not_silently_fall_back(self):
  with self.assertRaises(release.ReleaseError):release.frontend_path(self.root/'missing')
 def test_check_cli_does_not_start_server_or_modify_database(self):
  before=self.db.read_bytes();result=subprocess.run([sys.executable,str(ROOT/'run_release.py'),'--check','--database',str(self.db),'--frontend',str(self.front)],capture_output=True,text=True,timeout=10)
  self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(json.loads(result.stdout)['assets'],['assets/app.js']);self.assertEqual(self.db.read_bytes(),before)

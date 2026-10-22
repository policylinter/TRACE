import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT=Path(__file__).resolve().parents[1]/'tools/run_sast_local.py'
spec=importlib.util.spec_from_file_location('sast_local_runner',SCRIPT)
runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)

@unittest.skipUnless(shutil.which('git'),'local Git required')
class LocalSastRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='trace-runner-test-');self.root=Path(self.temp.name)
        self.repo=self.root/'repo';self.repo.mkdir();self.rules=self.root/'rules.yaml';self.rules.write_text('rules: []\n')
        def git(*args):return subprocess.check_output([shutil.which('git'),'-c','safe.directory='+str(self.repo),'-C',str(self.repo),*args],stderr=subprocess.DEVNULL).decode().strip()
        git('init');(self.repo/'sample.py').write_text('COMMITTED_ONLY\n')
        git('add','sample.py');git('-c','user.name=QA','-c','user.email=qa@example.test','commit','-m','QA fixture')
        self.commit=git('rev-parse','HEAD')
        (self.repo/'sample.py').write_text('DIRTY_WORKTREE\n');(self.repo/'untracked-secret.txt').write_text('DO_NOT_READ\n')
        self.mock=self.root/'mock_scanner.py'
        self.mock.write_text('''import json,os,pathlib,sys
assert pathlib.Path('sample.py').read_text()=='COMMITTED_ONLY\\n'
assert not pathlib.Path('untracked-secret.txt').exists()
assert 'TRACE_API_KEY' not in os.environ and 'SEMGREP_APP_TOKEN' not in os.environ
assert '--metrics=off' in sys.argv and '--disable-version-check' in sys.argv
print(json.dumps(dict(version='mock-only',errors=[],paths=dict(scanned=['sample.py'],skipped=[]),skipped_rules=[],results=[dict(check_id='qa.runner.rule',path='sample.py',start={'line':1},end={'line':1},extra={'severity':'ERROR','message':'DO_NOT_EXPORT'})])))
''',encoding='utf-8')
        self.real_bounded=runner.bounded
    def tearDown(self):self.temp.cleanup()
    def execute(self):
        def invoke(command,*args,**kwargs):
            if command[1]=='scan':command=[sys.executable,str(self.mock),*command[1:]]
            return self.real_bounded(command,*args,**kwargs)
        with patch.object(runner,'bounded',side_effect=invoke),patch.dict(os.environ,TRACE_API_KEY='DO_NOT_PASS',SEMGREP_APP_TOKEN='DO_NOT_PASS'):
            return runner.execute(repo=self.repo,commit=self.commit,rules=self.rules,output_dir=self.root/'out',source_id='source',asset_id='asset',run_id='run',scanner=sys.executable,timeout=2)
    def test_pinned_tree_dirty_preserved_and_batch_compatible(self):
        receipt,manifest=self.execute()
        self.assertEqual(receipt['source']['commit'],self.commit)
        self.assertEqual(receipt['source']['fileCount'],1)
        self.assertFalse(receipt['attested']);self.assertFalse(receipt['networkIsolationVerified'])
        self.assertEqual((self.repo/'sample.py').read_text(),'DIRTY_WORKTREE\n')
        self.assertEqual((self.repo/'untracked-secret.txt').read_text(),'DO_NOT_READ\n')
        from trace_api.semgrep_batch import BatchInput
        results=[json.loads((self.root/'out'/name).read_text()) for name in manifest['files']]
        BatchInput.model_validate(dict(manifest=manifest,results=results))
        self.assertNotIn('DO_NOT_EXPORT',json.dumps(results))
        self.assertTrue((self.root/'out/manifest.json').exists())
        self.assertFalse((self.root/'out/semgrep.json').exists())
    def test_scanner_failure_and_changed_snapshot_have_no_complete_export(self):
        for program in ('raise SystemExit(2)','import pathlib;pathlib.Path("sample.py").write_text("changed");print("{}")'):
            self.mock.write_text(program)
            with self.assertRaises(runner.ExecutionFailure):self.execute()
            self.assertFalse((self.root/'out').exists())
    def test_timeout_and_output_limits(self):
        env=runner.clean_env(self.root)
        with self.assertRaisesRegex(runner.ExecutionFailure,'timeout'):
            runner.bounded([sys.executable,'-c','import time;time.sleep(20)'],self.root,env,.2,1024)
        for stream in ('stdout','stderr'):
            with self.assertRaises(runner.ExecutionFailure):
                runner.bounded([sys.executable,'-c',f'import sys;sys.{stream}.write("x"*100000)'],self.root,env,2,1024)
    def test_refuses_missing_tools_context_and_existing_output(self):
        for name in ('nested/.git/config','CON','dir/LPT1.txt','dir/name.','dir/name '):
            with self.assertRaises(runner.ExecutionFailure):runner.validate_name(name)
        with patch.object(runner.shutil,'which',return_value=None):
            with self.assertRaisesRegex(runner.ExecutionFailure,'unavailable'):self.execute()
        original_commit=self.commit;self.commit='main'
        with self.assertRaisesRegex(runner.ExecutionFailure,'invalid_context'):self.execute()
        self.assertFalse((self.root/'out').exists())
        self.commit=original_commit;(self.root/'out').mkdir();(self.root/'out/keep.txt').write_text('preserved')
        with self.assertRaisesRegex(runner.ExecutionFailure,'invalid_paths'):self.execute()
        self.assertEqual((self.root/'out/keep.txt').read_text(),'preserved')
        result=subprocess.run([sys.executable,str(SCRIPT),'--repo',str(self.repo),'--commit',self.commit,
            '--rules',str(self.rules),'--output-dir',str(self.root/'cli-out'),'--source-id','source','--asset-id','asset',
            '--run-id','cli-qa','--scanner','TRACE_MISSING_SCANNER_FOR_QA'],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0);self.assertFalse((self.root/'cli-out').exists())
        self.assertNotIn('DIRTY_WORKTREE',result.stdout+result.stderr)
    def test_rejects_symlink_tree_without_touching_worktree(self):
        if os.name=='nt':
            # Git index can represent symlinks even without Windows symlink privilege.
            git=shutil.which('git');prefix=[git,'-c','safe.directory='+str(self.repo),'-C',str(self.repo)]
            oid=subprocess.check_output(prefix+['hash-object','-w','--stdin'],input=b'outside\n').decode().strip()
            subprocess.check_call(prefix+['update-index','--add','--cacheinfo','120000,'+oid+',link'],stdout=subprocess.DEVNULL)
            subprocess.check_call(prefix+['-c','user.name=QA','-c','user.email=qa@example.test','commit','-m','symlink'],stdout=subprocess.DEVNULL)
            self.commit=subprocess.check_output(prefix+['rev-parse','HEAD']).decode().strip()
            with self.assertRaisesRegex(runner.ExecutionFailure,'unsupported_tree_entry'):self.execute()
            self.assertFalse((self.root/'out').exists())

if __name__=='__main__':unittest.main()

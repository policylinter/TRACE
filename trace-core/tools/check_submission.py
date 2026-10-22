"""Reproducible local acceptance. Tests use temporary databases, never live data."""
from contextlib import redirect_stderr,redirect_stdout
from datetime import datetime,timezone
import importlib.util,json,os,sys,unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'tests'))

def main():
    os.environ['TRACE_AI_PROVIDER']='rules'
    output=ROOT/'work';output.mkdir(exist_ok=True)
    checks=[]
    try:
        import run_release
        value=run_release.preflight(ROOT/'trace_api/trace-platform.db',run_release.frontend_path(),5173)
        checks.append(dict(name='release_files_and_database',passed=True,detail=value['databaseState']))
    except Exception as exc:checks.append(dict(name='release_files_and_database',passed=False,detail=str(exc)))
    documents=['docs/platform/03-capabilities.md','docs/platform/36-release-acceptance.md','SUBMISSION.md']
    checks.append(dict(name='submission_documents',passed=all((ROOT/x).is_file() for x in documents)))
    names=['test_release_journeys.ReleaseJourneyTests','test_python_sast.PythonAstTests','test_python_sast.PythonAstJourneyTests','test_zap_import.ZapParserTests','test_zap_import.ZapJourneyTests','test_http_baseline.HttpBaselineTests','test_osv_runtime.OsvRuntimeTests','test_sca_ci.ScaCiTests']
    with (output/'submission-check.log').open('w',encoding='utf-8') as log,redirect_stdout(log),redirect_stderr(log):
        suite=unittest.defaultTestLoader.loadTestsFromNames(names)
        result=unittest.TextTestRunner(stream=log,verbosity=2).run(suite)
    checks.append(dict(name='isolated_user_journeys',passed=result.wasSuccessful(),tests=result.testsRun,failures=len(result.failures),errors=len(result.errors)))
    passed=all(x['passed'] for x in checks)
    receipt=dict(checkedAt=datetime.now(timezone.utc).isoformat(),status='CORE_ACCEPTANCE_PASSED' if passed else 'NOT_READY',checks=checks,
        scope='Local platform prototype; not certification of external scanners or all corporate security capabilities',
        externalRequirements=['Full DAST beyond three loopback header rules and explicit target configuration','External CI provider configuration','Semgrep native engine readiness'])
    from trace_api.config import _local_osv_ready
    receipt['localOsvVerified']=_local_osv_ready()
    (output/'submission-check.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2),encoding='utf-8')
    print(receipt['status']);print('Tests:',result.testsRun);print('Receipt:',output/'submission-check.json');print('Scope:',receipt['scope'])
    return 0 if passed else 1

if __name__=='__main__':raise SystemExit(main())

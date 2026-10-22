"""Test the real local engine on generated source, never on user repositories."""
import json,os,subprocess,sys,tempfile
from pathlib import Path
from datetime import datetime,timezone
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.run_sast_local import clean_env

def check(scanner=None):
    scanner=scanner or ROOT/'.tools/semgrep'/('Scripts/pysemgrep.exe' if os.name=='nt' else 'bin/semgrep')
    value=dict(checkedAt=datetime.now(timezone.utc).isoformat(),version=None,ready=False,code='not_installed')
    if not scanner.is_file():return value
    with tempfile.TemporaryDirectory(prefix='trace-semgrep-check-') as tmp:
        folder=Path(tmp);home=folder/'home';home.mkdir();source=folder/'source';source.mkdir()
        (source/'app.py').write_text('def parse_user(value):\n    return eval(value)\n')
        rules=folder/'rules.yaml';rules.write_text('rules:\n  - id: trace.engine-probe\n    languages: [python]\n    message: Local engine probe\n    severity: WARNING\n    pattern: eval($X)\n')
        env=clean_env(home)
        try:
            version=subprocess.run([str(scanner),'--version','--metrics=off','--disable-version-check'],env=env,cwd=source,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
            value['version']=version.stdout.strip()[:64] if version.returncode==0 else None
            result=subprocess.run([str(scanner),'scan','--config='+str(rules),'--json','--quiet','--metrics=off','--disable-version-check','--no-secrets-validation','--jobs=1','.'],env=env,cwd=source,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
            try:data=json.loads(result.stdout)
            except ValueError:data={}
            value['ready']=result.returncode in (0,1) and len(data.get('results',[]))==1 and not data.get('errors')
            value['code']='ok' if value['ready'] else 'native_engine_failed'
        except (OSError,subprocess.TimeoutExpired):value['code']='engine_unavailable_or_timeout'
    return value

if __name__=='__main__':
    value=check();target=ROOT/'.tools/semgrep-readiness.json';target.parent.mkdir(exist_ok=True);target.write_text(json.dumps(value,indent=2),encoding='utf-8')
    print(json.dumps(value,ensure_ascii=False,indent=2))
    print('READY: real engine detected the generated test pattern.' if value['ready'] else 'NOT READY: native engine could not complete. The native engine did not pass the local fixture; TRACE will not automatically enable it.')
    raise SystemExit(0 if value['ready'] else 1)

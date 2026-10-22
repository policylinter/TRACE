"""Verify the installed official OSV binary with a real, disposable npm lockfile."""
import hashlib,json,os,subprocess,sys,tempfile
from datetime import datetime,timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def check():
    folder=ROOT/'.tools/osv-scanner';binary=folder/'osv-scanner.exe';marker=folder/'readiness.json'
    result=dict(checkedAt=datetime.now(timezone.utc).isoformat(),ready=False)
    try:
        release=json.loads((folder/'release.json').read_text(encoding='utf-8'))
        checksum=hashlib.sha256(binary.read_bytes()).hexdigest()
        if checksum!=release['sha256']:raise ValueError('Installed binary does not match downloaded release digest')
        with tempfile.TemporaryDirectory(prefix='trace-osv-readiness-') as directory:
            path=Path(directory)
            fixture=dict(name='trace-readiness-only',version='1.0.0',lockfileVersion=1,requires=True,dependencies={'lodash':{'version':'4.17.20','resolved':'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz'}})
            (path/'package-lock.json').write_text(json.dumps(fixture),encoding='utf-8')
            run=subprocess.run([str(binary),'--format','json',str(path)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
            if run.returncode not in (0,1):raise ValueError('OSV execution failed')
            report=json.loads(run.stdout)
            sys.path.insert(0,str(ROOT));from trace_api.pipeline.ingest import detect_and_parse
            batch=detect_and_parse('osv.json',report)
            if batch.scanner!='OSV-Scanner' or not any(r.package=='lodash' and r.version=='4.17.20' for r in batch.records):raise ValueError('Known vulnerable fixture was not detected')
            result.update(ready=True,version=release['version'],binarySha256=checksum,findings=len(batch.records),fixture='public npm lodash 4.17.20',mode='real_osv_execution')
    except (OSError,ValueError,subprocess.SubprocessError) as exc:result.update(error=type(exc).__name__,detail=str(exc)[:200])
    folder.mkdir(exist_ok=True,parents=True);marker.write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result

if __name__=='__main__':
    result=check();print(json.dumps(result,indent=2));raise SystemExit(0 if result['ready'] else 1)

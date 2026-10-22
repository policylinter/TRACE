"""Operator CLI: bounded Semgrep execution over a pinned local Git tree. No queue or API upload."""
import argparse
from datetime import datetime,timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.convert_semgrep_report import convert
from trace_api.module_intake import SastLocation

MAX_TREE_BYTES=10485760
MAX_FILES=1000

class ExecutionFailure(ValueError):pass

def validate_name(name):
    SastLocation(path=name,startLine=1,endLine=1)
    reserved={'CON','PRN','AUX','NUL',*[f'COM{n}' for n in range(1,10)],*[f'LPT{n}' for n in range(1,10)]}
    if any(part.casefold()=='.git' or part.endswith(('.', ' ')) or part.split('.')[0].upper() in reserved for part in name.split('/')):
        raise ExecutionFailure('unsupported_tree_path')

def clean_env(home):
    # Do not pass CI/API credentials, Git overrides or user Semgrep config.
    env={key:os.environ[key] for key in ('PATH','SystemRoot','WINDIR','TEMP','TMP','PATHEXT') if key in os.environ}
    env.update(HOME=str(home),USERPROFILE=str(home),XDG_CONFIG_HOME=str(home),
        SEMGREP_SEND_METRICS='off',SEMGREP_ENABLE_VERSION_CHECK='0',GIT_CONFIG_NOSYSTEM='1',
        GIT_CONFIG_GLOBAL=os.devnull,GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1',GIT_TERMINAL_PROMPT='0',GIT_OPTIONAL_LOCKS='0')
    return env

def stop_tree(process):
    if process.poll() is not None:return
    if os.name=='nt':
        try:
            subprocess.run([str(Path(os.environ['SystemRoot'])/'System32/taskkill.exe'),'/PID',str(process.pid),'/T','/F'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10,creationflags=0x08000000)
        except (OSError,subprocess.TimeoutExpired):pass
    else:
        try:os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError:pass
    if process.poll() is None:process.kill()

def bounded(command,cwd,env,timeout,limit,input_bytes=None):
    """Drain both pipes with hard memory bounds; never log child output."""
    process=subprocess.Popen(command,cwd=cwd,env=env,stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,shell=False,
        creationflags=0x08000200 if os.name=='nt' else 0,start_new_session=os.name!='nt')
    chunks=[];overflow=threading.Event()
    def drain(pipe,keep):
        size=0
        try:
            while True:
                data=pipe.read1(65536)
                if not data:break
                size+=len(data)
                if size>limit:overflow.set();break
                if keep:chunks.append(data)
        finally:pipe.close()
    readers=[threading.Thread(target=drain,args=(process.stdout,True),daemon=True),threading.Thread(target=drain,args=(process.stderr,False),daemon=True)]
    for reader in readers:reader.start()
    if input_bytes is not None:
        def write_input():
            try:process.stdin.write(input_bytes);process.stdin.close()
            except (OSError,BrokenPipeError):pass
        threading.Thread(target=write_input,daemon=True).start()
    deadline=time.monotonic()+timeout
    try:
        while process.poll() is None:
            if overflow.is_set():raise ExecutionFailure('output_limit')
            if time.monotonic()>=deadline:raise ExecutionFailure('timeout')
            time.sleep(.02)
        for reader in readers:reader.join(timeout=1)
        if any(reader.is_alive() for reader in readers):raise ExecutionFailure('open_output_pipe')
        if overflow.is_set():raise ExecutionFailure('output_limit')
        return process.returncode,b''.join(chunks)
    finally:
        stop_tree(process)
        process.wait(timeout=10)

def snapshot(repo,commit,destination,git,env):
    def run(args,limit=MAX_TREE_BYTES+1048576,input_bytes=None):
        status,raw=bounded([git,'--no-lazy-fetch','--no-replace-objects','-c','safe.directory='+repo.as_posix(),'-C',str(repo),*args],repo,env,30,limit,input_bytes)
        if status!=0:raise ExecutionFailure('git_read_failed')
        return raw
    resolved=run(['rev-parse','--verify',commit+'^{commit}'],1024).decode().strip()
    if resolved!=commit:raise ExecutionFailure('commit_mismatch')
    tree=run(['ls-tree','-rz','--full-tree',commit],1048576)
    entries=[];seen=set()
    for record in tree.split(b'\0'):
        if not record:continue
        header,path=record.split(b'\t',1);mode,kind,oid=header.split()
        name=path.decode('utf-8')
        validate_name(name)
        if mode not in (b'100644',b'100755') or kind!=b'blob' or name.casefold() in seen:
            raise ExecutionFailure('unsupported_tree_entry')
        seen.add(name.casefold());entries.append((name,oid))
        if len(entries)>MAX_FILES:raise ExecutionFailure('source_file_limit')
    data=io.BytesIO(run(['cat-file','--batch'],input_bytes=b''.join(oid+b'\n' for _,oid in entries)))
    total=0;inventory=[]
    for name,oid in entries:
        header=data.readline(256).split()
        if len(header)!=3 or header[0]!=oid or header[1]!=b'blob':raise ExecutionFailure('invalid_git_blob')
        size=int(header[2]);total+=size
        if size<0 or total>MAX_TREE_BYTES:raise ExecutionFailure('source_byte_limit')
        raw=data.read(size)
        if len(raw)!=size or data.read(1)!=b'\n':raise ExecutionFailure('truncated_git_blob')
        target=destination.joinpath(*name.split('/'))
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
        inventory.append([name,hashlib.sha256(raw).hexdigest()])
    checksum=hashlib.sha256(json.dumps(sorted(inventory),ensure_ascii=False,separators=(',',':')).encode()).hexdigest()
    return dict(commit=resolved,fileCount=len(entries),byteCount=total,sourceSnapshotSha256=checksum)

def fingerprint(root):
    inventory=[];total=0
    for path in root.rglob('*'):
        if path.is_symlink():raise ExecutionFailure('snapshot_modified')
        if not path.is_file():continue
        total+=path.stat().st_size
        if total>MAX_TREE_BYTES or len(inventory)>=MAX_FILES:raise ExecutionFailure('snapshot_modified')
        with path.open('rb') as source:raw=source.read(MAX_TREE_BYTES+1)
        if len(raw)>MAX_TREE_BYTES:raise ExecutionFailure('snapshot_modified')
        inventory.append([path.relative_to(root).as_posix(),hashlib.sha256(raw).hexdigest()])
    return hashlib.sha256(json.dumps(sorted(inventory),ensure_ascii=False,separators=(',',':')).encode()).hexdigest()

def execute(*,repo,commit,rules,output_dir,source_id,asset_id,run_id,scanner=None,timeout=120):
    repo=Path(repo).resolve();rules=Path(rules).resolve();output_dir=Path(output_dir)
    if not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})',commit) or not 1<=timeout<=600:
        raise ExecutionFailure('invalid_context')
    if output_dir.exists() or not repo.is_dir() or not rules.is_file() or rules.stat().st_size>65536:
        raise ExecutionFailure('invalid_paths')
    git=shutil.which('git');scanner=shutil.which(scanner or 'semgrep')
    if not git or not scanner:raise ExecutionFailure('scanner_or_git_unavailable')
    rule_bytes=rules.read_bytes()
    started=datetime.now(timezone.utc).isoformat()
    # Validate IDs/run context before reading repository objects or starting a scanner.
    convert(b'{"version":"context","results":[],"errors":[]}',source_id=source_id,asset_id=asset_id,run_id=run_id,commit=commit,observed_at=started)
    with tempfile.TemporaryDirectory(prefix='trace-sast-') as temporary:
        base=Path(temporary);source=base/'source';source.mkdir();home=base/'home';home.mkdir()
        env=clean_env(home);context=snapshot(repo,commit,source,git,env)
        config=base/'operator-rules.yaml';config.write_bytes(rule_bytes)
        command=[scanner,'scan','--config='+str(config),'--json','--quiet','--metrics=off','--disable-version-check',
            '--no-secrets-validation','--jobs=1','--timeout=10','--max-memory=512','.']
        code,raw=bounded(command,source,env,timeout,1048576)
        if code not in (0,1):raise ExecutionFailure('scanner_exit_failed')
        if fingerprint(source)!=context['sourceSnapshotSha256']:raise ExecutionFailure('snapshot_modified')
        manifest,documents=convert(raw,source_id=source_id,asset_id=asset_id,run_id=run_id,commit=commit,observed_at=started)
        # Check outputs refer to the exact snapshot, not arbitrary local files.
        for document in documents:
            if not source.joinpath(*document['analysis']['location']['path'].split('/')).is_file():
                raise ExecutionFailure('reported_path_outside_snapshot')
        receipt=dict(schemaVersion='trace.local-sast-execution/1',executor='local-semgrep/1',startedAt=started,
            finishedAt=datetime.now(timezone.utc).isoformat(),scannerExitCode=code,reportState=manifest['reportState'],
            reportSha256=manifest['reportSha256'],rulesSha256=hashlib.sha256(rule_bytes).hexdigest(),
            source=context,networkIsolationVerified=False,attested=False)
        output_dir.mkdir()
        for name,document in zip(manifest['files'],documents):
            with (output_dir/name).open('x',encoding='utf-8') as target:json.dump(document,target,ensure_ascii=False,indent=2)
        with (output_dir/'execution.json').open('x',encoding='utf-8') as target:json.dump(receipt,target,indent=2)
        with (output_dir/'manifest.json').open('x',encoding='utf-8') as target:json.dump(manifest,target,indent=2)
    return receipt,manifest

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('repo','commit','rules','output-dir','source-id','asset-id','run-id'):parser.add_argument('--'+name,required=True)
    parser.add_argument('--scanner',help='Operator-approved executable path; defaults to semgrep in PATH')
    parser.add_argument('--timeout',type=int,default=120)
    args=parser.parse_args()
    try:receipt,manifest=execute(**vars(args))
    except (OSError,ValueError,TypeError,RecursionError,subprocess.SubprocessError):
        parser.error('SAST execution failed. Check installed tools, local commit/rules, bounds and a new output directory. Child output and source contents are not logged. No completed manifest is guaranteed on failure.')
    print('Local SAST finished; report state: '+manifest['reportState']+'; results: '+str(manifest['outputResults'])+'. Inspect execution.json and manifest.json before import.')
    return 0 if manifest['reportState']=='no_reported_errors' else 2

if __name__=='__main__':raise SystemExit(main())

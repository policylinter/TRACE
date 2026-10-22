"""One-process local demonstration: isolated TRACE DB plus explicit HTTP fixture."""
import json,os,socket,threading,time
from pathlib import Path
from urllib.request import Request,urlopen
ROOT=Path(__file__).resolve().parent

def main():
    folder=ROOT/'work/local-demo';folder.mkdir(parents=True,exist_ok=True)
    source=folder/'source';source.mkdir(exist_ok=True)
    # Generated fixtures only. Python is parsed by scanners, never executed.
    (source/'app.py').write_text('def parse_record(raw):\n    return eval(raw)\n',encoding='utf-8')
    (source/'package-lock.json').write_text(json.dumps(dict(name='trace-local-test-fixture',version='1.0.0',lockfileVersion=1,requires=True,
        dependencies={'lodash':{'version':'4.17.20','resolved':'https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz'}})),encoding='utf-8')
    targets=folder/'dast-targets.json';targets.write_text('[]',encoding='utf-8')
    for port in (5174,8878):
        with socket.socket() as probe:
            if probe.connect_ex(('127.0.0.1',port))==0:raise RuntimeError('Local demo port is occupied: '+str(port))
    from run_release import frontend_path,preflight
    frontend=frontend_path();database=folder/'trace-demo.db';preflight(database,frontend,5174,initialize=True)
    os.environ.update(TRACE_DATABASE_URL='sqlite:///'+database.as_posix(),TRACE_FRONTEND_DIST=str(frontend),TRACE_DAST_TARGETS_FILE=str(targets),
        TRACE_AUTH_ENABLED='0',TRACE_ADMIN_TOKEN='',TRACE_AI_PROVIDER='rules')
    from tools.dast_demo_app import Demo
    from http.server import ThreadingHTTPServer
    fixture=ThreadingHTTPServer(('127.0.0.1',8878),Demo)
    threading.Thread(target=fixture.serve_forever,daemon=True).start()
    def initialize():
        def api(path,body=None):
            with urlopen(Request('http://127.0.0.1:5174/api/v1/'+path,data=json.dumps(body).encode() if body else None,headers={'Content-Type':'application/json'}),timeout=3) as response:return json.load(response)
        try:
            for _ in range(100):
                try:projects=api('projects');break
                except OSError:time.sleep(.2)
            else:raise RuntimeError('TRACE did not become ready')
            project=next((p for p in projects if p['repoUrl']==str(source)),None)
            if project is None:project=api('projects',dict(name='TRACE local test lab',repoUrl=str(source)))
            targets.write_text(json.dumps([dict(id='demo-missing',name='Local test HTML without headers',workspaceId='default',projectId=project['id'],url='http://127.0.0.1:8878/missing'),dict(id='demo-secured',name='Local test HTML with headers',workspaceId='default',projectId=project['id'],url='http://127.0.0.1:8878/secured')]),encoding='utf-8')
            info=dict(url='http://127.0.0.1:5174/#view=dast&workspace=default&project='+str(project['id']),projectId=project['id'],database=str(database),source=str(source),mode='isolated_local_test_lab')
            (folder/'ready.json').write_text(json.dumps(info,indent=2),encoding='utf-8')
            print('LOCAL TEST LAB READY: '+info['url'],flush=True)
        except Exception as exc:print('Local test lab setup failed: '+str(exc),flush=True)
    threading.Thread(target=initialize,daemon=True).start()
    print('TRACE LOCAL TEST LAB. Separate database; public package fixture; no external targets. Ctrl+C stops both servers.',flush=True)
    import uvicorn
    try:uvicorn.run('trace_api.main:app',host='127.0.0.1',port=5174,log_level='warning')
    finally:fixture.shutdown();fixture.server_close()

if __name__=='__main__':main()

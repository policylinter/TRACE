from pathlib import Path
import subprocess,sys,venv,threading,time,webbrowser
ROOT=Path(__file__).resolve().parent
core=ROOT/'trace-core'
python=core/'.venv/Scripts/python.exe'
if sys.version_info<(3,12):
    raise SystemExit('Python 3.12 or newer is required. Install Python from python.org.')
if not python.exists():
    print('Creating Python environment...',flush=True)
    venv.EnvBuilder(with_pip=True).create(core/'.venv')
marker=core/'.venv/trace-installed.txt'
if not marker.exists():
    subprocess.run([str(python),'-m','pip','install','-r',str(core/'requirements-runtime.lock')],check=True)
    marker.write_text('Runtime installed',encoding='utf-8')
def browser():
    from urllib.request import urlopen
    for _ in range(120):
        try:
            with urlopen('http://127.0.0.1:5174/api/v1/projects',timeout=1) as response:
                if response.status==200:
                    webbrowser.open('http://127.0.0.1:5174/');return
        except OSError:pass
        time.sleep(1)
threading.Thread(target=browser,daemon=True).start()
raise SystemExit(subprocess.call([str(python),str(core/'run_demo.py')],cwd=core))

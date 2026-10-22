"""Bounded Python AST observations. Does not execute source or prove exploitation."""
import ast,os,time,tokenize
from pathlib import Path
MAX_FILES=1000
MAX_BYTES=10*1024*1024
MAX_FILE_BYTES=256*1024
MAX_RESULTS=200
PRUNE={'.git','.venv','venv','.tools','node_modules','__pycache__','dist','build','.trace-work'}
RULES={
 'TRACE-PY-001':('high','Динамическое выполнение Python: проверьте происхождение аргумента.'),
 'TRACE-PY-002':('high','Десериализация pickle/dill: недоверенные данные могут привести к выполнению кода.'),
 'TRACE-PY-003':('medium','yaml.load без явно безопасного Loader: проверьте версию и источник данных.'),
 'TRACE-PY-004':('high','subprocess с shell=True: проверьте формирование команды и недоверенные аргументы.'),
}
def scan(root:Path):
 root=root.resolve();results=[];errors=[];skipped=0;scanned=0;total=0;seen=0;deadline=time.monotonic()+20;limited=False
 for base,dirs,files in os.walk(root,followlinks=False):
  dirs[:]=sorted(d for d in dirs if d not in PRUNE and not d.startswith('.') and not (Path(base)/d).is_symlink() and (Path(base)/d).resolve().is_relative_to(root))
  for name in sorted(files):
   if not name.endswith('.py'):continue
   seen+=1;path=Path(base)/name;relative=path.relative_to(root).as_posix()
   if seen>MAX_FILES or time.monotonic()>deadline or len(results)>=MAX_RESULTS:limited=True;break
   try:
    if path.is_symlink() or not path.resolve().is_relative_to(root):skipped+=1;continue
    size=path.stat().st_size
    if size>MAX_FILE_BYTES or total+size>MAX_BYTES:skipped+=1;continue
    total+=size
    with tokenize.open(path) as stream:source=stream.read(MAX_FILE_BYTES+1)
    if len(source)>MAX_FILE_BYTES:skipped+=1;continue
    tree=ast.parse(source,filename=relative);scanned+=1
   except (OSError,SyntaxError,UnicodeError,ValueError):errors.append({'path':relative,'code':'unreadable_or_invalid_python'});continue
   aliases={}
   for node in ast.walk(tree):
    if isinstance(node,ast.Import):
     for item in node.names:aliases[item.asname or item.name.split('.')[0]]=item.name
    elif isinstance(node,ast.ImportFrom) and node.module:
     for item in node.names:aliases[item.asname or item.name]=node.module+'.'+item.name
   def symbol(node):
    if isinstance(node,ast.Name):return aliases.get(node.id,node.id)
    if isinstance(node,ast.Attribute):return symbol(node.value)+'.'+node.attr
    return ''
   for node in ast.walk(tree):
    if not isinstance(node,ast.Call):continue
    name=symbol(node.func);rule=None
    if name in ('eval','exec','builtins.eval','builtins.exec'):rule='TRACE-PY-001'
    elif name in ('pickle.load','pickle.loads','dill.load','dill.loads'):rule='TRACE-PY-002'
    elif name=='yaml.load' and not any(k.arg=='Loader' and symbol(k.value) in ('yaml.SafeLoader','yaml.CSafeLoader','yaml.BaseLoader') for k in node.keywords):rule='TRACE-PY-003'
    elif name in ('subprocess.run','subprocess.call','subprocess.check_call','subprocess.check_output','subprocess.Popen') and any(k.arg=='shell' and isinstance(k.value,ast.Constant) and k.value.value is True for k in node.keywords):rule='TRACE-PY-004'
    if rule:
     severity,message=RULES[rule];results.append(dict(ruleId=rule,path=relative,line=node.lineno,severity=severity,message=message))
     if len(results)>=MAX_RESULTS:limited=True;break
  if limited:break
 return dict(schemaVersion='trace.python-sast/1',scanner='TRACE Python AST',results=results,errors=errors,
  coverage=dict(language='python',filesScanned=scanned,filesSkipped=skipped,limited=limited,ruleCount=len(RULES),exploitationVerified=False))

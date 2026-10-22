"""One-request HTTP baseline on explicitly configured loopback test targets."""
import json,os
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request,build_opener,ProxyHandler,HTTPRedirectHandler
from urllib.error import HTTPError
from fastapi import APIRouter,Depends,HTTPException
from pydantic import BaseModel,ConfigDict,Field
from . import access
from .database import get_db

RULES={
 'TRACE-HTTP-001':('low','Не указан Content-Security-Policy','Определите политику CSP для приложения.'),
 'TRACE-HTTP-002':('low','Не установлен X-Content-Type-Options: nosniff','Установите X-Content-Type-Options: nosniff.'),
 'TRACE-HTTP-003':('low','Не задана политика встраивания страницы','Настройте frame-ancestors в CSP или X-Frame-Options.'),
}
class Target(BaseModel):
 model_config=ConfigDict(extra='forbid')
 id:str=Field(pattern=r'^[a-z0-9][a-z0-9_-]{0,63}$')
 name:str=Field(min_length=1,max_length=128)
 workspaceId:str=Field(min_length=1,max_length=64)
 projectId:int=Field(strict=True,gt=0)
 url:str=Field(min_length=1,max_length=1024)

def validate_url(value):
 parsed=urlsplit(value)
 if (parsed.scheme!='http' or parsed.hostname not in ('127.0.0.1','::1') or not parsed.port or not 1024<=parsed.port<=65535
     or parsed.username or parsed.password or parsed.query or parsed.fragment or any(ord(c)<33 for c in value)):
  raise ValueError('Baseline target must be an explicit loopback HTTP URL without credentials or query')
 return value

def targets():
 name=os.environ.get('TRACE_DAST_TARGETS_FILE','')
 if not name:return []
 try:
  path=Path(name)
  if not path.is_absolute():raise ValueError()
  with path.open('rb') as stream:raw=stream.read(65537)
  data=json.loads(raw)
  if len(raw)>65536 or not isinstance(data,list) or len(data)>20:raise ValueError()
  values=[Target.model_validate(x) for x in data]
  if len({x.id for x in values})!=len(values):raise ValueError()
  for value in values:validate_url(value.url)
  return values
 except (OSError,ValueError,TypeError):raise HTTPException(503,'DAST target configuration is unavailable') from None

class NoRedirect(HTTPRedirectHandler):
 def redirect_request(self,*args,**kwargs):return None

def probe(url):
 validate_url(url)
 opener=build_opener(ProxyHandler({}),NoRedirect())
 # Never follow links, redirects, send credentials or execute active payloads.
 try:response=opener.open(Request(url,headers={'User-Agent':'TRACE-HTTP-Baseline/1','Accept':'text/html'}),timeout=3)
 except HTTPError as exc:
  exc.close();raise ValueError('Target returned an error or redirect') from None
 with response:
  if response.status!=200:raise ValueError('Target did not return HTTP 200')
  content_type=response.headers.get('Content-Type','').split(';',1)[0].strip().lower()
  if content_type not in ('text/html','application/xhtml+xml'):raise ValueError('Target is not an HTML response')
  csp=response.headers.get('Content-Security-Policy','')
  mime=response.headers.get('X-Content-Type-Options','').lower().strip()
  frame=response.headers.get('X-Frame-Options','').lower().strip()
  missing=[]
  if not csp.strip():missing.append('TRACE-HTTP-001')
  if mime!='nosniff':missing.append('TRACE-HTTP-002')
  if frame not in ('deny','sameorigin') and 'frame-ancestors' not in csp.lower():missing.append('TRACE-HTTP-003')
  return {'schemaVersion':'trace.http-baseline/1','url':url,'method':'GET','statusCode':200,'ruleIds':missing,'checkedRules':list(RULES),'requestCount':1}

def records(data):
 from .pipeline.ingest import RawRecord
 url=validate_url(data.get('url',''))
 if data.get('method')!='GET' or data.get('statusCode')!=200 or data.get('requestCount')!=1 or data.get('checkedRules')!=list(RULES):raise ValueError('Invalid HTTP baseline report')
 ids=data.get('ruleIds')
 if not isinstance(ids,list) or any(not isinstance(x,str) or x not in RULES for x in ids) or len(set(ids))!=len(ids):raise ValueError('Invalid HTTP baseline observations')
 return [RawRecord(scanner='TRACE HTTP Baseline',cve=id,package=url,version='',ecosystem='web',severity=RULES[id][0],cvss=0,dataflow={'web':dict(url=url,method='GET',ruleId=id,title=RULES[id][1],description='Один ответ HTML на GET. Проверены только три HTTP-заголовка; эксплуатация и остальные маршруты не проверялись.',solution=RULES[id][2])}) for id in ids]

def choose(db,id):
 from .models import Project
 value=next((x for x in targets() if x.id==id and x.workspaceId==db.info.get('workspace_id','default')),None)
 if value is None or db.get(Project,value.projectId) is None:raise HTTPException(404,'DAST target not found')
 return value

class Input(BaseModel):
 model_config=ConfigDict(extra='forbid')
 targetId:str=Field(min_length=1,max_length=64)

router=APIRouter(prefix='/api/v1/platform/dast',dependencies=[Depends(access.require_read)])
@router.get('/targets')
def listing(db=Depends(get_db)):
 return dict(mode='loopback_http_headers_only',targets=[dict(id=x.id,name=x.name,url=x.url,projectId=x.projectId) for x in targets() if x.workspaceId==db.info.get('workspace_id','default')])

@router.post('/checks',dependencies=[Depends(access.require_admin)],status_code=201)
def check(body:Input,db=Depends(get_db)):
 from .jobs import authorize_execution
 from .services import run_scan
 from .serializers import serialize_scan
 from .platform import audit
 target=choose(db,body.targetId);actor=db.info['actor'];user_id=db.info.get('user_id');db.commit()
 try:report=probe(target.url)
 except (OSError,ValueError):raise HTTPException(502,'HTTP baseline failed; no scan saved') from None
 authorize_execution(db,actor,user_id,require_admin=True)
 if choose(db,target.id)!=target:raise HTTPException(409,'DAST configuration changed during execution')
 scan=run_scan(db,repository=target.url,commit_sha='',branch='http-baseline',payloads=[('baseline.json',report)],project_id=target.projectId,triggered_by=actor)
 scan.status='partial';scan.scanner_results=[dict(id='http-baseline',label='TRACE HTTP Baseline',role='dast',status='partial',detail='Выполнен один GET; проверены три заголовка HTML. Полное DAST-покрытие не подтверждено.')]
 audit(db,'dast.baseline',scan.id,'Loopback target; one GET; three header rules');db.commit()
 return serialize_scan(scan)

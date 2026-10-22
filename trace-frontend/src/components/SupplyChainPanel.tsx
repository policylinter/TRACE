import { useEffect,useState,type FormEvent } from 'react';
import { getSupplyChainContext,registerSupplyChainContext,type PlatformAsset,type SupplyChainData,type SupplyChainRecord } from '@/lib/api';
import { useTrace } from '@/state/TraceProvider';
const supported=['build','artifact','deployment'];
export function SupplyChainPanel({asset,assets,onNavigate}:{asset:PlatformAsset;assets:PlatformAsset[];onNavigate:(id:string)=>void}) {
  const t=useTrace();const canWrite=!t.auth?.enabled||t.user?.role==='admin'||t.user?.role==='analyst';
  const [record,setRecord]=useState<SupplyChainRecord|null>(null);const [loading,setLoading]=useState(true);const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [retry,setRetry]=useState(0);const [loadFailed,setLoadFailed]=useState(false);
  const [upstream,setUpstream]=useState('');const [commit,setCommit]=useState('');const [external,setExternal]=useState('');const [checksum,setChecksum]=useState('');const [environment,setEnvironment]=useState('');const [observed,setObserved]=useState('');const [evidence,setEvidence]=useState('');
  useEffect(()=>{if(!supported.includes(asset.kind))return;let live=true;setLoading(true);setRecord(null);setError('');setLoadFailed(false);void getSupplyChainContext(asset.id).then(value=>{if(live)setRecord(value.context);}).catch(e=>{if(live){setError(String(e));setLoadFailed(true);}}).finally(()=>{if(live)setLoading(false);});return()=>{live=false;};},[asset.id,asset.kind,retry]);
  if(!supported.includes(asset.kind))return null;
  const upstreamKind=asset.kind==='build'?'repository':asset.kind==='artifact'?'build':'artifact';
  const upstreamLabel=asset.kind==='build'?'Репозиторий':asset.kind==='artifact'?'Сборка с зафиксированным контекстом':'Артефакт с зафиксированным контекстом';
  async function save(event:FormEvent){event.preventDefault();setBusy(true);setError('');try{
    const common={observedAt:new Date(observed).toISOString(),evidenceRef:evidence};let body:SupplyChainData;
    if(asset.kind==='build')body={...common,kind:'build',repositoryAssetId:upstream,commitSha:commit,buildExternalId:external};
    else if(asset.kind==='artifact')body={...common,kind:'artifact',buildAssetId:upstream,digest:checksum};
    else body={...common,kind:'deployment',artifactAssetId:upstream,environment,deploymentExternalId:external};
    setRecord(await registerSupplyChainContext(asset.id,body));
  }catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  const names=(id:string)=>assets.find(item=>item.id===id)?.name||id;
  return <section className="panel p-5 module-intake-panel space-y-3"><h2>Контекст поставки: {asset.name}</h2><p>Репозиторий → сборка → артефакт → развёртывание. Сведения заявлены оператором; TRACE не загружает артефакт, не проверяет подпись и не подтверждает его исполнение.</p>
    {error&&<p role="alert" className="text-rose-300">{error}</p>}<button className="btn" disabled={busy||loading} onClick={()=>setRetry(value=>value+1)}>Обновить контекст</button>
    {loading?<p>Загрузка контекста…</p>:record?<div className="space-y-3"><strong>Контекст зафиксирован · происхождение не удостоверено</strong><p>Записано: {new Date(record.recordedAt).toLocaleString('ru-RU')} · {record.recordedBy}.</p><p>Наблюдение по основанию: {new Date(record.context.observedAt).toLocaleString('ru-RU')}.</p><p className="break-all">Основание: {record.context.evidenceRef}.</p>{record.context.commitSha&&<p className="break-all">Коммит: <code>{record.context.commitSha}</code></p>}{record.context.digest&&<p className="break-all">SHA-256 артефакта: <code>{record.context.digest}</code></p>}{record.context.environment&&<p>Окружение: {record.context.environment}.</p>}{record.context.buildExternalId&&<p>ID сборки: {record.context.buildExternalId}.</p>}{record.context.deploymentExternalId&&<p>ID развёртывания: {record.context.deploymentExternalId}.</p>}
      {([['Репозиторий',record.context.repositoryAssetId],['Сборка',record.context.buildAssetId],['Артефакт',record.context.artifactAssetId]] as const).map(([label,id])=>id&&id!==asset.id?<p key={label}>{label}: <button className="text-jade-400 underline" onClick={()=>onNavigate(id)}>{names(id)}</button></p>:null)}
      <code className="block break-all text-xs">SHA-256 контекста: {record.sha256}</code><p className="micro">Связанные записи фиксируются по ID; для артефакта и развёртывания также сохраняются контрольные суммы предыдущих звеньев. Изменить её нельзя; для следующей поставки зарегистрируйте новый актив. Наличие контекста не связывает находки проекта с развёртыванием автоматически.</p>
    </div>:<><p>{loadFailed?"Состояние контекста не получено.":"Контекст ещё не зафиксирован."}</p>{canWrite&&!loadFailed&&<form onSubmit={e=>void save(e)}><fieldset disabled={busy} className="platform-form"><label>{upstreamLabel}<select required value={upstream} onChange={e=>setUpstream(e.target.value)}><option value="">Выберите актив</option>{assets.filter(item=>item.kind===upstreamKind).map(item=><option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      {asset.kind==='build'&&<label>Полный SHA коммита<input required pattern="[0-9a-f]{40}|[0-9a-f]{64}" maxLength={64} value={commit} onChange={e=>setCommit(e.target.value)} placeholder="40 или 64 символа lowercase hex"/></label>}
      {asset.kind==='artifact'&&<label>Digest артефакта<input required pattern="sha256:[0-9a-f]{64}" value={checksum} onChange={e=>setChecksum(e.target.value)} placeholder="sha256:…"/></label>}
      {asset.kind!=='artifact'&&<label>{asset.kind==='build'?'Внешний ID сборки':'Внешний ID развёртывания'}<input required maxLength={128} value={external} onChange={e=>setExternal(e.target.value)}/></label>}
      {asset.kind==='deployment'&&<label>Окружение<input required maxLength={128} value={environment} onChange={e=>setEnvironment(e.target.value)} placeholder="Например, staging"/></label>}
      <label>Время наблюдения по основанию<input required type="datetime-local" value={observed} onChange={e=>setObserved(e.target.value)}/></label><label>Ссылка / ID основания<input required maxLength={512} value={evidence} onChange={e=>setEvidence(e.target.value)} placeholder="Без паролей и ключей"/></label><p className="micro">Сначала фиксируется сборка, затем артефакт и развёртывание. Запись неизменяема; проверьте значения перед сохранением. Время вводится в локальном часовом поясе браузера.</p><button className="btn-primary" disabled={busy}>{busy?'Сохранение…':'Зафиксировать контекст'}</button>
    </fieldset></form>}</>}
  </section>;
}



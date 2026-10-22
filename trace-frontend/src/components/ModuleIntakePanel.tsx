import { useEffect,useState } from 'react';
import { getResultSources,createResultSource,setResultSourceActive,getModuleResults,importModuleResult,type ResultSource,type ImportedModuleResult,type PlatformAsset } from '@/lib/api';
import { useTrace } from '@/state/TraceProvider';
import { SourceWebhookPanel } from '@/components/SourceWebhookPanel';
import { ImportedResultCard } from '@/components/ImportedResultCard';

export function ModuleIntakePanel({assets}:{assets:PlatformAsset[]}) {
  const t=useTrace();
  const canWrite=!t.auth?.enabled || t.user?.role==='admin';
  const [sources,setSources]=useState<ResultSource[]>([]);
  const [results,setResults]=useState<ImportedModuleResult[]>([]);
  const [assetFilter,setAssetFilter]=useState('');
  const [contextFilter,setContextFilter]=useState('');
  const [name,setName]=useState('');const [module,setModule]=useState('infrastructure');
  const [draft,setDraft]=useState('');const [busy,setBusy]=useState(false);
  const [error,setError]=useState('');const [note,setNote]=useState('');
  async function load(){const [s,r]=await Promise.all([getResultSources(),getModuleResults(assetFilter,contextFilter)]);setSources(s);setResults(r);}
  useEffect(()=>{let live=true;setResults([]);setError('');void Promise.all([getResultSources(),getModuleResults(assetFilter,contextFilter)]).then(([s,r])=>{if(live){setSources(s);setResults(r);}}).catch(e=>{if(live)setError(String(e));});return()=>{live=false;};},[t.workspaceId,assetFilter,contextFilter]);
  async function run(action:()=>Promise<void>){setBusy(true);setError('');setNote('');try{await action();await load();}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  function example(){const source=sources.find(s=>s.active);if(!source || !assets[0])return;setDraft(JSON.stringify({schemaVersion:'trace.intake/1',objectType:'finding',sourceId:source.id,externalId:'REPLACE_WITH_REPORT_ID',assetId:assets[0].id,ruleId:'REPLACE_WITH_RULE_ID',title:'Укажите результат из отчёта',description:'',severity:'unknown',contextAssetId:null,contextReason:null,observedAt:'REPLACE_WITH_OBSERVATION_TIME_ISO8601',evidence:[{label:'Отчёт источника',reference:'REPLACE_WITH_REPORT_REFERENCE',sha256:'REPLACE_WITH_ACTUAL_SHA256'}]},null,2));}
  return <section className="module-intake-panel panel p-5 space-y-4"><h2>Источники и импорт результатов</h2>
    <p>Ручной или подписанный приём отчётов, привязанных к активу выбранного пространства. Импорт не запускает сканер и не подтверждает достоверность источника. Эти записи пока хранятся отдельно от очереди AppSec-находок.</p>
    {error&&<p role="alert" className="text-rose-300">{error}</p>}{note&&<p role="status" className="text-jade-300">{note}</p>}
    <button className="btn" disabled={busy} onClick={()=>void run(async()=>{})}>Обновить список</button>
    {canWrite&&<form className="platform-form" onSubmit={e=>{e.preventDefault();void run(async()=>{await createResultSource(name,module);setName('');setNote('Источник зарегистрирован. Внешнее подключение не выполнялось.');});}}><label>Название источника<input required maxLength={128} value={name} onChange={e=>setName(e.target.value)}/></label><label>Направление<select value={module} onChange={e=>setModule(e.target.value)}><option value="appsec">Безопасность приложений</option><option value="infrastructure">Инфраструктура</option><option value="access-data">Доступ и данные</option><option value="governance">Управление ИБ</option></select></label><button className="btn" disabled={busy}>Зарегистрировать источник</button></form>}
    {!sources.length?<p>Источники ещё не зарегистрированы.</p>:<ul>{sources.map(source=><li key={source.id} className="mt-3"><strong>{source.name}</strong> · {source.module} · {source.active?'Приём разрешён':'Приём выключен'}<code className="block break-all micro">{source.id}</code>{canWrite&&<button className="btn" disabled={busy} onClick={()=>void run(async()=>{await setResultSourceActive(source.id,!source.active);})}>{source.active?'Выключить приём':'Включить приём'}</button>}{canWrite&&<SourceWebhookPanel key={t.workspaceId+source.id} sourceId={source.id}/>}</li>)}</ul>}
    {canWrite&&<details><summary className="cursor-pointer font-semibold">Импортировать один результат JSON</summary><div className="mt-3 space-y-3"><p>Нужны зарегистрированный источник, актив и минимум одна ссылка на доказательство с SHA-256 из отчёта. Ссылки не загружаются автоматически. Не включайте пароли, ключи и персональные данные. Время observedAt должно быть временем наблюдения из отчёта.</p><button className="btn" disabled={busy||!assets.length||!sources.some(s=>s.active)} onClick={example}>Подготовить шаблон</button><p className="micro">В шаблоне замените идентификаторы, время и контрольную сумму. Повтор того же externalId и данных не создаёт дубль. Изменённый отчёт требует нового externalId.</p><p className="micro">Для снимка поставки укажите contextAssetId — ID актива с зафиксированным контекстом — и contextReason — основание привязки. Если контекст неизвестен, оставьте оба значения null. Для результата артефакта, сборки или развёртывания контекст должен принадлежать этому же активу.</p><textarea rows={14} maxLength={40000} className="w-full rounded border border-hairline bg-ink-950 p-3 font-mono text-xs" value={draft} onChange={e=>setDraft(e.target.value)} aria-label="Результат модуля JSON"/><button className="btn-primary" disabled={busy||!draft.trim()} onClick={()=>void run(async()=>{const parsed=JSON.parse(draft);const result=await importModuleResult(parsed);setNote('Результат сохранён или уже был принят: '+result.id);})}>Проверить и импортировать</button></div></details>}
    <h3>Принятые результаты</h3><p className="micro">Последние 100 записей. Удостоверение происхождения не выполнялось; SHA-256 в доказательстве сообщён оператором.</p>
    <label className="field-label">Результаты по активу<select disabled={busy} value={assetFilter} onChange={e=>setAssetFilter(e.target.value)}><option value="">Все активы пространства</option>{assets.map(asset=><option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></label>
    <label className="field-label">По зафиксированному контексту поставки<select disabled={busy} value={contextFilter} onChange={e=>setContextFilter(e.target.value)}><option value="">Без ограничения по контексту</option>{assets.filter(asset=>['build','artifact','deployment'].includes(asset.kind)).map(asset=><option key={asset.id} value={asset.id}>{asset.name}</option>)}</select></label>
    {!results.length?<p>В выбранной выборке импортированных результатов нет.</p>:results.map(result=><ImportedResultCard key={result.id} result={result} candidates={results} assetName={assets.find(a=>a.id===result.payload.assetId)?.name||result.payload.assetId}/>)}
  </section>;
}




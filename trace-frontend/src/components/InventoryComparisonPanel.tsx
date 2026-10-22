import {InventoryReconciliationPanel} from '@/components/InventoryReconciliationPanel';
import {useEffect,useState} from 'react';
import {compareInventorySnapshots,type InventoryRun,type InventoryComparison,type InventoryChangeKind} from '@/lib/api';
const kinds:Record<InventoryChangeKind,string>={only_after:'Только в новом снимке',changed:'Сведения изменились',not_in_after:'Нет в полном новом снимке',not_observed_partial:'Не наблюдался при частичном сборе',unchanged:'Сведения совпадают'};
const fields:Record<string,string>={name:'Имя по данным источника',kind:'Тип узла',owner:'Заявленный владелец',platform:'Платформа',version:'Версия',provider:'Провайдер',region:'Регион'};
const states={complete:'полный',partial:'частичный',error:'ошибка'};

export function InventoryComparisonPanel({sourceId,recentRuns,onOpen}:{sourceId:string;recentRuns:InventoryRun[];onOpen:(id:string)=>void}) {
  const [known,setKnown]=useState(recentRuns);const [before,setBefore]=useState('');const [after,setAfter]=useState('');
  const [include,setInclude]=useState(false);const [data,setData]=useState<InventoryComparison|null>(null);
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');
  const recentKey=recentRuns.map(run=>run.id).join(',');
  useEffect(()=>{
    setKnown(previous=>[...recentRuns,...previous.filter(run=>!recentRuns.some(current=>current.id===run.id)&&(run.id===before||run.id===after))]);
    setBefore(current=>current||recentRuns[1]?.id||'');setAfter(current=>current||recentRuns[0]?.id||'');
  },[sourceId,recentKey,before,after]);
  const a=known.find(run=>run.id===before);const b=known.find(run=>run.id===after);
  const ordered=!!a&&!!b&&new Date(a.observedAt)<new Date(b.observedAt);
  async function load(offset=0){setBusy(true);setError('');try{setData(await compareInventorySnapshots(sourceId,before,after,include,offset));}catch(e){setError(String(e));}finally{setBusy(false);}}
  return <section className="space-y-3 border-t border-hairline pt-4"><h3>Сравнение снимков</h3>
    <p className="micro">Сравниваются сведения двух выбранных снимков одного источника. Отсутствие в снимке не означает удаление узла или уязвимость. Новые импорты не переключают выбранную пару.</p>
    {known.length<2?<p>Для сравнения нужны хотя бы два снимка.</p>:<>
      <form className="platform-form" onSubmit={e=>{e.preventDefault();void load();}}><fieldset disabled={busy} className="platform-form w-full">
        <label>Базовый снимок<select value={before} onChange={e=>{setBefore(e.target.value);setData(null);setError('');}}>{known.map(run=><option key={run.id} value={run.id}>{run.externalRunId} · {states[run.status]}</option>)}</select></label>
        <label>Новый снимок<select value={after} onChange={e=>{setAfter(e.target.value);setData(null);setError('');}}>{known.map(run=><option key={run.id} value={run.id}>{run.externalRunId} · {states[run.status]}</option>)}</select></label>
        <label><input type="checkbox" checked={include} onChange={e=>{setInclude(e.target.checked);setData(null);}}/> Показывать узлы без изменений</label>
        <button className="btn" disabled={!ordered||busy}>Сравнить выбранные снимки</button>
      </fieldset></form>
      {!ordered&&<p>Базовый снимок должен быть раньше нового.</p>}
      {error&&<p role="alert" className="text-rose-300">{error}</p>}
      {data&&<>
        <p>{data.before.externalRunId} ({new Date(data.before.observedAt).toLocaleString('ru-RU')}) → {data.after.externalRunId} ({new Date(data.after.observedAt).toLocaleString('ru-RU')}).</p>
        {data.status==='unavailable'?<p role="status">Сравнение не выполнено: {data.reason==='collection_error'?'один из снимков сообщает об ошибке сбора. Выберите другую пару; отсутствие данных не означает отсутствия изменений.':'не удалось подтвердить целостность сохранённых снимков.'}</p>:<>
          {data.before.status==='partial'&&<p className="micro">Базовый снимок частичный: «только в новом» не означает первое появление узла в инфраструктуре.</p>}
          {data.after.status==='partial'&&<p className="micro">Новый снимок частичный: не попавшие в него узлы не считаются отсутствующими.</p>}
          <p className="micro">Рассчитано {new Date(data.checkedAt).toLocaleString('ru-RU')}. Реестр и история наблюдений не изменены.</p>
          {data.counts&&<ul>{Object.entries(data.counts).map(([key,value])=><li key={key}>{kinds[key as InventoryChangeKind]}: {value}</li>)}</ul>}
          {!data.total&&<p>Различий в сведениях выбранных снимков нет.</p>}
          {data.items.map(item=><article key={item.externalId} className="border border-hairline rounded p-3 space-y-2"><h4>{kinds[item.kind]}</h4>{item.assetId?<button className="text-jade-400" onClick={()=>onOpen(item.assetId!)}>{item.after?.name||item.before?.name||item.externalId}</button>:<p>{item.after?.name||item.before?.name||item.externalId}</p>}<p className="micro break-all">{item.externalId}</p>
            {item.changes.map(change=><p key={change.field}>{fields[change.field]||change.field}: {change.before||'не указано'} → {change.after||'не указано'}</p>)}
            {item.kind==='not_in_after'&&<p className="micro">Узел отсутствует только в заявленной области нового полного снимка. Актив сохранён; факт удаления не подтверждён.</p>}
            {item.kind==='not_observed_partial'&&<p className="micro">Частичный сбор не даёт основания считать узел отсутствующим.</p>}
            {(item.kind==='not_in_after'||item.kind==='not_observed_partial')&&item.assetId&&<InventoryReconciliationPanel key={data.before.id+data.after.id+item.externalId} sourceId={sourceId} before={data.before.id} after={data.after.id} externalId={item.externalId}/>}
          </article>)}
          <p className="micro">Записей с текущим фильтром: {data.total}.</p><button className="btn" disabled={busy||!data.offset} onClick={()=>void load(Math.max(0,data.offset-50))}>Предыдущие различия</button><button className="btn" disabled={busy||data.offset+data.limit>=data.total} onClick={()=>void load(data.offset+50)}>Следующие различия</button>
        </>}
      </>}
    </>}
  </section>;
}

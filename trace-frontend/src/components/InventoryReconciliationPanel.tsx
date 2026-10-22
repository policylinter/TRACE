import {useEffect,useState} from 'react';
import {useTrace} from '@/state/TraceProvider';
import {getInventoryReconciliation,saveInventoryReconciliation,type InventoryReconciliation,type InventoryReviewState} from '@/lib/api';
const labels={open:'Ожидает сверки',in_progress:'В работе',needs_observation:'Нужно новое наблюдение',explained:'Есть объяснение'};

export function InventoryReconciliationPanel({sourceId,before,after,externalId}:{sourceId:string;before:string;after:string;externalId:string}) {
  const t=useTrace();const canWrite=!t.auth?.enabled||t.user?.role==='admin'||t.user?.role==='analyst';
  const [open,setOpen]=useState(false);const [data,setData]=useState<InventoryReconciliation|null>(null);
  const [status,setStatus]=useState<InventoryReviewState['status']>('open');const [reason,setReason]=useState('');
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [note,setNote]=useState('');
  useEffect(()=>{if(!open)return;let live=true;setBusy(true);setError('');void getInventoryReconciliation(sourceId,before,after,externalId).then(value=>{if(live){setData(value);setStatus(value.review.status);setReason(value.review.reason);}}).catch(e=>{if(live)setError(String(e));}).finally(()=>{if(live)setBusy(false);});return()=>{live=false;};},[sourceId,before,after,externalId,open]);
  async function refresh(){const value=await getInventoryReconciliation(sourceId,before,after,externalId);setData(value);setStatus(value.review.status);setReason(value.review.reason);}
  async function run(action:()=>Promise<void>){setBusy(true);setError('');setNote('');try{await action();}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  return <details className="mt-3 border-t border-hairline pt-3" onToggle={e=>setOpen(e.currentTarget.open)}><summary className="cursor-pointer font-semibold">Сверка узла и история решений</summary>
    {open&&<div className="mt-3 space-y-3"><p className="micro">Решение аналитика относится только к этому узлу и выбранной паре снимков. Объяснение не подтверждает удаление актива. Реестр и результаты проверок не меняются; сборщик автоматически не запускается.</p>
      {error&&<p role="alert" className="text-rose-300">{error}</p>}{note&&<p role="status">{note}</p>}
      <button className="btn" disabled={busy} onClick={()=>void run(refresh)}>Обновить сверку и сбросить черновик</button>
      {data&&<>
        {data.observationKind==='not_observed_partial'&&<p>Узел не наблюдался в частичном сборе. Его отсутствие не установлено.</p>}
        <p>{labels[data.review.status]} · версия {data.review.revision} · {data.review.updatedBy||'Решений ещё нет'}{data.review.updatedAt?' · '+new Date(data.review.updatedAt).toLocaleString('ru-RU'):''}</p>
        <form onSubmit={e=>{e.preventDefault();void run(async()=>{await saveInventoryReconciliation(sourceId,{beforeRunId:before,afterRunId:after,externalId,expectedRevision:data.review.revision,status,reason});await refresh();setNote('Решение и причина сохранены для выбранной пары снимков.');});}}><fieldset disabled={busy||!canWrite} className="platform-form" style={{minWidth:0}}>
          <label>Решение по сверке<select value={status} onChange={e=>setStatus(e.target.value as InventoryReviewState['status'])}>{Object.entries(labels).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select></label>
          <label>Причина решения по сверке<textarea required rows={3} maxLength={4000} value={reason} onChange={e=>setReason(e.target.value)} className="w-full"/></label>
          {canWrite&&<button className="btn" disabled={busy||!reason.trim()}>Сохранить решение по сверке</button>}
        </fieldset></form>
        <h5>История сверки</h5><p className="micro">Изменений: {data.historyTotal}. Последние 100, от новых к старым.</p>
        {!data.history.length?<p>Решений ещё нет.</p>:data.history.map(event=><article key={event.id} className="border-l border-hairline pl-3"><p>{new Date(event.at).toLocaleString('ru-RU')} · {event.actor} · версия {event.revision}</p><p>{labels[event.change.before.status]} → {labels[event.change.after.status]}</p><p className="whitespace-pre-wrap break-words">{event.change.after.reason}</p></article>)}
      </>}
    </div>}
  </details>;
}

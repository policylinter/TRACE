import { useEffect, useState } from 'react';
import type { Finding } from '@/data/findings';
import { getFindingResult, type FindingResult } from '@/lib/api';

const categories = {reported_observation:'Данные исходного отчёта', engine_assessment:'Оценка движка', team_decision:'Решение команды'};
export function ResultProvenance({finding}:{finding:Finding}) {
  const [open,setOpen]=useState(false);
  const [data,setData]=useState<FindingResult|null>(null);
  const [error,setError]=useState('');
  const [retry,setRetry]=useState(0);
  useEffect(()=>{
    setData(null);setError('');
    if (!open) return;
    let live=true;
    void getFindingResult(finding.id).then(value=>{if(live)setData(value);}).catch(e=>{if(live)setError(e instanceof Error?e.message:'Не удалось получить происхождение результата');});
    return ()=>{live=false;};
  },[finding,open,retry]);
  function download() {
    if (!data) return;
    const url=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:'application/json'}));
    const a=document.createElement('a');a.href=url;a.download='trace-finding-result.json';a.click();
    window.setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  return <details className="wb-card p-4" onToggle={e=>setOpen(e.currentTarget.open)}>
    <summary className="cursor-pointer font-semibold">Происхождение результата и доказательств</summary>
    {open && <div className="mt-4 space-y-3">
      {error ? <p role="alert">{error} <button className="btn" onClick={()=>setRetry(v=>v+1)}>Повторить</button></p> : !data ? <p>Загрузка происхождения…</p> : <>
        <p className="wb-footnote">Формат {data.schemaVersion} · модуль AppSec · пространство {data.workspaceId}{data.demo?' · Демонстрационные данные':''}</p>
        <p>Запись находки: {data.recordedAt?new Date(data.recordedAt).toLocaleString('ru-RU'):'время неизвестно'}. Время исходного наблюдения не установлено.</p>
        {data.evidence.map(item=><div key={item.id} className="border-t border-hairline pt-3"><strong>{categories[item.category]}</strong><p className="wb-footnote">Источник: {item.source === 'unknown'?'не установлен':item.source}. Независимое подтверждение не зарегистрировано.</p><code className="block break-all text-xs">SHA-256: {item.sha256}</code></div>)}
        <ul className="list-disc pl-5 text-sm">{data.limitations.map(line=><li key={line}>{line}</li>)}</ul>
        <button className="btn" onClick={download}>Скачать результат JSON</button>
      </>}
    </div>}
  </details>;
}

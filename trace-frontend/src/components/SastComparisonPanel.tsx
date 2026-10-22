import {useState} from 'react';
import {compareSastExecutions,type SastComparison,type SastExecution} from '@/lib/api';

export function SastComparisonPanel({executions}:{executions:SastExecution[]}){
  const [baseline,setBaseline]=useState('');const [current,setCurrent]=useState('');const [result,setResult]=useState<SastComparison|null>(null);
  const [busy,setBusy]=useState(false);const [error,setError]=useState('');
  async function compare(){setBusy(true);setError('');setResult(null);try{setResult(await compareSastExecutions(current,baseline));}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
  const labels={appeared:'Появилось',repeated:'Повторилось',not_observed:'Не наблюдается в новом отчёте'};
  return <details className="border-t border-hairline py-3"><summary className="cursor-pointer font-semibold">Сравнение выполнений SAST</summary><div className="space-y-3 mt-3">
    <p>Сопоставление по точному правилу, пути и диапазону строк. Изменение строк считается другим наблюдением. Требуются одна цель, источник, репозиторий, конфигурация и правила. Версия сканера и полнота покрытия не подтверждаются.</p>
    {executions.length<2?<p>Для сравнения нужны два завершённых выполнения. Доступны последние 20 свидетельств этого пространства.</p>:<form className="platform-form" onSubmit={e=>{e.preventDefault();void compare();}}>
      <label>Базовое выполнение SAST<select required value={baseline} disabled={busy} onChange={e=>{setBaseline(e.target.value);setResult(null);setError('');}}><option value="">Выберите более раннее выполнение</option>{executions.map(x=><option key={x.id} value={x.id}>{x.targetId} · {x.execution.source.commit.slice(0,12)} · {x.receivedAt} · {x.id.slice(0,8)}</option>)}</select></label>
      <label>Новое выполнение SAST<select required value={current} disabled={busy} onChange={e=>{setCurrent(e.target.value);setResult(null);setError('');}}><option value="">Выберите более позднее выполнение</option>{executions.map(x=><option key={x.id} value={x.id}>{x.targetId} · {x.execution.source.commit.slice(0,12)} · {x.receivedAt} · {x.id.slice(0,8)}</option>)}</select></label>
      <button className="btn" disabled={busy||!baseline||!current||baseline===current}>{busy?'Сравнение…':'Сравнить выполнения SAST'}</button>
    </form>}
    {error&&<p role="alert">{error}</p>}
    {result&&<div className="space-y-3"><p className="break-all">Базовый commit: {result.baselineCommit}. Новый commit: {result.currentCommit}.</p><p>Состояние отчётов: {result.baselineReportState} → {result.currentReportState}.</p><p role="status">Появилось: {result.counts.appeared}. Повторилось: {result.counts.repeated}. Не наблюдается: {result.counts.not_observed}.</p>
      <p>Отсутствие наблюдения не подтверждает исправление. Частичный или пустой отчёт не означает безопасность. Решения триажа и повторные проверки автоматически не меняются.</p>
      {result.items.map(item=><article key={JSON.stringify([item.ruleId,item.path,item.startLine,item.endLine])} className="border-t border-hairline py-2"><strong>{labels[item.state]}</strong><p className="break-all">{item.ruleId} · {item.path} · строки {item.startLine}–{item.endLine}</p><details><summary>Связанные результаты</summary><p className="break-all">Базовые: {item.baselineResultIds.join(', ')||'нет'}. Новые: {item.currentResultIds.join(', ')||'нет'}.</p></details></article>)}
      {!result.items.length&&<p>В обоих пакетах наблюдений нет; покрытие и исправление не подтверждены.</p>}
    </div>}
  </div></details>;
}

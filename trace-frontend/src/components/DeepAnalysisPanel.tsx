import {useState} from 'react';
import type {Finding} from '@/data/findings';
import {analyzeFinding} from '@/lib/api';
import {useTrace} from '@/state/TraceProvider';
import {IconSparkle,IconChevronRight} from './icons';
export function DeepAnalysisPanel({finding,onEvidence}:{finding:Finding;onEvidence:(ref:string)=>void}){
 const t=useTrace();const [busy,setBusy]=useState(false);const [error,setError]=useState('');const [open,setOpen]=useState(false);const report=finding.evidence.deepAnalysis;
 async function run(){setBusy(true);setError('');try{await analyzeFinding(finding.id);await t.reload();setOpen(true);}catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}}
 return <section className="wb-card deep-analysis-panel">
  <div className="deep-analysis-heading"><div className="flex items-start gap-3"><span className="deep-analysis-icon"><IconSparkle className="h-5 w-5"/></span><div><h2>Глубокий анализ ИИ</h2><p className="wb-footnote">Условия эксплуатации, влияние, пробелы в доказательствах и проверка исправления.</p></div></div><div className="flex flex-wrap gap-2">{report&&<button className="wb-button" onClick={()=>setOpen(v=>!v)}>{open?'Свернуть':'Открыть разбор'}<IconChevronRight className="h-3 w-3"/></button>}<button className="wb-button wb-primary" disabled={busy || (!!t.auth?.enabled && t.user?.role==='viewer')} onClick={()=>void run()}>{busy?'Выполняется анализ…':report?'Обновить разбор':'Разобрать находку'}</button></div></div>
  <p className="wb-footnote">Анализ использует сохранённые метаданные, шаги пути и контекст из настроек. Полный исходный файл в запрос не включён.</p>
  {t.health && !t.health.modelAvailable && <p role="status" className="analysis-guard">Локальная модель недоступна. Разбор по правилам не является выводом модели; источник будет указан в результате.</p>}
  {error&&<p role="alert" className="wb-error">{error}</p>}
  {finding.evidence.guardNote&&<p className="analysis-guard">{finding.evidence.guardNote}</p>}
  {report&&<div className="analysis-provenance"><span className="wb-count">{report.source==='model'?'Ответ модели':'Разбор по правилам · модель не использована'}</span><span>{new Date(report.generatedAt).toLocaleString('ru-RU')}</span><span>{finding.evidence.model}</span></div>}
  {open&&report&&<div className="deep-analysis-report">
   <div className="analysis-report-column"><section><h3>Наблюдения {report.source==='model'?'модели':'по данным отчёта'}</h3>{report.observations.map((item,i)=><div className="analysis-observation" key={i}><p>{item.statement}</p><div className="analysis-reference-list">{item.evidenceRefs.map(ref=>/^frame-\d+$/.test(ref)?<button key={ref} title={report.evidenceIndex.find(e=>e.id===ref)?.label} onClick={()=>onEvidence(ref)}>↗ {ref}</button>:<span key={ref} title={report.evidenceIndex.find(e=>e.id===ref)?.label}>{ref}</span>)}</div></div>)}</section><section><h3>Условия эксплуатации</h3><ul>{report.exploitationConditions.map((item,i)=><li key={i}>{item}</li>)}</ul></section><section><h3>Потенциальное влияние</h3><p>{report.impact}</p></section></div>
   <div className="analysis-report-column"><section className="analysis-gaps"><h3>Чего не хватает для вывода</h3>{report.missingEvidence.length?<ul>{report.missingEvidence.map((item,i)=><li key={i}>{item}</li>)}</ul>:<p>Пробелы не перечислены в результате. Это не подтверждает полноту проверки.</p>}</section><section><h3>Допущения · не подтверждены</h3>{report.assumptions.length?<ul>{report.assumptions.map((item,i)=><li key={i}>{item}</li>)}</ul>:<p>Допущения не перечислены.</p>}</section><section><h3>Что проверить</h3><ol>{report.verificationSteps.map((item,i)=><li key={i}>{item}</li>)}</ol></section></div>
   {report.remediationPlan.length>0&&<section className="analysis-remediation"><h3>План изменений</h3>{report.remediationPlan.map((item,i)=><article key={i}><strong>{i+1}. {item.action}</strong><p>{item.rationale}</p><p><b>Проверка:</b> {item.verification}</p></article>)}</section>}
  </div>}
 </section>;
}

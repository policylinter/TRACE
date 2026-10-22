import { useEffect, useState } from 'react';
import { useTrace } from '@/state/TraceProvider';
import { getScanPolicy, type GateResult } from '@/lib/api';
import { scanCoverage, scanStatusLabel } from '@/lib/scanState';
import { EmptyState, SeverityBadge } from '@/components/primitives';
import { IconTarget } from '@/components/icons';
import { SignalProfile } from '@/components/SignalProfile';
import { ScanNotice } from '@/components/ScanNotice';

const severities = [{id:'critical',label:'Критические'},{id:'high',label:'Высокие'},{id:'medium',label:'Средние'},{id:'low',label:'Низкие'}] as const;
export function Overview() {
  const t=useTrace();
  const [gate,setGate]=useState<GateResult|null>(null);
  const [gateError,setGateError]=useState(false);
  useEffect(()=>{let live=true;setGate(null);setGateError(false);if(t.scan) void getScanPolicy(t.scan.id).then(x=>{if(live)setGate(x);}).catch(()=>{if(live)setGateError(true);});return()=>{live=false;};},[t.scan?.id]);
  const s=t.scan;
  if(!s) return <EmptyState icon={<IconTarget className="h-5 w-5"/>} title="Начните с первой проверки" description="Создайте проект и запустите анализ или импортируйте отчёт сканера." action={<button className="btn-primary" onClick={()=>t.navigate(t.projectId?'scans':'projects')}>{t.projectId?'Новая проверка':'К проектам'} →</button>}/>;
  const coverage=scanCoverage(s);
  const pending=t.findings.filter(f=>!f.reviewed&&f.reachability!=='suppressed');
  const priority=[...pending].sort((a,b)=>Number(b.reachability==='reachable'&&b.verdict==='affected')-Number(a.reachability==='reachable'&&a.verdict==='affected')||b.cvss-a.cvss).slice(0,7);
  const recent=[...t.scans].filter(item=>item.projectId===s.projectId).sort((a,b)=>b.scannedAt.localeCompare(a.scannedAt)).slice(0,4);
  const openQueue=()=>{t.setFilter('all');t.setQuery('');t.navigate('findings');};
  return <div className="soc-dashboard">
    <header className="soc-heading"><div><p className="soc-eyebrow">TRACE / SECURITY OPERATIONS</p><h1>Обзор безопасности</h1><p>{s.repository}<span> / </span><code>{s.branch}</code></p></div><div className="soc-heading-actions"><time dateTime={s.scannedAt}>{new Date(s.scannedAt).toLocaleString('ru-RU')}</time><button className="btn" onClick={openQueue}>Все находки ↗</button><button className="btn-primary" onClick={()=>t.navigate('scans')}>+ Новая проверка</button></div></header>
    <ScanNotice/>
    <section className="soc-metrics" aria-label="Находки по критичности">{severities.map(level=>{const count=t.findings.filter(f=>f.severity===level.id).length;const share=t.findings.length?count/t.findings.length*100:0;return <div className={`soc-metric soc-${level.id}`} key={level.id}><div><span><i/>{level.label}</span><span className="soc-metric-code">{level.id.toUpperCase()}</span></div><strong>{count}</strong><div className="soc-meter" role="img" aria-label={`${level.label}: ${count} из ${t.findings.length}`}><span style={{width:`${share}%`}}/></div><p>{count} из {t.findings.length} находок выбранной проверки</p></div>;})}</section>
    <div className="soc-main-grid"><div className="soc-primary-column">
      <section className="panel soc-queue"><div className="soc-panel-heading"><div><h2>Приоритетная очередь</h2><p>Непроверенные · сначала достижимые и затронутые, затем по CVSS</p></div><button className="btn" onClick={()=>{t.setFilter('needs_review');t.setQuery('');t.navigate('findings');}}>Открыть триаж ↗</button></div>
        <div className="soc-table-scroll" role="region" aria-label="Приоритетные находки, таблица прокручивается по горизонтали" tabIndex={0}><table className="soc-table"><thead><tr><th>Находка / компонент</th><th>Критичность</th><th>Вердикт</th><th>Действие</th></tr></thead><tbody>{priority.map(f=><tr key={f.id}><td><button className="soc-finding-link" onClick={()=>{t.navigate('findings');t.select(f.id);}}>{f.cve}</button><p title={f.packageName}>{f.packageName}{f.version?` @ ${f.version}`:''}</p></td><td><SeverityBadge severity={f.severity} cvss={f.cvss} unscored={!!(f.evidence.nativeObservations?.length || f.evidence.webObservations?.length)}/></td><td><span className={`soc-verdict soc-verdict-${f.verdict}`}>{f.verdict==='affected'?'Затронута':f.verdict==='not_affected'?'Не затронута':'Нужна проверка'}</span></td><td><button className="soc-row-action" aria-label={`Открыть ${f.id}`} onClick={()=>{t.navigate('findings');t.select(f.id);}}>↗</button></td></tr>)}</tbody></table></div>
        {!priority.length&&<EmptyState compact title="Непроверенных находок нет" description="Оцените полноту анализа перед решением о релизе."/>}<footer className="soc-table-footer"><span>{pending.length} непроверенных · {t.findings.length} всего</span><span>Вердикт требует проверки доказательств</span></footer>
      </section>
      <section className="panel soc-runs"><div className="soc-panel-heading"><div><h2>Недавние проверки</h2><p>История выбранного проекта</p></div><button className="btn" onClick={()=>t.navigate('scans')}>Все запуски ↗</button></div><div className="soc-run-list">{recent.map(item=><button key={item.id} aria-current={s.id===item.id?'true':undefined} onClick={()=>t.setActiveScan(item.id)}><span className="soc-run-icon">⌁</span><span><strong>{item.branch}</strong><code>{item.commit||item.id}</code></span><span>{scanStatusLabel(item.status)}<time>{new Date(item.scannedAt).toLocaleString('ru-RU')}</time></span><strong>{item.counts.total}<small> находок</small></strong></button>)}</div></section>
    </div><aside className="soc-summary-column" aria-label="Сводка проверки">
      <SignalProfile findings={t.findings} onOpen={openQueue}/>
      <section className="panel soc-release"><div className="soc-panel-heading"><h2>Контроль релиза</h2><span className="soc-small-label">POLICY</span></div><div className="soc-release-value"><strong>{gate?gate.summary.blocking:'—'}</strong><span>блокирующих<br/>по текущей политике</span></div><p>{gateError?'Политика недоступна. Обновите страницу.':gate?'Решение по сохранённым результатам':'Загрузка политики…'}</p><div className="soc-coverage"><span>Полнота анализа</span><strong className={coverage.full?'attention-positive':'attention-warning'}>{coverage.full?'Подтверждена':'Не подтверждена'}</strong></div><p>Политика релиза не подтверждает полноту сканирования.</p><button className="btn" onClick={()=>t.navigate('settings')}>Настройки политики ↗</button></section>
      <section className="panel soc-engines"><div className="soc-panel-heading"><h2>Движки анализа</h2><span className="soc-small-label">{coverage.completed.length} / {s.scannerResults?.length||0}</span></div>{s.scannerResults?.length?s.scannerResults.map(engine=><div className="soc-engine-row" key={engine.id}><i className={engine.status==='completed'?'is-complete':''}/><div><strong>{engine.label}</strong><span title={engine.detail}>{scanStatusLabel(engine.status)}</span></div></div>):<p>Статусы движков не сохранены. Полнота проверки неизвестна.</p>}<button className="btn" onClick={()=>t.navigate('scans')}>Подробности проверки ↗</button></section>
    </aside></div>
  </div>;
}

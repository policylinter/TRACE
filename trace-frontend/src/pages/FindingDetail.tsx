import {SecurityContextPanel} from '@/components/SecurityContextPanel';
import { VerdictChip } from '@/components/primitives';
import { DeepAnalysisPanel } from '@/components/DeepAnalysisPanel';
import { useState } from 'react';
import type { Finding } from '@/data/findings';
import { useTrace } from '@/state/TraceProvider';
import { FindingWorkflow } from '@/components/FindingWorkflow';
import { ResultProvenance } from '@/components/ResultProvenance';
import { IconChevronLeft, IconCopy, IconCheck, IconGraph, IconDoc, IconTarget, IconShield } from '@/components/icons';
const kinds: Record<string, string> = { entrypoint: 'Точка входа', controller: 'Контроллер', service: 'Сервис', internal: 'Код проекта', library: 'Библиотека', sink: 'Уязвимая операция', barrier: 'Барьер' };
const severity: Record<string, string> = { critical: 'Критичная', high: 'Высокая', medium: 'Средняя', low: 'Низкая', unknown: 'Не определена' };
export function FindingDetail({ finding: f }: {
    finding: Finding;
}) {
    const t = useTrace();
    const [tab, setTab] = useState<'evidence' | 'fix' | 'team'>('evidence');
    const [frame, setFrame] = useState(0);
    const [copied, setCopied] = useState(false);
    const [error, setError] = useState('');
    const [busy, setBusy] = useState(false);
    const active = f.frames[frame];
    const native = !!f.evidence.nativeObservations?.length;
    const web = !!f.evidence.webObservations?.length;
    const baseline = f.evidence.model === 'TRACE HTTP Baseline';
    const rules = web || native || f.evidence.deepAnalysis?.source === 'rules' || f.evidence.model.includes('fallback: rules');
    async function copy() { try {
        await navigator.clipboard.writeText(`${f.cve}\n${f.packageName}@${f.version}\n${window.location.href}`);
        setCopied(true);
    }
    catch {
        setError('Не удалось скопировать. Выделите идентификатор находки вручную.');
    } }
    async function review() { setBusy(true); setError(''); try {
        await t.toggleReview(f, !f.reviewed);
    }
    catch (e) {
        setError(String(e));
    }
    finally {
        setBusy(false);
    } }
    return <article className="finding-workspace">
    <div className="detail-breadcrumb"><button onClick={t.closeDrawer}><IconChevronLeft className="h-4 w-4"/> Все находки</button><span>/</span><code>{f.id}</code></div>
    <header className="detail-heading">
      <div><div className="flex flex-wrap items-center gap-3"><span className={`risk-pill risk-${f.severity}`}>{severity[f.severity]}</span><span className="detail-type">{web ? (baseline ? 'DAST / HTTP baseline' : 'DAST / ZAP') : f.ecosystem === 'code' ? 'Анализ кода' : 'Уязвимая зависимость'}</span></div><h1>{f.cve}</h1><p className="detail-package">{f.packageName}{f.version && <span>@ {f.version}</span>}</p></div>
      <div className="flex flex-wrap gap-2"><button className="wb-button" onClick={() => void copy()}>{copied ? <IconCheck className="h-4 w-4"/> : <IconCopy className="h-4 w-4"/>}{copied ? 'Скопировано' : 'Поделиться'}</button><button className="wb-button" onClick={() => t.openVex('finding')}><IconDoc className="h-4 w-4"/> VEX</button><button className="wb-button wb-primary" disabled={busy || (t.auth?.enabled && t.user?.role === 'viewer')} onClick={() => void review()}>{f.reviewed ? 'Снять отметку' : 'Отметить проверенной'}</button></div>
    </header>
    {error && <p role="alert" className="wb-error">{error}</p>}
    <div className="finding-facts">
      <div><span title="API не различает исходный CVSS и оценку по серьёзности">CVSS из API</span><strong className="risk-number">{native || web ? 'Не оценивался' : <>{f.cvss.toFixed(1)}<small> / 10</small></>}</strong></div>
      <div><span>Достижимость</span><strong>{({ reachable: 'Путь найден', unreachable: 'Путь не найден', suppressed: 'Подавлена', unknown: 'Не определена' } as Record<string, string>)[f.reachability]}</strong></div>
      <div><span>Исправленная версия</span><strong>{f.fixedIn || 'Не указана'}</strong></div>
      <div><span>Ответственный</span><strong>{f.assignee || 'Не назначен'}</strong></div>
    </div>

    <section className="finding-summary wb-card"><span className="wb-kicker">ЧТО ОБНАРУЖЕНО</span><h2>Технический вердикт {f.reachability === 'suppressed' ? <span className="wb-count">Исключена аналитиком</span> : <VerdictChip value={f.verdict}/>}</h2><p>{f.evidence.headline || 'Краткое описание в отчёте отсутствует.'}</p><p className="wb-footnote">Вердикт анализа отделён от решения аналитика: {f.reviewed ? 'находка проверена' : 'ожидает проверки'}. Статус работы: {f.workflowStatus ? ({new: 'новая', in_progress: 'в работе', resolved: 'исправлена', accepted_risk: 'риск принят'}[f.workflowStatus]) : 'не указан'}.</p>{f.reachability === 'suppressed' && <p className="analysis-guard">Исключена аналитиком: {f.suppressReason || 'Причина не указана'}. Исключение не доказывает безопасность.</p>}</section>
    <nav className="workspace-tabs" aria-label="Разделы находки">{([{ id: 'evidence', label: 'Чем подтверждается', icon: IconGraph }, { id: 'fix', label: 'Как исправить', icon: IconShield }, { id: 'team', label: 'Работа команды', icon: IconTarget }] as const).map(item => <button key={item.id} aria-pressed={tab === item.id} onClick={() => setTab(item.id)}><item.icon className="h-4 w-4"/>{item.label}</button>)}</nav>
    {tab === 'evidence' && <details className="analysis-disclosure"><summary>Дополнительный разбор и происхождение результата</summary>    <DeepAnalysisPanel finding={f} onEvidence={ref=>{const match=/^frame-(\d+)$/.exec(ref);if(match){setTab('evidence');setFrame(Number(match[1])-1);requestAnimationFrame(()=>document.getElementById(`evidence-${ref}`)?.scrollIntoView({behavior:'smooth',block:'center'}));}}}/>
    <ResultProvenance finding={f}/>
</details>}
    {tab === 'evidence' && web && <section className="wb-card"><span className="wb-kicker">{baseline?'DAST / HTTP BASELINE':'DAST / ИМПОРТ ZAP'}</span><h2>{baseline?'Наблюдения HTTP-проверки':'Наблюдения из внешнего отчёта'}</h2><p className="wb-footnote">{baseline?'Выполнен один GET. Проверены только три правила заголовков HTML; эксплуатация и другие маршруты не проверялись.':'TRACE не обращался к адресам отчёта. Импорт не подтверждает эксплуатацию или новое выполнение проверки.'}</p>{f.evidence.webObservations?.map((item,i)=><article key={i} className="mt-4"><h3>{item.title}</h3><code className="break-all">{item.method} {item.url}</code><p className="mt-2 whitespace-pre-wrap">{item.description}</p></article>)}</section>}
    {tab === 'evidence' && !web && <div className="detail-grid">
      <section className="wb-card evidence-path"><div className="wb-card-heading"><div><span className="wb-kicker">{native ? 'СТРУКТУРНЫЙ АНАЛИЗ' : 'ПОТОК ДАННЫХ'}</span><h2>{native ? 'Наблюдения AST' : 'Путь к уязвимой операции'}</h2></div><span className="wb-count">{f.frames.length} {native ? 'наблюдений' : 'шагов'}</span></div>
        {f.evidence.taintSource && <div className="source-callout"><IconTarget className="h-4 w-4"/><div><span>Источник данных</span><p>{f.evidence.taintSource}</p></div></div>}
        {f.frames.length ? <ol className="flow-steps">{f.frames.map((node, index) => <li id={`evidence-frame-${index+1}`} key={`${node.symbol}-${index}`} className={index === frame ? 'flow-selected' : ''}><button onClick={() => setFrame(index)}><span className={`flow-marker ${node.vulnerable ? 'flow-danger' : ''}`}>{String(index + 1).padStart(2, '0')}</span><div><span className="flow-kind">{kinds[node.kind] || node.kind}</span><h3>{node.symbol}</h3><p>{node.location}{node.line ? `:${node.line}` : ''}</p></div>{node.vulnerable && <span className="risk-pill risk-critical">SINK</span>}</button>{node.edge && <div className="flow-edge-label">{node.edge}</div>}</li>)}</ol> : <div className="wb-empty">Доказательства пути вызовов в отчёте отсутствуют. Это не подтверждает безопасность.</div>}
        {f.blocker && <div className="wb-inset"><strong>Ограничение анализа</strong><p>{f.blocker}</p></div>}
      </section>
      <div className="detail-side">
        <section className="wb-card"><div className="wb-card-heading"><h2>Выбранный шаг</h2><span className="wb-count">{f.frames.length ? frame + 1 : 0} / {f.frames.length}</span></div>{active ? <><div className="code-location"><span>{active.location}{active.line ? `:${active.line}` : ''}</span><code>{active.symbol}</code></div><div className="step-note"><span className="wb-kicker">Сведения из доказательства</span><p>{active.note || 'Дополнительное описание отсутствует.'}</p></div><p className="wb-footnote">Отображаются сведения отчёта. Исходный файл для просмотра не загружен.</p></> : <p className="wb-footnote">Выберите шаг пути.</p>}</section>
        <section className="wb-card"><div className="wb-card-heading"><h2>Контекст зависимости</h2><span className="wb-count">{f.dependencyPath.length}</span></div><ol className="dependency-chain">{f.dependencyPath.map((item, i) => <li key={`${item}-${i}`}><i /><code>{item}</code></li>)}</ol></section>
        <section className="wb-card model-assessment"><div className="wb-card-heading"><h2>{rules ? 'Обоснование по правилам' : 'Оценка модели · не факт'}</h2><span className="wb-count">{f.evidence.model || t.scan?.aiEngine || 'Не указана'}</span></div><p className="model-headline">{f.evidence.headline || 'Обоснование отсутствует'}</p><details><summary>Полное обоснование</summary><p className="model-reasoning">{f.evidence.reasoning || 'Не представлено.'}</p></details><p className="wb-footnote">{rules ? 'Вывод получен по правилам, модель не использовалась. Проверьте доказательства и ограничения анализа.' : 'Вывод модели требует проверки по доказательствам и контексту проекта. Уверенность модели не является измеренной вероятностью безопасности.'}</p></section>
      </div>
    </div>}
    {tab === 'fix' && <section className="wb-card remediation-workspace"><span className="wb-kicker">ИСПРАВЛЕНИЕ</span><h2>План исправления</h2><div className="version-upgrade"><div><span>Сейчас</span><code>{f.version || 'Не указана'}</code></div><span>→</span><div><span>Исправленная версия из отчёта</span><code>{f.fixedIn || 'Не указана'}</code></div></div><ol>{f.evidence.remediation?.length ? f.evidence.remediation.map((item, i) => <li key={i}><span>{String(i + 1).padStart(2, '0')}</span><p>{item}</p></li>) : <li><p>Рекомендации отсутствуют. Проверьте бюллетень уязвимости и доступные обновления.</p></li>}</ol><div className="verify-callout"><IconCheck className="h-5 w-5"/><div><strong>Проверить результат</strong><p>После изменения запустите новую проверку и сравните её с этим запуском.</p></div><button className="wb-button wb-primary" onClick={() => { t.closeDrawer(); t.navigate('scans'); }}>К проверкам →</button></div></section>}
    {tab === 'team' && <section className="wb-card team-workspace"><span className="wb-kicker">РАБОТА КОМАНДЫ</span><h2>Решение и ответственность</h2><p className="wb-footnote">Назначьте ответственного, зафиксируйте срок и причину решения.</p><FindingWorkflow finding={f}/><SecurityContextPanel key={f.id} targetKind="finding" targetId={f.id} label={f.cve}/></section>}
  </article>;
}

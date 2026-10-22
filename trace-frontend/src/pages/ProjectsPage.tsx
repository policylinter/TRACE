import { scanCoverage } from '@/lib/scanState';
import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { createProject, getIntegrations, listScans, type IntegrationStatus, type Scan } from '@/lib/api';
import { useTrace } from '@/state/TraceProvider';
import { isDemoScan } from '@/lib/scanMode';
import { IconLayers, IconGraph, IconChevronRight, IconSearch, IconShield, IconTarget, IconCpu, IconAlert } from '@/components/icons';
function SnapshotMap() {
    const { sbom, navigate } = useTrace();
    const nodes = (sbom?.nodes || []).slice(0, 13);
    const layers = new Map<number, number>();
    for (const n of nodes)
        layers.set(n.depth, (layers.get(n.depth) || 0) + 1);
    const indices = new Map<number, number>();
    const positioned = nodes.map(n => { const row = indices.get(n.depth) || 0; indices.set(n.depth, row + 1); return { ...n, x: 40 + n.depth * 133, y: 24 + (row + 1) * 170 / ((layers.get(n.depth) || 0) + 1) }; });
    const map = new Map(positioned.map(n => [n.id, n]));
    return <button className="snapshot-map" onClick={() => navigate('sbom')} aria-label="Открыть карту зависимостей"><div className="map-caption"><span><i /> КАРТА АКТИВНОГО ПРОЕКТА</span><IconGraph className="h-4 w-4"/></div><svg viewBox="0 0 500 220" aria-label="Фрагмент графа зависимостей">{sbom?.edges.map((e, i) => { const a = map.get(e.source), b = map.get(e.target); return a && b ? <path key={i} d={`M${a.x} ${a.y} C${a.x + 65} ${a.y},${b.x - 65} ${b.y},${b.x} ${b.y}`} stroke={b.vulnerable ? 'var(--graph-risk-border)' : 'var(--graph-edge)'} fill="none"/> : null; })}{positioned.map(n => <g key={n.id} transform={`translate(${n.x},${n.y})`}><circle r={n.depth === 0 ? 13 : 7} fill={n.depth === 0 ? 'var(--accent)' : n.vulnerable ? 'var(--danger)' : 'var(--muted)'} stroke="var(--surface)" strokeWidth="4"/><text x="0" y="25" textAnchor="middle" fill="var(--muted)" fontSize="8">{n.label.length > 18 ? n.label.slice(0, 17) + '…' : n.label}</text></g>)}</svg><div className="map-bottom"><span>{sbom ? `${nodes.length} из ${sbom.nodes.length} узлов` : 'Граф ещё не построен'}</span><span>Исследовать граф ↗</span></div></button>;
}
export function ProjectsPage() {
    const t = useTrace();
    const [scans, setScans] = useState<Scan[] | null>(null);
    const [engines, setEngines] = useState<IntegrationStatus[] | null>(null);
    const [error, setError] = useState('');
    const [integrationError, setIntegrationError] = useState('');
    const [form, setForm] = useState(false);
    const [name, setName] = useState('');
    const [repo, setRepo] = useState('');
    const [saving, setSaving] = useState(false);
    const [query, setQuery] = useState('');
    const [filter, setFilter] = useState<'all' | 'attention'>('all');
    const [refresh, setRefresh] = useState(0);
    useEffect(() => { let live = true; setError(''); setIntegrationError(''); void listScans().then(v => { if (live)
        setScans(v); }).catch(e => { if (live)
        setError(String(e)); }); void getIntegrations().then(v => { if (live)
        setEngines(v.integrations.filter(i => i.kind === 'scanner')); }).catch(e => { if (live)
        setIntegrationError(String(e)); }); return () => { live = false; }; }, [t.projects, refresh]);
    const latest = useMemo(() => new Map(t.projects.map(p => [p.id, scans?.filter(s => s.projectId === p.id).sort((a, b) => b.scannedAt.localeCompare(a.scannedAt))[0]])), [scans, t.projects]);
    const snapshots = [...latest.values()].filter((s): s is Scan => Boolean(s));
    const total = snapshots.reduce((sum, s) => sum + s.counts.total, 0);
    const attention = snapshots.reduce((sum, s) => sum + s.counts.actionable, 0);
    const available = engines?.filter(e => e.available).length || 0;
    const projects = t.projects.filter(p => (`${p.name} ${p.repoUrl} ${latest.get(p.id)?.repository || ''}`).toLowerCase().includes(query.toLowerCase()) && (filter === 'all' || (latest.get(p.id)?.counts.actionable || 0) > 0));
    const priority = [...t.findings].filter(f => f.reachability !== 'suppressed').sort((a, b) => (Number(b.reachability === 'reachable') - Number(a.reachability === 'reachable')) || b.cvss - a.cvss).slice(0, 3);
    async function add(e: FormEvent) { e.preventDefault(); setSaving(true); setError(''); try {
        await createProject({ name: name.trim(), repoUrl: repo.trim() });
        await t.reload();
        setForm(false);
        setName('');
        setRepo('');
    }
    catch (e) {
        setError(String(e));
    }
    finally {
        setSaving(false);
    } }
    function open(id: number, view: 'overview' | 'scans' = 'overview') { t.setProject(id); t.closeDrawer(); t.navigate(view); }
    return <div className="project-workspace portfolio-workspace">
   <header className="portfolio-heading"><div><span className="wb-kicker">РАБОЧЕЕ ПРОСТРАНСТВО</span><h1>Обзор безопасности<span className="heading-dot">.</span></h1><p>Проекты, риски и следующие действия команды.</p></div><button className="wb-button wb-primary" disabled={!!t.auth?.enabled && t.user?.role === 'viewer'} onClick={() => setForm(v => !v)}><span className="text-lg">+</span> {form ? 'Закрыть форму' : 'Добавить проект'}</button></header>
   {form && <form onSubmit={add} className="wb-card project-form"><div className="wb-card-heading"><h2>Подключить проект</h2><span className="wb-kicker">01 / ПРОЕКТ</span></div><div className="grid gap-4 md:grid-cols-2"><label className="field-label">Название<input required maxLength={150} value={name} onChange={e => setName(e.target.value)} placeholder="payments-api"/></label><label className="field-label">Репозиторий<input value={repo} onChange={e => setRepo(e.target.value)} placeholder="https://gitlab.example.ru/team/project"/></label></div><div className="mt-4 flex flex-wrap items-center justify-between gap-3"><p className="wb-footnote">Проверка запускается отдельно после создания проекта.</p><button disabled={saving || !name.trim()} className="wb-button wb-primary">{saving ? 'Создание…' : 'Создать проект →'}</button></div></form>}
   {error && <p role="alert" className="wb-error">{error}</p>}
   <div className="portfolio-metrics">{[{ label: 'Проекты в пространстве', value: t.projects.length, icon: IconLayers, sub: 'Репозитории команды', tone: 'blue' }, { label: 'Находки в последних запусках', value: scans ? total : '—', icon: IconShield, sub: 'Последняя проверка каждого проекта', tone: 'orange' }, { label: 'Приоритетные находки', value: scans ? attention : '—', icon: IconTarget, sub: 'Достижимые с вердиктом «Затронута»', tone: 'rose' }, { label: 'Готовность движков', value: engines ? `${available} / ${engines.length}` : '—', icon: IconCpu, sub: engines && available === 0 ? 'Нужно подключить сканеры' : 'Доступность в текущем окружении', tone: 'violet' }].map(m => <div className={`portfolio-metric metric-${m.tone}`} key={m.label}><div className="metric-label"><span>{m.label}</span><m.icon className="h-4 w-4"/></div><strong>{m.value}</strong><p>{m.sub}</p></div>)}</div>
   {t.scan ? <div className="portfolio-stage"><section className="active-project-stage"><div className="stage-topline"><span className="wb-kicker">В ФОКУСЕ</span><span className="stage-badge">{isDemoScan(t.scan) ? 'Демонстрационный проект' : 'Активный проект'}</span></div><h2>{t.scan?.repository || 'Выберите первый проект'}</h2><p className="stage-context">{t.scan ? `⑂ ${t.scan.branch} · ${t.scan.commit || 'коммит не указан'}` : 'Начните с подключения репозитория команды'}</p><div className="severity-distribution">{(['critical', 'high', 'medium', 'low'] as const).map((severity, i) => { const count = t.findings.filter(f => f.severity === severity).length; return <div className={`severity-column severity-${severity}`} key={severity}><div className="severity-track"><span style={{ width: t.findings.length ? `${count / t.findings.length * 100}%` : '0%' }}/></div><strong>{count}</strong><span>{['Критичные', 'Высокие', 'Средние', 'Низкие'][i]}</span></div>; })}</div><div className="stage-footer"><span>{t.scan ? `Выбранный запуск · ${new Date(t.scan.scannedAt).toLocaleDateString('ru-RU')}` : 'Результатов пока нет'}</span><button onClick={() => t.navigate('overview')}>Обзор проекта <IconChevronRight className="h-4 w-4"/></button></div></section><SnapshotMap /></div> : <section className="wb-card empty-state"><h2 className="section-title">{t.projects.length ? 'Выберите проект и начните проверку' : 'Добавьте первый проект'}</h2><p className="mt-3">Результатов анализа ещё нет. Подключите проект, затем запустите анализ или импортируйте отчёт.</p><button className="btn-primary mt-4" onClick={() => setForm(true)}>Добавить проект</button></section>}
   <div className="portfolio-bottom"><section className="wb-card projects-directory"><div className="wb-card-heading"><div><h2>Проекты команды <span className="wb-count">{t.projects.length}</span></h2><p className="wb-footnote">Состояние по последней сохранённой проверке</p></div><div className="directory-search"><IconSearch className="h-4 w-4"/><input aria-label="Поиск проекта" placeholder="Найти проект…" value={query} onChange={e => setQuery(e.target.value)}/></div></div><div className="directory-tabs"><button aria-pressed={filter === 'all'} onClick={() => setFilter('all')}>Все проекты</button><button aria-pressed={filter === 'attention'} onClick={() => setFilter('attention')}>Требуют внимания</button></div><div className="project-rows">{projects.map(p => { const s = latest.get(p.id); const display = p.name === 'Default workspace' && s ? s.repository : p.name; return <article key={p.id} className="project-directory-row"><div className="project-avatar"><IconLayers className="h-5 w-5"/></div><button className="project-name-button" onClick={() => open(p.id)}><strong>{display}</strong><span>{s ? `⑂ ${s.branch} · ${s.commit || 'без коммита'}` : p.repoUrl || 'Источник ещё не указан'}</span></button><div className="project-status"><span className={`project-status-dot ${s && scanCoverage(s).full ? 'status-complete' : ''}`}/><span>{!scans ? 'Загрузка…' : !s ? 'Нет проверок' : isDemoScan(s) ? 'Демо' : s.status === 'partial' ? 'Неполная проверка' : s.status === 'failed' ? 'Ошибка' : s.status === 'completed' ? scanCoverage(s).full ? 'Проверка завершена' : 'Полнота неизвестна' : s.status}</span></div><div className="project-count"><strong>{s?.counts.total ?? '—'}</strong><span>находок</span></div><button className="project-open" aria-label={`Открыть проект ${display}`} onClick={() => open(p.id)}><IconChevronRight className="h-5 w-5"/></button></article>; })}{!projects.length && <div className="wb-empty">{query || filter !== 'all' ? 'Проекты по выбранным условиям не найдены.' : 'Добавьте проект, чтобы начать работу.'}</div>}</div><div className="directory-footer"><span>{projects.length} из {t.projects.length} проектов</span><button onClick={() => setRefresh(v => v + 1)}>Обновить данные ↻</button></div></section>
   <aside className="wb-card priority-panel"><div className="wb-card-heading"><h2>Требуют разбора</h2><span className="priority-dot"/></div><p className="wb-footnote">В выбранном проекте · {t.scan?.repository || 'проект не выбран'}</p>{priority.map(f => <button key={f.id} className="priority-finding" onClick={() => { t.navigate('findings'); t.select(f.id); }}><span className={`priority-severity priority-${f.severity}`}><IconAlert className="h-4 w-4"/></span><div><strong>{f.cve}</strong><p>{f.packageName}</p><span>CVSS {f.cvss} · {f.reachability === 'reachable' ? 'Путь найден' : 'Нужен анализ'}</span></div><IconChevronRight className="h-4 w-4"/></button>)}{!priority.length && <div className="wb-empty">В активной проверке нет находок для разбора.</div>}<button className="wb-text-link" onClick={() => t.navigate('findings')}>Открыть очередь находок →</button></aside></div>
   <section className="engine-dock"><span className="engine-dock-title"><IconCpu className="h-4 w-4"/> Движки</span>{engines?.map(e => <span key={e.id} className="engine-chip"><i className={e.available ? 'engine-ready' : ''}/>{e.label}</span>)}{integrationError && <span className="wb-error">Статусы недоступны</span>}<button onClick={() => t.navigate('settings')}>Настроить интеграции →</button></section>
 </div>;
}

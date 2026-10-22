import { scanStatusLabel } from '@/lib/scanState';
import { BranchHistory } from '@/components/BranchHistory';
import { SourceJobsPanel, SourceJobStatus } from '@/components/SourceJobsPanel';
import { useEffect, useState, type FormEvent } from 'react';
import { useTrace } from '@/state/TraceProvider';
import { getIntegrations, startSourceScan, getSourceJob, getFindings, createScan, type SourceJob } from '@/lib/api';
import type { Finding } from '@/data/findings';
import { IconGraph, IconSearch } from '@/components/icons';
import { EmptyState } from '@/components/primitives';
export function ScansPage() {
    const t = useTrace();
    const canWrite = !t.auth?.enabled || t.user?.role !== 'viewer';
    const canRunSource = !t.auth?.enabled || t.user?.role === 'admin';
    const [branch, setBranch] = useState('all');
    const [source, setSource] = useState('');
    const [ref, setRef] = useState('main');
    const [job, setJob] = useState<SourceJob | null>(null);
    const [error, setError] = useState('');
    const [sending, setSending] = useState(false);
    const [engines, setEngines] = useState<number | null>(null);
    const [integrationError, setIntegrationError] = useState('');
    const [launcherOpen,setLauncherOpen]=useState(false);
    useEffect(()=>{if(job?.jobId)setLauncherOpen(true);},[job?.jobId]);
    const [file, setFile] = useState<File | null>(null);
    const [baseline, setBaseline] = useState('');
    const [before, setBefore] = useState<Finding[] | null>(null);
    const [compareError, setCompareError] = useState('');
    useEffect(() => { let live = true; setBefore(null); setCompareError(''); if (baseline)
        void getFindings(baseline).then(x => { if (live)
            setBefore(x); }).catch(e => { if (live)
            setCompareError(String(e)); }); return () => { live = false; }; }, [baseline]);
    const key = (f: Finding) => `${f.ecosystem}:${f.packageName}:${f.cve}`;
    const oldKeys = new Set(before?.map(key));
    const nowKeys = new Set(t.findings.map(key));
    const added = before ? t.findings.filter(f => !oldKeys.has(key(f))) : [];
    const removed = before ? before.filter(f => !nowKeys.has(key(f))) : [];
    const project = t.projects.find(p => p.id === (t.projectId ?? t.scan?.projectId));
    const projectId = t.projectId ?? t.scan?.projectId ?? null;
    useEffect(() => { setSource(project?.repoUrl ?? ''); setBaseline(''); setBefore(null); setJob(null); setError(''); setFile(null); }, [projectId, project?.repoUrl]);
    useEffect(() => { let active = true; void getIntegrations().then(x => { if (active)
        setEngines(x.integrations.filter(i => i.kind === 'scanner' && i.available).length); }).catch(e => { if (active)
        setIntegrationError(String(e)); }); return () => { active = false; }; }, []);
    useEffect(() => { if (!job?.jobId || !['queued', 'running'].includes(job.status))
        return; let active = true; const timer = window.setInterval(() => { void getSourceJob(job.jobId).then(async (next) => { if (!active)
        return; setJob({ ...next, jobId: job.jobId }); if (next.status === 'completed') {
        await t.reload();
        if (active && next.scanId)
            t.setActiveScan(next.scanId);
    } }).catch(e => { if (active)
        setError(e instanceof Error ? e.message : 'Не удалось выполнить действие. Повторите запрос.'); }); }, 1800); return () => { active = false; clearInterval(timer); }; }, [job?.jobId, job?.status]);
    const list = [...t.scans].filter(s => s.projectId === projectId).filter(s => branch === 'all' || s.branch === branch).sort((a, b) => b.scannedAt.localeCompare(a.scannedAt));
    const branches = [...new Set(t.scans.map(s => s.branch))];
    async function start(event: FormEvent) { event.preventDefault(); if (!projectId)
        return; setSending(true); setError(''); try {
        setJob(await startSourceScan({ projectId, source: source.trim(), ref: ref.trim(), wait: false }));
    }
    catch (e) {
        setError(e instanceof Error ? e.message : 'Не удалось выполнить действие. Повторите запрос.');
    }
    finally {
        setSending(false);
    } }
    async function upload() { if (!file || !projectId)
        return; setSending(true); setError(''); try {
        if(file.size>10*1024*1024)throw new Error('Размер отчёта превышает 10 МиБ. Разделите отчёт перед импортом.');
        let json: unknown;
        try { json = JSON.parse(await file.text()); } catch { throw new Error('Файл не является корректным JSON. Проверьте содержимое и выберите отчёт ещё раз.'); }
        const result = await createScan({ projectId, repository: project?.repoUrl || project?.name || t.scan?.repository || 'project', branch: ref, files: [{ name: file.name, json }] });
        await t.reload();
        t.setActiveScan(result.id);
    }
    catch (e) {
        setError(e instanceof Error ? e.message : 'Не удалось выполнить действие. Повторите запрос.');
    }
    finally {
        setSending(false);
    } }
    const running = job && ['queued', 'running'].includes(job.status);
    return <div className="space-y-6"><header className="page-heading"><div><p className="eyebrow">История анализа</p><h1>Проверки</h1><p>Результаты по коммитам и веткам выбранного проекта.</p></div><span className="context-tag">{project?.name || t.scan?.repository || 'Выберите проект'}</span></header>
{list.length === 0 && !running ? (
  <EmptyState icon={<IconGraph className="h-5 w-5" />} title="Нет проверок" description={projectId ? 'Запустите первую проверку в выбранном проекте.' : 'Выберите проект, чтобы посмотреть или запустить проверки.'} action={projectId&&canWrite ? <button className="btn-primary" onClick={()=>setLauncherOpen(true)}>Открыть запуск и импорт</button> : undefined} />
) : null}

 
 <details open={launcherOpen} onToggle={e=>setLauncherOpen(e.currentTarget.open)} className="panel p-5 scan-launcher"><summary className="scan-launcher-summary">+ Новая проверка / импорт отчёта<span>Настроить запуск →</span></summary><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="section-title">Новая проверка</h2><p className="attention-caption">1. Укажите источник → 2. Выберите ветку → 3. Запустите анализ</p></div><span className="text-xs text-slate-400">{engines === null ? 'Доступность движков не определена' : `Доступно движков: ${engines}`}</span></div>
 <form onSubmit={start} className="mt-4 grid gap-3 lg:grid-cols-[1fr_180px_auto]"><label className="field-label">Репозиторий или локальный путь<input required value={source} onChange={e => setSource(e.target.value)} placeholder="https://gitlab.example.ru/team/repository"/></label><label className="field-label">Ветка / тег<input required value={ref} onChange={e => setRef(e.target.value)}/></label><button disabled={!canRunSource || sending || !!running || !projectId || !engines} className="btn-primary self-end disabled:opacity-40">{sending ? 'Отправка…' : running ? job?.requiresReview ? 'Требуется проверка задания' : 'Проверка выполняется…' : 'Запустить проверку'}</button></form>
 {engines === 0 && <p className="mt-3 text-sm text-amber-200">Подключите движки на сервере или загрузите готовый JSON-отчёт ниже.</p>}{integrationError && <p role="alert" className="mt-3 text-sm text-amber-200">Статусы движков недоступны: {integrationError}</p>}{!projectId && <p className="mt-3 text-sm text-amber-200">Сначала откройте проект в разделе «Проекты».</p>}
 <div className="mt-5 flex flex-wrap items-end gap-3 border-t border-hairline pt-4"><label className="field-label flex-1">Импорт отчёта Trivy, Grype, OSV, Semgrep или ZAP<input type="file" disabled={!canWrite} accept=".json,application/json" onChange={e => setFile(e.target.files?.[0] ?? null)}/></label><button onClick={() => void upload()} disabled={!canWrite || !file || !projectId || sending || !!running} className="btn disabled:opacity-40">Загрузить отчёт</button></div>
 {job && <SourceJobStatus job={job}/>}{error && <p role="alert" className="mt-3 text-rose-300">{error}</p>}</details>
 <SourceJobsPanel activeJob={job} onSelect={setJob} canCancel={canRunSource} refreshKey={t.scan?.scannedAt} watching={t.busy}/>
 <BranchHistory/>
 <section className="panel p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="section-title">Изменения находок</h2><p className="mt-2 text-xs text-slate-400">Активная проверка сравнивается по CVE, пакету и экосистеме. Отсутствие находки не подтверждает исправление при неполной проверке.</p></div><select aria-label="Базовая проверка" className="trace-select" value={baseline} onChange={e => setBaseline(e.target.value)}><option value="">Выберите базовый запуск</option>{t.scans.filter(s => s.id !== t.scan?.id && s.projectId === projectId).map(s => <option key={s.id} value={s.id}>{s.branch} · {s.commit || s.id}</option>)}</select></div>{compareError && <p role="alert" className="mt-3 text-rose-300">{compareError}</p>}{baseline && !before && !compareError && <p className="mt-3 text-slate-400">Загрузка сравнения…</p>}{before && <div className="mt-5 grid gap-4 sm:grid-cols-2"><div className="rounded-xl border border-rose-400/20 p-4"><p className="text-sm text-rose-200">Новые находки: {added.length}</p>{added.slice(0, 6).map(f => <button key={f.id} className="mt-3 block text-xs text-slate-300" onClick={() => { t.navigate('findings'); t.select(f.id); }}>{f.cve} · {f.packageName} →</button>)}</div><div className="rounded-xl border border-jade-400/20 p-4"><p className="text-sm text-jade-200">Больше не обнаружены: {removed.length}</p>{removed.slice(0, 6).map(f => <p key={f.id} className="mt-3 text-xs text-slate-400">{f.cve} · {f.packageName}</p>)}</div></div>}</section>
</div>;
}

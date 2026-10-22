import { useCallback, useEffect, useState } from 'react';
import { getSourceJobs, cancelSourceJob, type SourceJob } from '@/lib/api';
import { scanStatusLabel } from '@/lib/scanState';

export function sourceJobLabel(job: SourceJob) {
    if (job.status === 'cancelled') return 'Отменено до запуска';
    if (job.status === 'running' && job.executionState === 'heartbeat-lost') return 'Потеряна связь с worker';
    if (job.status === 'running' && job.executionState === 'unknown') return 'Выполнение не подтверждено';
    return scanStatusLabel(job.status === 'completed' ? job.scanStatus || 'completed' : job.status);
}

export function SourceJobStatus({ job }: { job: SourceJob }) {
    return <div role="status" className="mt-4 rounded-lg border border-hairline p-3 text-sm">
        <span className="break-all">Задание {job.jobId}: {sourceJobLabel(job)}</span>
        {job.status === 'running' && job.requiresReview && <p className="mt-2 text-amber-200">Состояние worker требует проверки администратором. Отсутствие heartbeat не доказывает остановку процесса. Автоматический повтор отключён, чтобы не создать дубликаты результатов.</p>}
        {job.lastHeartbeatAt && job.status === 'running' && <p className="mt-2 text-xs text-slate-400">Последний heartbeat: {new Date(job.lastHeartbeatAt * 1000).toLocaleString('ru-RU')}</p>}
        {job.reconciled && <p className="mt-2 text-slate-400">Статус восстановлен по сохранённому результату проверки.</p>}
        {job.error && <p className="mt-2 text-rose-300">Задание не выполнено. Проверьте источник и доступность движков на сервере.</p>}
    </div>;
}

export function SourceJobsPanel({ onSelect, activeJob, canCancel = false, refreshKey, watching = false }: { onSelect: (job: SourceJob) => void; activeJob: SourceJob | null; canCancel?: boolean; refreshKey?: string; watching?: boolean }) {
    const [items, setItems] = useState<SourceJob[]>([]);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(true);
    const [cancelling, setCancelling] = useState<string | null>(null);
    const [actionError, setActionError] = useState('');
    useEffect(() => {
        if (!watching) return;
        let live = true;
        const timer = window.setInterval(() => { void getSourceJobs().then(x => { if (live) { setItems(x); setError(''); } }).catch(e => { if (live) setError(String(e)); }); }, 1800);
        return () => { live = false; window.clearInterval(timer); };
    }, [watching]);
    async function cancel(id: string) { setCancelling(id); setActionError(''); try {
        const result = await cancelSourceJob(id);
        setItems(items => items.map(j => j.jobId === id ? result : j));
        if (activeJob?.jobId === id) onSelect(result);
    } catch (e) { setActionError(e instanceof Error ? e.message : 'Не удалось отменить ожидание'); }
    finally { setCancelling(null); } }
    const load = useCallback(async () => { setLoading(true); setError(''); try { setItems(await getSourceJobs()); } catch (e) { setError(e instanceof Error ? e.message : 'Не удалось загрузить задания'); } finally { setLoading(false); } }, []);
    useEffect(() => { let live = true; setLoading(true); void getSourceJobs().then(x => { if (live) { setItems(x); setError(''); } }).catch(e => { if (live) setError(String(e)); }).finally(() => { if (live) setLoading(false); }); return () => { live = false; }; }, [activeJob?.jobId, activeJob?.status, activeJob?.executionState, refreshKey]);
    return <section className="panel p-5"><div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="section-title">Фоновые задания</h2><p className="mt-2 text-xs text-slate-400">Последние 20 заданий выбранного пространства. Выберите задание, чтобы продолжить наблюдение после обновления страницы.</p></div><button className="btn" disabled={loading} onClick={() => void load()}>Обновить задания</button></div>
        {error ? <p role="alert" className="mt-3 text-rose-300">{error}</p> : loading ? <p className="mt-3 text-slate-400">Загрузка заданий…</p> : items.length === 0 ? <p className="mt-3 text-slate-400">Фоновых заданий в пространстве пока нет.</p> : <div className="mt-4 overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr><th className="p-2">Задание</th><th className="p-2">Состояние</th><th className="p-2">Действие</th></tr></thead><tbody>{items.map(j => <tr key={j.jobId} className="border-t border-hairline"><td className="p-2"><span className="break-all">{j.jobId}</span>{j.kind && <p className="mt-1 text-xs text-slate-400 break-all">{j.kind === 'sast' ? 'SAST' : j.kind === 'rescan' ? 'Пересчёт: ' + j.targetScanId : 'Проверка источника'}</p>}{j.createdAt && <p className="mt-1 text-xs text-slate-400">{new Date(j.createdAt * 1000).toLocaleString('ru-RU')}</p>}</td><td className="p-2">{sourceJobLabel(j)}</td><td className="p-2"><div className="flex flex-wrap gap-2"><button className="btn" onClick={() => onSelect(j)}>Наблюдать</button>{canCancel && j.status === 'queued' && j.cancellable === true && <button className="btn" disabled={cancelling !== null} onClick={() => void cancel(j.jobId)}>{cancelling === j.jobId ? 'Отмена…' : 'Отменить ожидание'}</button>}</div></td></tr>)}</tbody></table></div>}
        {actionError && <p role="alert" className="mt-3 text-rose-300">{actionError}</p>}
    </section>;
}

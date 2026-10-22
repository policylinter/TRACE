import { useState, type FormEvent } from 'react';
import { getJobRetention, type JobRetentionPlan } from '@/lib/api';

export function JobRetentionPanel() {
    const [days, setDays] = useState(90);
    const [plan, setPlan] = useState<JobRetentionPlan | null>(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    async function preview(event: FormEvent) {
        event.preventDefault(); setLoading(true); setError(''); setPlan(null);
        try { setPlan(await getJobRetention(days)); }
        catch (e) { setError(e instanceof Error ? e.message : 'Не удалось подготовить предварительный просмотр'); }
        finally { setLoading(false); }
    }
    function download() {
        if (!plan) return;
        const url = URL.createObjectURL(new Blob([JSON.stringify(plan, null, 2)], { type:'application/json' }));
        const link = document.createElement('a'); link.href=url; link.download='trace-job-retention-plan.json'; link.click();
        window.setTimeout(() => URL.revokeObjectURL(url),1000);
    }
    return <section className="panel p-5"><h2>Хранение истории заданий</h2>
        <p>Предпросмотр выбирает только завершённую историю фоновых заданий. Проверки, находки и журнал аудита сохраняются. Активные задания не затрагиваются.</p>
        <form onSubmit={e => void preview(e)} className="mt-4 flex flex-wrap items-end gap-3"><label className="field-label">Хранить историю, дней<input required type="number" min={1} max={3650} disabled={loading} value={days} onChange={e => { setDays(Number(e.target.value)); setPlan(null); setError(''); }}/></label><button className="btn" disabled={loading}>{loading ? 'Подготовка…' : 'Предварительный просмотр'}</button></form>
        {error && <p role="alert" className="mt-3 text-rose-300">{error}</p>}
        {plan && <div className="mt-4"><p>Граница хранения: {new Date(plan.cutoff*1000).toLocaleString('ru-RU')}. Пространство: {plan.workspaceId}.</p>
            {plan.candidates.length === 0 ? <p className="mt-2">Подходящих записей в этой выборке нет.</p> : <><p className="mt-2">В плане: {plan.candidates.length} заданий. Одна выборка ограничена {plan.limit} заданиями.</p>
            <div className="overflow-x-auto mt-3"><table><thead><tr><th>Задание</th><th>Завершено</th><th>Состояние</th></tr></thead><tbody>{plan.candidates.slice(0,20).map(j => <tr key={j.jobId}><td className="break-all">{j.jobId}</td><td>{new Date(j.finishedAt*1000).toLocaleString('ru-RU')}</td><td>{j.terminalReason === 'cancelled' ? 'Отменено до запуска' : j.status === 'completed' ? 'Выполнение завершено' : 'Ошибка выполнения'}</td></tr>)}</tbody></table></div>
            <p className="micro mt-2">Показаны первые 20 строк. Полный план содержит также число связанных служебных записей.</p><button className="btn mt-3" onClick={download}>Скачать план</button></>}
            <p className="micro mt-3">Данные не удалены. План действует один час; применение выполняется отдельно администратором после проверки.</p></div>}
    </section>;
}

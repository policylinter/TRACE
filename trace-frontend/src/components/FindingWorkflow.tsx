import { useState, useEffect, type FormEvent } from 'react';
import type { Finding } from '@/data/findings';
import { updateWorkflow, getEvents, type ScanEvent } from '@/lib/api';
import { useTrace } from '@/state/TraceProvider';
export function FindingWorkflow({ finding }: {
    finding: Finding;
}) {
    const t = useTrace();
    const canWrite = !t.auth?.enabled || t.user?.role === 'admin' || t.user?.role === 'analyst';
    const [owner, setOwner] = useState(finding.assignee || '');
    const [status, setStatus] = useState(finding.workflowStatus || 'new');
    const [due, setDue] = useState(finding.dueDate || '');
    const [note, setNote] = useState(finding.triageNote || '');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState('');
    const [saved, setSaved] = useState(false);
    const [history, setHistory] = useState<ScanEvent[]>([]);
    const [historyError, setHistoryError] = useState('');
    useEffect(() => { let live = true; void getEvents(100).then(events => { if (live)
        setHistory(events.filter(e => e.findingId === finding.id)); }).catch(e => { if (live)
        setHistoryError(String(e)); }); return () => { live = false; }; }, [finding.id, saved]);
    async function save(e: FormEvent) { e.preventDefault(); setBusy(true); setError(''); setSaved(false); try {
        await updateWorkflow(finding.id, { assignee: owner, status, dueDate: due || null, note });
        await t.reload();
        setSaved(true);
    }
    catch (e) {
        setError(String(e));
    }
    finally {
        setBusy(false);
    } }
    return <details className="panel-flat p-4"><summary className="cursor-pointer text-sm font-semibold text-slate-100">Работа команды · {owner || 'Не назначено'}</summary><form onSubmit={save} className="mt-4 space-y-3"><fieldset disabled={!canWrite || busy} className="space-y-3"><label className="field-label">Ответственный<input maxLength={128} value={owner} onChange={e => setOwner(e.target.value)} placeholder="Имя или логин"/></label><div className="grid grid-cols-2 gap-3"><label className="field-label">Статус<select className="trace-select" value={status} onChange={e => setStatus(e.target.value as typeof status)}><option value="new">Новая</option><option value="in_progress">В работе</option><option value="resolved">Исправлена вручную</option><option value="accepted_risk">Риск принят</option></select></label><label className="field-label">Срок / пересмотр<input type="date" required={status === 'accepted_risk'} value={due} onChange={e => setDue(e.target.value)}/></label></div><label className="field-label">Комментарий / причина<textarea required={status === 'accepted_risk'} maxLength={4000} className="rounded-lg border border-hairline bg-ink-950 p-3 text-sm text-slate-200" rows={3} value={note} onChange={e => setNote(e.target.value)}/></label><p className="text-xs text-slate-400">Ручной статус фиксирует решение команды. Подтверждение исправления требует повторной проверки.</p>{error && <p role="alert" className="text-sm text-rose-300">{error}</p>}{saved && <p role="status" className="text-sm text-jade-300">Изменения сохранены</p>}<button disabled={busy} className="btn-primary">{busy ? 'Сохранение…' : 'Сохранить'}</button></fieldset></form><details className="mt-4 border-t border-hairline pt-3"><summary className="cursor-pointer text-xs text-slate-400">Последние действия ({history.length})</summary>{historyError && <p className="mt-3 text-xs text-amber-200">{historyError}</p>}{history.map(e => <div key={e.id} className="mt-3 border-l border-hairline pl-3 text-xs"><p className="text-slate-200">{e.action} · {e.actor}</p><p className="mt-1 break-words text-slate-400">{e.detail}</p><time className="mt-1 block text-slate-400">{new Date(e.createdAt).toLocaleString('ru-RU')}</time></div>)}{!history.length && <p className="mt-3 text-xs text-slate-400">В последних 100 событиях действия по этой находке отсутствуют.</p>}</details></details>;
}

import { useTrace } from '@/state/TraceProvider';
import { isDemoScan } from '@/lib/scanMode';
import { scanCoverage, scanStatusLabel } from '@/lib/scanState';
export function ScanNotice() {
  const t = useTrace();
  const s = t.scan;
  const coverage = s ? scanCoverage(s) : null;
  return <div className="scan-notices">
    <div className="persistent-context" aria-label="Контекст проекта и проверки"><span>Проект <strong>{t.projects.find(p => p.id === (t.projectId ?? s?.projectId))?.name || s?.repository || 'Не выбран'}</strong></span><span>Проверка <code>{s?.id || 'Нет запусков'}</code>{s && <> · {s.branch} · {scanStatusLabel(s.status)}</>}</span><label className="context-scan-select">Выбрать запуск <select aria-label="Активная проверка" value={s?.id ?? ''} onChange={e => t.setActiveScan(e.target.value)} disabled={!s}><option value="" disabled>Нет проверок</option>{t.scans.filter(item => item.projectId === (t.projectId ?? s?.projectId)).map(item => <option key={item.id} value={item.id}>{item.branch} · {item.commit || item.id} · {new Date(item.scannedAt).toLocaleDateString('ru-RU')}</option>)}</select></label></div>
    {isDemoScan(s) && <div role="note" className="demo-ribbon"><span>ДЕМО</span><p>Демонстрационный запуск. Находки и доказательства приведены для примера.</p></div>}
    {coverage && !coverage.full && <div role="status" className={`coverage-notice ${s?.status === 'failed' ? 'coverage-error' : ''}`}><strong>{coverage.label}</strong><p>{s?.scannerResults?.length ? `Ошибок движков: ${coverage.failed.length} · не выполнено: ${coverage.skipped.length}.` : 'Статусы движков не сохранены.'} Отсутствие находок не подтверждает безопасность.</p></div>}
    {t.error && <div role="alert" className="coverage-notice"><strong>Не удалось обновить данные</strong><p>Показан сохранённый результат. Проверьте подключение и повторите запрос.</p><button className="btn" onClick={() => void t.reload()}>Повторить</button></div>}
  </div>;
}

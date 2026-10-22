import { useEffect, useMemo, useState } from 'react';
import { getComplianceStandards, getScanCompliance, type ComplianceReport, type ComplianceStandard } from '@/lib/api';
import { useTrace } from '@/state/TraceProvider';
import { Badge, Micro, PageHeader, Panel } from '@/components/primitives';
import { cx, downloadFile } from '@/lib/format';

const selectCls =
  'h-8 rounded-md border border-hairline bg-ink-950/60 px-2 font-mono text-[12px] text-slate-300 outline-none focus:border-jade-500/50';

export function CompliancePage() {
  const { scan, activeScanId } = useTrace();
  const [standards, setStandards] = useState<ComplianceStandard[]>([]);
  const [standard, setStandard] = useState('iso-27001');
  const [format, setFormat] = useState<'md' | 'html'>('md');
  const [report, setReport] = useState<ComplianceReport | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getComplianceStandards()
      .then((list) => {
        setStandards(list);
        if (list.length) setStandard(list[0].id);
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Не удалось загрузить стандарты'));
  }, []);

  const load = useMemo(
    () => async () => {
      if (!activeScanId) return;
      setBusy(true);
      setError(null);
      try {
        setReport(await getScanCompliance(activeScanId, standard, format));
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Не удалось сформировать отчёт');
      } finally {
        setBusy(false);
      }
    },
    [activeScanId, standard, format],
  );

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="compliance-workspace space-y-3">
      <PageHeader
        title="Соответствие стандартам"
        meta={scan ? `${scan.repository}@${scan.commit}` : '—'}
        right={
          <div className="flex flex-wrap items-center gap-2">
            <select aria-label="Стандарт соответствия" value={standard} onChange={(e) => setStandard(e.target.value)} className={selectCls}>
              {standards.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
            <div className="flex overflow-hidden rounded-md border border-hairline">
              {(['md', 'html'] as const).map((f) => (
                <button
                  key={f}
                  type="button"
                  onClick={() => setFormat(f)}
                  className={cx(
                    'px-2.5 py-1 font-mono text-2xs transition-colors',
                    format === f ? 'bg-jade-500/15 text-jade-200' : 'text-slate-400 hover:text-slate-200',
                  )}
                >
                  {f}
                </button>
              ))}
            </div>
            {activeScanId ? (
              <button type="button" disabled={busy} onClick={() => void load()} className="btn-ghost">
                {busy ? 'формирую…' : 'Обновить'}
              </button>
            ) : null}
            {report ? (
              <button type="button"
                className="btn-primary" disabled={busy}
                onClick={() => downloadFile(`trace-${report.scanId}-${report.standard}.${report.format}`, report.report, report.format === 'html' ? 'text/html' : 'text/markdown')}
              >
                Скачать
              </button>
            ) : null}
          </div>
        }
      />

      {error ? <p className="panel px-4 py-2.5 font-mono text-2xs text-rose-300">{error}</p> : null}

      {!activeScanId ? (
        <Panel className="p-6">
          <p className="text-center text-2xs text-slate-500">Нет активного скана — запустите анализ.</p>
        </Panel>
      ) : null}

      <Panel>
        {report ? (
          <div className="p-4">
            <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-2xs text-slate-500">
              <span>
                {report.standardName} · {report.format.toUpperCase()}
              </span>
              <span>{report.generatedAt}</span>
              <Badge tone="positive">offline</Badge>
            </div>
            {report.format === 'md' ? (
              <pre className="overflow-auto rounded-md border border-hairline bg-ink-950/60 p-4 text-2xs leading-relaxed text-slate-200">
                {report.report}
              </pre>
            ) : (
              <iframe title="compliance-report" sandbox="" className="h-[70vh] w-full rounded-md border border-hairline bg-white" srcDoc={report.report} />
            )}
          </div>
        ) : (
          <div className="p-6">
            <p className="text-center text-2xs text-slate-500">Загрузка отчёта…</p>
          </div>
        )}
      </Panel>
    </div>
  );
}
import { vexIntegrityIssue } from '@/lib/vexIntegrity';
import { useDialogFocus } from '@/hooks/useDialogFocus';
import { useEffect, useMemo, useState } from 'react';
import type { Finding } from '@/data/findings';
import { getVex, getVexMeta, type VexMeta } from '@/lib/api';
import type { VexScope } from '@/lib/vex';
import { copyToClipboard, downloadFile, cx, n } from '@/lib/format';
import { highlightJson } from '@/lib/highlight';
import { useTrace } from '@/state/TraceProvider';
import { Micro } from './primitives';
import { IconCheck, IconClose, IconCopy, IconDoc, IconDownload, IconShield } from './icons';

interface VexModalProps {
  open: boolean;
  selected: Finding | null;
  initialScope: VexScope;
  onClose: () => void;
}

export function VexModal({ open, selected, initialScope, onClose }: VexModalProps) {
  const dialogRef = useDialogFocus<HTMLDivElement>(open, onClose);
  const { scan, findings } = useTrace();
  const [scope, setScope] = useState<VexScope>(initialScope);
  const [json, setJson] = useState('');
  const [meta, setMeta] = useState<VexMeta | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // The modal stays mounted between openings, so the scope has to be re-seeded
  // whenever it is re-opened from a different entry point.
  useEffect(() => {
    if (open) { setScope(initialScope); setJson(''); setMeta(null); }
  }, [open, initialScope]);

  const effectiveScope: VexScope = scope === 'finding' && !selected ? 'actionable' : scope;

  useEffect(() => {
    if (!open || !scan) return;
    let cancelled = false;
    setLoading(true);
    setJson(''); setMeta(null);
    setError(null);
    Promise.all([
      getVex(scan.id, effectiveScope, selected?.id),
      getVexMeta(scan.id, effectiveScope),
    ])
      .then(([text, m]) => {
        if (cancelled) return;
        setJson(text);
        setMeta(effectiveScope === 'finding' && selected ? { ...m, count: 1, affected: selected.verdict === 'affected' ? 1 : 0, notAffected: selected.verdict === 'not_affected' ? 1 : 0, suppressed: selected.reachability === 'suppressed' ? 1 : 0 } : m);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Ошибка генерации VEX');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, scan, effectiveScope, selected?.id]);

  const integrityIssue = useMemo(() => vexIntegrityIssue(json, effectiveScope === 'finding' && selected ? [selected] : findings), [json, findings, effectiveScope, selected]);
  const tokens = useMemo(() => highlightJson(json), [json]);

  const scopeHint = (key: VexScope): string => {
    if (key === 'finding') return 'одна запись';
    if (key === 'actionable') return `${scan?.counts.actionable ?? 0} по вердикту`;
    return 'полный отчёт';
  };

  if (!open) return null;

  const fileName = meta?.fileName ?? 'trace-vex.csaf.json';

  const handleCopy = async () => {
    try {
      await copyToClipboard(json);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  };

  const handleDownload = () => {
    if (json && !loading && !error && !integrityIssue) downloadFile(fileName, json, 'application/json');
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/80 p-4 backdrop-blur-sm sm:p-8"
      ref={dialogRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-label="Генератор VEX-отчёта"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="panel animate-fade-rise flex h-full max-h-[860px] w-full max-w-6xl flex-col overflow-hidden">
        {/* Header */}
        <header className="flex shrink-0 flex-wrap items-start gap-3 border-b border-hairline px-5 py-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <IconDoc className="h-4 w-4 text-jade-300" />
              <h2 className="text-[14px] font-semibold tracking-tight text-slate-100">
                Генератор VEX-отчёта
              </h2>
              <span className="rounded border border-hairline bg-ink-800/50 px-1.5 py-0.5 font-mono text-2xs text-slate-400">
                CSAF 2.0
              </span>
            </div>
            <p className="mt-1 font-mono text-2xs text-slate-500">
              {meta?.documentId ?? '…'}
            </p>
          </div>
          <button type="button" onClick={onClose} className="btn-ghost h-7 w-7 p-0" title="Закрыть">
            <IconClose className="h-3.5 w-3.5" />
          </button>
        </header>

        {/* Scope + summary */}
        <div className="flex shrink-0 flex-wrap items-center gap-x-6 gap-y-3 border-b border-hairline bg-ink-950/40 px-5 py-3">
          <div className="flex items-center gap-2">
            <Micro>Область</Micro>
            <div className="flex items-center gap-0.5 rounded-md border border-hairline bg-ink-950/60 p-0.5">
              {(['finding', 'actionable', 'all'] as VexScope[]).map((key) => (
                <button
                  key={key}
                  type="button"
                  disabled={key === 'finding' && !selected}
                  onClick={() => setScope(key)}
                  className={cx(
                    'rounded px-2 py-1 text-2xs font-medium transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-40',
                    scope === key
                      ? 'bg-ink-750 text-slate-100 shadow-inset'
                      : 'text-slate-500 hover:text-slate-300',
                  )}
                >
                  {key === 'finding' ? 'Выбранная находка' : key === 'actionable' ? 'Достижимые · затронуты' : 'Все находки'}
                  <span className="ml-1.5 text-slate-600">{scopeHint(key)}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-4 font-mono text-2xs">
            <span className="text-slate-500">
              записей <span className="tnum text-slate-100">{loading || !meta ? '—' : n(meta.count)}</span>
            </span>
            <span className="text-rose-300">
              known_affected <span className="tnum">{loading || !meta ? '—' : n(meta.affected)}</span>
            </span>
            <span className="text-emerald-300">
              known_not_affected <span className="tnum">{loading || !meta ? '—' : n(meta.notAffected)}</span>
            </span>
            <span className="text-slate-500">
              из них подавлено <span className="tnum">{loading || !meta ? '—' : n(meta.suppressed)}</span>
            </span>
          </div>

          <div className="ml-auto flex items-center gap-2">
            <button type="button" onClick={handleCopy} disabled={loading || !!error || !!integrityIssue || !json} className="btn disabled:opacity-50">
              {copied ? (
                <IconCheck className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <IconCopy className="h-3.5 w-3.5" />
              )}
              {copied ? 'Скопировано' : 'Копировать'}
            </button>
            <button type="button" onClick={handleDownload} disabled={loading || !!error || !!integrityIssue || !json} className="btn-primary disabled:opacity-50">
              <IconDownload className="h-3.5 w-3.5" />
              Скачать .csaf.json
            </button>
          </div>
        </div>

        {integrityIssue && <p role="alert" className="wb-error mx-5 my-3">{integrityIssue}</p>}
        {/* Document */}
        <div className="min-h-0 flex-1 overflow-hidden">
          {loading ? (
            <div className="flex h-full items-center justify-center font-mono text-2xs text-slate-500">
              генерация CSAF 2.0 документа…
            </div>
          ) : error ? (
            <div className="flex h-full items-center justify-center px-4 text-center font-mono text-2xs text-rose-300">
              {error}
            </div>
          ) : (
            <pre className="h-full overflow-auto bg-ink-950/60 px-5 py-4 font-mono text-[11.5px] leading-[1.6] text-slate-300">
              <code className="whitespace-pre">{tokens}</code>
            </pre>
          )}
        </div>

        <footer className="flex shrink-0 flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-hairline px-5 py-3">
          <div className="flex items-center gap-2 text-2xs text-slate-500">
            <IconShield className="h-3.5 w-3.5 text-slate-600" />
            <span className="font-mono">
              {scan ? `${scan.repository}@${scan.commit} · ${scan.commitLong.slice(0, 12)}` : '—'}
            </span>
            <span className="text-slate-700">·</span>
            <span>Документ сформирован backend · требуется проверка содержания</span>
          </div>
          <span className="font-mono text-2xs text-slate-600">{fileName}</span>
        </footer>
      </div>
    </div>
  );
}

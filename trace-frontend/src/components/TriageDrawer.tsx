import { useRef, useState } from 'react';
import type { Finding } from '@/data/findings';
import { confidenceTone, copyToClipboard, cx, n } from '@/lib/format';
import { useTrace } from '@/state/TraceProvider';
import { Badge, Micro, ReachabilityChip, SeverityBadge, VerdictChip } from './primitives';
import { FindingWorkflow } from './FindingWorkflow';
import { ScanNotice } from './ScanNotice';
import { CallGraph } from './CallGraph';
import { IconCheck, IconClose, IconCopy, IconCpu, IconDoc, IconLock, IconSparkle } from './icons';

type SectionId = 'summary' | 'path' | 'ai' | 'remediation';

const SECTIONS: { id: SectionId; label: string }[] = [
  { id: 'summary', label: 'Сводка' },
  { id: 'path', label: 'Путь вызовов' },
  { id: 'ai', label: 'Обоснование ИИ' },
  { id: 'remediation', label: 'Исправление' },
];

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-baseline gap-3 py-1">
      <span className="w-[104px] shrink-0 text-2xs text-slate-600">{label}</span>
      <span className="min-w-0 break-words text-[11.5px] text-slate-300">{children}</span>
    </div>
  );
}

interface TriageDrawerProps {
  finding: Finding | null;
  onClose: () => void;
  onOpenVex: (finding: Finding) => void;
  /** True when the drawer must float above the table instead of sitting beside it. */
  overlay?: boolean;
}

export function TriageDrawer({ finding, onClose, onOpenVex, overlay = false }: TriageDrawerProps) {
  const { scan, toggleReview, suppress, unsuppress } = useTrace();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [showReason, setShowReason] = useState(false);
  const [reason, setReason] = useState('');

  const reviewed = finding?.reviewed ?? false;

  const onToggleReview = async () => {
    if (!finding) return;
    setBusy(true);
    try {
      await toggleReview(finding, !reviewed);
    } finally {
      setBusy(false);
    }
  };

  const onToggleSuppress = async () => {
    if (!finding) return;
    setBusy(true);
    try {
      await suppress(finding, reason.trim());
    } finally {
      setBusy(false);
      setShowReason(false);
      setReason('');
    }
  };

  const onUnsuppress = async () => {
    if (!finding) return;
    setBusy(true);
    try {
      await unsuppress(finding);
    } finally {
      setBusy(false);
      setShowReason(false);
      setReason('');
    }
  };

  const jumpTo = (id: SectionId) => {
    const container = scrollRef.current;
    const target = container?.querySelector<HTMLElement>(`[data-section="${id}"]`);
    if (!container || !target) return;
    container.scrollTo({ top: target.offsetTop - 12, behavior: 'smooth' });
  };

  const handleCopy = async () => {
    if (!finding) return;
    try {
      await copyToClipboard(finding.cve);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      setCopied(false);
    }
  };

  const isOpen = finding !== null;

  return (
    <aside
      aria-hidden={!isOpen}
      className={cx(
        'flex h-full shrink-0 flex-col border-l border-hairline bg-ink-900/85 transition-[width,transform,opacity] duration-[320ms] ease-swift',
        overlay
          ? isOpen
            ? 'fixed inset-0 z-40 w-full translate-x-0 opacity-100 shadow-drawer backdrop-blur'
            : 'pointer-events-none absolute inset-y-0 right-0 z-40 w-full max-w-[520px] translate-x-full opacity-0'
          : isOpen
            ? 'w-[520px] opacity-100'
            : 'w-0 overflow-hidden opacity-0',
      )}
    >
      {finding ? (
        <>
          {/* Header */}
          <header className="shrink-0 border-b border-hairline bg-ink-900/95 backdrop-blur">
            <div className="flex items-start gap-3 px-4 pb-3 pt-3.5">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[15px] font-semibold tracking-tight text-slate-50">
                    {finding.cve}
                  </span>
                  <SeverityBadge severity={finding.severity} cvss={finding.cvss} />
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-2">
                  <span className="font-mono text-2xs text-slate-500">{finding.id}</span>
                  <span className="text-slate-700">·</span>
                  <span className="font-mono text-2xs text-slate-500">
                    {finding.packageName}@{finding.version}
                  </span>
                </div>
              </div>

              <div className="flex shrink-0 items-center gap-1">
                <button
                  type="button"
                  onClick={handleCopy}
                  title="Скопировать CVE"
                  className="btn-ghost h-7 w-7 p-0"
                >
                  {copied ? (
                    <IconCheck className="h-3.5 w-3.5 text-emerald-400" />
                  ) : (
                    <IconCopy className="h-3.5 w-3.5" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={onClose}
                  title="Закрыть (Esc)"
                  className="btn-ghost h-7 w-7 p-0"
                >
                  <IconClose className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 px-4 pb-3">
              <ReachabilityChip value={finding.reachability} />
              <VerdictChip value={finding.verdict} confidence={finding.confidence} />
              {reviewed ? (
                <Badge tone="positive">
                  <IconCheck className="h-3 w-3" />
                  проверено
                </Badge>
              ) : null}
            </div>

            <nav className="no-scrollbar flex gap-0.5 overflow-x-auto border-t border-hairline px-3 py-1.5">
              {SECTIONS.map((section) => (
                <button
                  key={section.id}
                  type="button"
                  onClick={() => jumpTo(section.id)}
                  className="shrink-0 rounded px-2 py-1 text-2xs font-medium text-slate-500 transition-colors duration-150 hover:bg-white/[0.04] hover:text-slate-200"
                >
                  {section.label}
                </button>
              ))}
            </nav>
          </header>

          {/* Body */}
          <div
            ref={scrollRef}
            className="min-h-0 flex-1 space-y-6 overflow-y-auto overscroll-contain px-4 py-4"
          >
            <ScanNotice />
            <FindingWorkflow key={finding.id} finding={finding} />
            {finding.suppressReason ? (
              <div className="flex items-start gap-2.5 rounded-md border border-hairline bg-ink-800/30 px-3 py-2.5">
                <IconLock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
                <div className="min-w-0">
                  <div className="micro">Подавлено политикой</div>
                  <p className="mt-1 text-[11.5px] leading-relaxed text-slate-400">
                    {finding.suppressReason}
                  </p>
                </div>
              </div>
            ) : null}

            <section className="rounded-xl border border-jade-400/20 bg-jade-400/5 p-4 space-y-3" aria-label="Что исправить">
              <h3 className="text-sm font-semibold text-slate-100">Что исправить</h3>
              <p className="text-sm leading-relaxed text-slate-300">{finding.fixedIn ? `Обновите ${finding.packageName} с ${finding.version} до ${finding.fixedIn}.` : 'Исправленная версия не указана. Проверьте рекомендации и доступные обновления пакета.'}</p>
              <p className="text-xs leading-relaxed text-slate-400">{finding.frames[0] ? `Начало пути: ${finding.frames[0].location}${finding.frames[0].line ? ':' + finding.frames[0].line : ''}` : 'Путь вызовов не представлен в результатах проверки.'}</p>
              <button type="button" className="btn" onClick={() => jumpTo('remediation')}>Рекомендации по исправлению ↓</button>
              <p className="text-xs text-slate-400">Оценка ИИ требует проверки по доказательствам и контексту проекта.</p>
            </section>
            <section data-section="summary" className="space-y-3">
              <div className="flex items-center gap-2">
                <h3 className="micro-strong">Сводка находки</h3>
              </div>

              <div className="panel-flat divide-y divide-hairline px-3 py-1.5">
                <Row label="Пакет">
                  <span className="font-mono">{finding.packageName}</span>
                </Row>
                <Row label="Версия">
                  <span className="font-mono">
                    {finding.version}
                    <span className="ml-2 text-slate-600">
                      фикс в {finding.fixedIn}
                    </span>
                  </span>
                </Row>
                <Row label="Экосистема">
                  <span className="font-mono">{finding.ecosystem}</span>
                </Row>
                <Row label="CWE">
                  <span className="font-mono">{finding.cwe.join(' · ')}</span>
                </Row>
                <Row label="Сырых записей">
                  <span className="font-mono tnum">{n(finding.rawCount)}</span>
                  <span className="ml-1.5 text-slate-600">
                    → 1 находка после дедупликации
                  </span>
                </Row>
                <Row label="Уверенность">
                  <span className={cx('font-mono tnum', confidenceTone(finding.confidence))}>
                    {(finding.confidence * 100).toFixed(0)}%
                  </span>
                </Row>
              </div>

              <div className="panel-flat px-3 py-2.5">
                <Micro className="block">Путь зависимости</Micro>
                <ol className="mt-2 space-y-1">
                  {finding.dependencyPath.map((node, i) => (
                    <li key={node} className="flex items-center gap-2">
                      <span className="font-mono text-2xs text-slate-700">
                        {String(i).padStart(2, '0')}
                      </span>
                      <span
                        className={cx(
                          'break-all font-mono text-[11.5px]',
                          i === finding.dependencyPath.length - 1 ? 'text-slate-100' : 'text-slate-400',
                        )}
                      >
                        {node}
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            </section>

            <section data-section="path">
              <CallGraph finding={finding} />
            </section>

            <section data-section="ai" className="space-y-3">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <IconSparkle className="h-3.5 w-3.5 text-jade-300" />
                  <h3 className="micro-strong">Обоснование ИИ</h3>
                </div>
                <span className="flex items-center gap-1.5 rounded border border-hairline bg-ink-800/50 px-1.5 py-0.5 font-mono text-2xs text-slate-500">
                  <IconCpu className="h-3 w-3" />
                  {finding.evidence?.model ?? 'rules'}
                </span>
              </div>

              <div className="panel-flat px-3 py-2.5">
                <Micro className="block">Вывод</Micro>
                <p
                  className={cx(
                    'mt-1.5 text-[12px] font-medium leading-relaxed',
                    finding.verdict === 'affected' ? 'text-rose-200' : 'text-emerald-200',
                  )}
                >
                  {finding.evidence?.headline ?? ''}
                </p>

                <div className="mt-2.5 space-y-2 border-t border-hairline pt-2.5">
                  <p className="text-[11.5px] leading-[1.65] text-slate-400">
                    {finding.evidence?.reasoning ?? ''}
                  </p>
                </div>

                <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-hairline pt-2.5 font-mono text-2xs text-slate-600">
                  <span>runtime: {finding.evidence?.runtime ?? 'local'}</span>
                  <span>egress: {scan?.aiRuntime.egress ?? '0 B'}</span>
                  <span>host: {scan?.aiRuntime.host ?? 'local'}</span>
                </div>
              </div>

              <div className="panel-flat px-3 py-2.5">
                <Micro className="block">Сигналы анализа</Micro>
                <dl className="mt-2 divide-y divide-hairline">
                  {(finding.evidence?.signals ?? []).map((signal) => (
                    <div key={signal.label} className="flex items-baseline gap-2 py-1.5">
                      <span
                        className={cx(
                          'mt-1.5 h-1 w-1 shrink-0 rounded-full',
                          signal.tone === 'positive'
                            ? 'bg-emerald-400'
                            : signal.tone === 'negative'
                              ? 'bg-rose-400'
                              : 'bg-slate-600',
                        )}
                      />
                      <dt className="min-w-0 flex-1 text-[11.5px] text-slate-500">{signal.label}</dt>
                      <dd
                        className={cx(
                          'shrink-0 text-right font-mono text-[11.5px]',
                          signal.tone === 'positive'
                            ? 'text-emerald-300'
                            : signal.tone === 'negative'
                              ? 'text-rose-300'
                              : 'text-slate-400',
                        )}
                      >
                        {signal.value}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>

              {finding.evidence.counterfactual ? (
                <div className="rounded-md border border-hairline bg-ink-800/20 px-3 py-2.5">
                  <Micro className="block">Почему одного сканера недостаточно</Micro>
                  <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-400">
                    {finding.evidence.counterfactual}
                  </p>
                </div>
              ) : null}
            </section>

            <section data-section="remediation" className="space-y-3 pb-2">
              <h3 className="micro-strong">Рекомендации</h3>
              <ol className="space-y-2">
                {(finding.evidence?.remediation ?? []).map((item, i) => (
                  <li key={item} className="flex gap-2.5">
                    <span className="mt-0.5 font-mono text-2xs text-slate-600">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <p className="min-w-0 flex-1 text-[11.5px] leading-relaxed text-slate-300">
                      {item}
                    </p>
                  </li>
                ))}
              </ol>

              <div className="rounded-md border border-hairline bg-ink-800/20 px-3 py-2.5 font-mono text-2xs leading-relaxed text-slate-600">
                scan {scan?.scannedAt ?? '—'} · {(scan?.commitLong ?? '').slice(0, 12)} ·{' '}
                {scan?.pipeline ?? ''}
              </div>
            </section>
          </div>

          {/* Footer */}
          <footer className="shrink-0 border-t border-hairline bg-ink-900/95 px-4 py-3 backdrop-blur">
            {showReason && finding.reachability !== 'suppressed' ? (
              <div className="mb-3 space-y-2 rounded-md border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2.5">
                <Micro className="text-amber-200/80">Причина подавления</Micro>
                <textarea
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="например: зависимость не используется, backport, инфраструктура недоступна…"
                  spellCheck={false}
                  autoFocus
                  rows={3}
                  className="w-full resize-none rounded-md border border-hairline bg-ink-950/60 px-2.5 py-2 font-mono text-[11.5px] leading-relaxed text-slate-200 placeholder:text-slate-600 focus:border-jade-500/60 focus:outline-none"
                />
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={onToggleSuppress}
                    disabled={busy || !reason.trim()}
                    className="rounded border border-amber-500/30 bg-amber-500/10 px-2.5 py-1 text-2xs font-medium text-amber-200 transition-colors duration-150 hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    Подтвердить подавление
                  </button>
                  <button
                    type="button"
                    onClick={() => setShowReason(false)}
                    className="font-mono text-2xs text-slate-500 transition-colors duration-150 hover:text-slate-300"
                  >
                    отмена
                  </button>
                </div>
              </div>
            ) : null}

            <button
              type="button"
              onClick={() => onOpenVex(finding)}
              className="btn-primary w-full py-2 text-[12.5px] font-semibold"
            >
              <IconDoc className="h-3.5 w-3.5" />
              Сгенерировать VEX-отчёт
            </button>
            <div className="mt-2 flex items-center justify-between gap-2">
              <span className="font-mono text-2xs text-slate-600">
                CSAF 2.0 · Vulnerability Exploitability eXchange
              </span>
              <div className="flex items-center gap-1.5">
                {finding.reachability === 'suppressed' ? (
                  <button
                    type="button"
                    onClick={onUnsuppress}
                    disabled={busy}
                    className="btn-ghost text-2xs disabled:opacity-50"
                  >
                    Снять подавление
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={() => setShowReason((open) => !open)}
                    disabled={busy}
                    className="btn-ghost text-2xs disabled:opacity-50"
                  >
                    Подавить
                  </button>
                )}
                <button
                  type="button"
                  onClick={onToggleReview}
                  disabled={busy}
                  className="btn-ghost text-2xs disabled:opacity-50"
                >
                  {reviewed ? 'Снять отметку' : 'Отметить проверенным'}
                </button>
              </div>
            </div>
          </footer>
        </>
      ) : null}
    </aside>
  );
}
import { useMemo } from 'react';
import { useTrace } from '@/state/TraceProvider';
import { cx, n } from '@/lib/format';
import { CallGraph } from '@/components/CallGraph';
import { Micro, PageHeader, Panel, ReachabilityChip, SeverityBadge, VerdictChip } from '@/components/primitives';
import { IconGraph } from '@/components/icons';

export function Reachability() {
  const { scan, findings, select, openVex } = useTrace();

  const reachable = useMemo(
    () =>
      [...findings]
        .filter((f) => f.reachability === 'reachable' || f.reachability === 'suppressed')
        .sort((a, b) => a.cvss - b.cvss),
    [findings],
  );

  if (!scan) return null;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title={
          <span className="flex items-center gap-2">
            <IconGraph className="h-4 w-4 text-jade-300" />
            Анализ достижимости
          </span>
        }
        meta="semgrep taint analysis"
        right={
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-2xs">
            <span className="text-slate-500">
              групп <span className="tnum text-slate-100">{n(scan.counts.total)}</span>
            </span>
            <span className="text-rose-300">
              достижимо <span className="tnum">{n(scan.counts.reachable)}</span>
            </span>
            <span className="text-slate-400">
              не достижимо <span className="tnum">{n(scan.counts.unreachable)}</span>
            </span>
            <span className="text-slate-500">
              подавлено <span className="tnum">{n(scan.counts.suppressed)}</span>
            </span>
          </div>
        }
      />

      {reachable.length === 0 ? (
        <Panel>
          <div className="flex flex-col items-center justify-center gap-2 px-4 py-16 text-center">
            <IconGraph className="h-5 w-5 text-slate-700" />
            <p className="text-[12px] text-slate-400">Достижимых путей не обнаружено</p>
            <p className="font-mono text-2xs text-slate-600">
              все находки остановлены барьерами или недостижимы
            </p>
          </div>
        </Panel>
      ) : (
        reachable.map((finding) => (
          <Panel key={finding.id}>
            <header className="flex flex-wrap items-center gap-2 border-b border-hairline px-4 py-2.5">
              <button
                type="button"
                onClick={() => select(finding.id)}
                className="font-mono text-[13px] font-medium text-slate-100 hover:text-jade-200"
              >
                {finding.cve}
              </button>
              <span className="font-mono text-2xs text-slate-600">
                {finding.packageName}@{finding.version}
              </span>
              <SeverityBadge severity={finding.severity} cvss={finding.cvss} />
              <ReachabilityChip value={finding.reachability} />
              <VerdictChip value={finding.verdict} confidence={finding.confidence} />
              <div className="ml-auto flex items-center gap-2">
                <Micro>{finding.frames.length} узлов</Micro>
                <button
                  type="button"
                  onClick={() => {
                    select(finding.id);
                    openVex('finding');
                  }}
                  className="btn-ghost text-2xs"
                >
                  VEX
                </button>
              </div>
            </header>
            <div className="px-4 py-4">
              <CallGraph finding={finding} />
            </div>
          </Panel>
        ))
      )}

      <p className="px-1 pb-2 font-mono text-2xs text-slate-700">
        путь строится по taint-эвиденсу Semgrep · без эвиденса находки уходят в needs review ·{' '}
        <span className={cx(reachable.some((f) => f.reachability === 'reachable') && 'text-rose-400/70')}>
          {reachable.filter((f) => f.reachability === 'reachable').length} подтверждённых путей
        </span>
      </p>
    </div>
  );
}

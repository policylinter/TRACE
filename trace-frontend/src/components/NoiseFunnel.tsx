import { useEffect, useState } from 'react';
import { cx, funnelWidth, n, pct, reduction } from '@/lib/format';
import { useTrace } from '@/state/TraceProvider';
import { Badge, Micro, Panel, Stat } from './primitives';
import { IconCpu, IconLock, IconSparkle } from './icons';

export function NoiseFunnel() {
  const { scan } = useTrace();
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    const raf = requestAnimationFrame(() => setMounted(true));
    return () => cancelAnimationFrame(raf);
  }, []);

  if (!scan) return null;

  const stages = scan.funnel;
  const totalRaw = scan.rawCount;
  const actionable = scan.counts.actionable;
  const noiseReduction = reduction(totalRaw, actionable);
  const max = stages[0]?.value ?? totalRaw;

  return (
    <Panel className="relative overflow-hidden">
      {/* A single, restrained sweep of light. No gradients-as-decoration beyond this. */}
      <div
        className="pointer-events-none absolute inset-x-0 top-0 h-px rule-top-fade"
        aria-hidden="true"
      />
      <div
        className="pointer-events-none absolute -right-24 -top-32 h-72 w-72 rounded-full opacity-60"
        aria-hidden="true"
        style={{
          background:
            'radial-gradient(circle, rgba(99,102,241,0.16) 0%, rgba(99,102,241,0) 68%)',
        }}
      />

      <header className="relative flex flex-wrap items-start justify-between gap-x-4 gap-y-3 px-4 pb-3 pt-3.5 sm:px-5">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <IconSparkle className="h-3.5 w-3.5 text-jade-300" />
            <h1 className="text-[13px] font-semibold tracking-tight text-slate-100">
              Воронка снижения шума
            </h1>
            <Badge tone="accent">Noise Reduction Funnel</Badge>
          </div>
          <p className="mt-1 max-w-2xl text-[12px] leading-relaxed text-slate-400">
            {scan.repository}@{scan.commit} ·{' '}
            <span className="font-mono text-slate-500">{scan.branch}</span> — все находки
            сканеров проходят через дедупликацию пакетов, анализ графа вызовов и локальную
            модель. Наружу выходит только то, что реально достижимо.
          </p>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          <div className="hidden items-center gap-1.5 rounded-md border border-hairline bg-ink-800/50 px-2 py-1 sm:flex">
            <IconCpu className="h-3.5 w-3.5 text-slate-500" />
            <span className="font-mono text-2xs text-slate-400">{scan.aiRuntime.model}</span>
            <span className="font-mono text-2xs text-slate-600">{scan.aiRuntime.quantisation}</span>
          </div>
          <Badge tone="positive">
            <IconLock className="h-3 w-3" />
            egress {scan.aiRuntime.egress}
          </Badge>
        </div>
      </header>

      {/* Hero numbers */}
      <div className="relative grid grid-cols-1 divide-y divide-hairline border-y border-hairline bg-ink-950/40 sm:grid-cols-3 sm:divide-x sm:divide-y-0">
        <Stat
          label="Вход · сырые находки"
          value={<>{n(totalRaw)}</>}
          hint={
            <span className="font-mono">
              Trivy + Grype + OSV · {stages[0]?.engine}
            </span>
          }
        />
        <Stat
          label="Выход · реальные уязвимости"
          value={
            <>
              {actionable}
              <span className="ml-2 align-middle text-[11px] font-normal text-slate-500">
                / {stages[1]?.value} пакетных групп
              </span>
            </>
          }
          hint={<span className="font-mono">подтверждено Semgrep Call Graph</span>}
          tone="text-rose-300"
        />
        <Stat
          label="Эффект · шум отсеян"
          value={<span className="text-emerald-300">−{pct(noiseReduction)}</span>}
          hint={
            <span className="font-mono">
              {n(totalRaw - actionable)} из {n(totalRaw)} записей
            </span>
          }
          tone="text-emerald-300"
        />
      </div>

      {/* Stages — width is drawn on a log10 scale so the small stages stay legible. */}
      <div className="relative px-4 py-4 sm:px-5">
        <ol className="space-y-2.5">
          {stages.map((stage, i) => {
            const width = funnelWidth(stage.value, max);
            const delta = i === 0 ? null : reduction(stages[i - 1].value, stage.value);
            const isLast = i === stages.length - 1;

            return (
              <li key={stage.key}>
                <div className="flex items-baseline justify-between gap-3">
                  <div className="flex min-w-0 items-baseline gap-2">
                    <span className="font-mono text-2xs text-slate-600">
                      {String(i + 1).padStart(2, '0')}
                    </span>
                    <span className="truncate text-[12px] font-medium text-slate-200">
                      {stage.label}
                    </span>
                    <span className="hidden truncate font-mono text-2xs text-slate-600 lg:inline">
                      {stage.engine}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-baseline gap-2">
                    {delta !== null ? (
                      <span
                        className={cx(
                          'tnum font-mono text-2xs',
                          delta >= 99 ? 'text-emerald-400' : 'text-slate-500',
                        )}
                      >
                        −{pct(delta)}
                      </span>
                    ) : (
                      <span className="font-mono text-2xs text-slate-600">baseline</span>
                    )}
                    <span className="tnum w-[52px] text-right font-mono text-[13px] font-medium text-slate-100">
                      {n(stage.value)}
                    </span>
                  </div>
                </div>

                <div className="mt-1.5 h-[6px] w-full overflow-hidden rounded-[3px] bg-slate-800/50">
                  <div
                    className={cx(
                      'h-full rounded-[3px] transition-[width] duration-[900ms] ease-swift',
                      isLast
                        ? 'bg-gradient-to-r from-rose-500/90 to-rose-400/70'
                        : i === 2
                          ? 'bg-gradient-to-r from-amber-500/80 to-amber-400/50'
                          : i === 1
                            ? 'bg-gradient-to-r from-jade-500/70 to-jade-400/40'
                            : 'bg-gradient-to-r from-slate-600/70 to-slate-500/40',
                    )}
                    style={{
                      width: mounted ? `${width * 100}%` : '0%',
                      transitionDelay: `${i * 110}ms`,
                    }}
                  />
                </div>

                <p className="mt-1 truncate text-2xs text-slate-600">{stage.operation}</p>
              </li>
            );
          })}
        </ol>
      </div>

      <footer className="relative flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-t border-hairline px-4 py-2.5 sm:px-5">
        <div className="flex flex-wrap items-center gap-1.5">
          <Micro className="mr-1">Движки</Micro>
          {scan.engines.map((engine) => (
            <span
              key={engine.name}
              className="rounded-md border border-hairline bg-ink-800/50 px-1.5 py-0.5 font-mono text-2xs text-slate-400"
            >
              {engine.name}
              <span className="text-slate-600">@{engine.version}</span>
            </span>
          ))}
        </div>
        <div className="font-mono text-2xs text-slate-600">
          {scan.pipeline} · {scan.duration} · {scan.sbom}
        </div>
      </footer>
    </Panel>
  );
}

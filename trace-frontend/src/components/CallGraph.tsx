import type { CallFrame, Finding, FrameKind } from '@/data/findings';
import { cx } from '@/lib/format';
import { IconAlert, IconLock, IconTarget } from './icons';

const KIND: Record<FrameKind, { label: string; text: string; dot: string; ring: string }> = {
  entrypoint: {
    label: 'Точка входа',
    text: 'text-jade-300',
    dot: 'bg-jade-400',
    ring: 'ring-jade-500/25',
  },
  controller: {
    label: 'Контроллер',
    text: 'text-sky-300',
    dot: 'bg-sky-400',
    ring: 'ring-sky-500/25',
  },
  service: {
    label: 'Сервис',
    text: 'text-teal-300',
    dot: 'bg-teal-400',
    ring: 'ring-teal-500/25',
  },
  internal: {
    label: 'Внутренний код',
    text: 'text-slate-400',
    dot: 'bg-slate-500',
    ring: 'ring-slate-500/20',
  },
  library: {
    label: 'Библиотека',
    text: 'text-violet-300',
    dot: 'bg-violet-400',
    ring: 'ring-violet-500/25',
  },
  sink: {
    label: 'Уязвимый символ',
    text: 'text-rose-300',
    dot: 'bg-rose-400',
    ring: 'ring-rose-500/40',
  },
  barrier: {
    label: 'Барьер',
    text: 'text-slate-400',
    dot: 'bg-slate-700',
    ring: 'ring-slate-700/40',
  },
};

function locationLabel(frame: CallFrame): string {
  return frame.line ? `${frame.location}:${frame.line}` : frame.location;
}

export function CallGraph({ finding }: { finding: Finding }) {
  const frames = finding.frames;
  const edges = frames.filter((f) => f.edge).length;
  const isBlocked = finding.reachability === 'unreachable';

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <IconTarget className="h-3.5 w-3.5 text-slate-500" />
          <h3 className="micro-strong">Граф вызовов</h3>
          <span className="font-mono text-2xs text-slate-600">
            {frames.length} узлов · {edges} рёбер
          </span>
        </div>
        <span className="font-mono text-2xs text-slate-600">
          {isBlocked ? 'путь прерван барьером' : 'путь до уязвимого символа'}
        </span>
      </div>

      {finding.evidence.taintSource ? (
        <div className="flex items-start gap-2.5 rounded-md border border-amber-500/25 bg-amber-500/[0.06] px-3 py-2.5">
          <IconAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" />
          <div className="min-w-0">
            <div className="micro text-amber-300/80">Источник недоверенных данных</div>
            <div className="mt-1 break-words font-mono text-[11.5px] leading-relaxed text-amber-100/90">
              {finding.evidence.taintSource}
            </div>
          </div>
        </div>
      ) : null}

      {isBlocked && finding.blocker ? (
        <div className="flex items-start gap-2.5 rounded-md border border-hairline bg-ink-800/30 px-3 py-2.5">
          <IconLock className="mt-0.5 h-3.5 w-3.5 shrink-0 text-slate-500" />
          <div className="min-w-0">
            <div className="micro">Почему путь недостижим</div>
            <div className="mt-1 text-[11.5px] leading-relaxed text-slate-400">{finding.blocker}</div>
          </div>
        </div>
      ) : null}

      <ol className="relative">
        {frames.map((frame, i) => {
          const meta = KIND[frame.kind];
          const isSink = frame.kind === 'sink';
          const isBarrier = frame.kind === 'barrier';
          const isLast = i === frames.length - 1;

          return (
            <li key={`${frame.symbol}-${i}`} className="relative grid grid-cols-[18px_minmax(0,1fr)] gap-x-3">
              <div className="flex flex-col items-center">
                <span className={cx('h-3 w-px', i === 0 ? 'bg-transparent' : 'bg-slate-700/70')} />
                <span className="relative flex h-4 w-4 shrink-0 items-center justify-center">
                  {isSink ? (
                    <span className="absolute inset-0 animate-pulse-ring rounded-full bg-rose-500/40" />
                  ) : null}
                  <span
                    className={cx(
                      'relative h-[9px] w-[9px] rounded-full ring-4',
                      meta.dot,
                      meta.ring,
                    )}
                  />
                </span>
                <span
                  className={cx(
                    'w-px flex-1',
                    isLast ? 'bg-transparent' : isBarrier ? 'bg-slate-800' : 'bg-slate-700/70',
                  )}
                />
              </div>

              <div className={cx('pb-3', isLast && 'pb-0')}>
                {frame.edge ? (
                  <div className="mb-2 flex items-center gap-1.5 pl-0.5">
                    <span className="font-mono text-2xs leading-relaxed text-slate-600">
                      ↓ {frame.edge}
                    </span>
                  </div>
                ) : null}

                <div
                  className={cx(
                    'rounded-md border px-3 py-2.5 transition-colors duration-150',
isSink
                        ? 'border-rose-500/40 bg-rose-500/[0.07] shadow-sink'
                        : isBarrier
                          ? 'border-dashed border-hairline-strong bg-ink-800/20'
                          : 'border-hairline bg-ink-850/40 hover:border-hairline-strong',
                  )}
                >
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className={cx('text-2xs font-semibold uppercase tracking-micro', meta.text)}>
                      {meta.label}
                    </span>
                    {isSink ? (
                      <span className="rounded border border-rose-500/40 bg-rose-500/15 px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-micro text-rose-200">
                        эксплуатируется
                      </span>
                    ) : null}
                    {isBarrier ? (
                      <span className="rounded border border-hairline-strong bg-ink-800/60 px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase tracking-micro text-slate-400">
                        путь прерван
                      </span>
                    ) : null}
                  </div>

                  <div
                    className={cx(
                      'mt-1.5 break-words font-mono text-[12px] font-medium leading-snug',
                      isSink ? 'text-rose-100' : isBarrier ? 'text-slate-300' : 'text-slate-100',
                    )}
                  >
                    {frame.symbol}
                  </div>

                  <div className="mt-1 break-all font-mono text-2xs leading-relaxed text-slate-500">
                    {locationLabel(frame)}
                  </div>

                  {frame.note ? (
                    <p
                      className={cx(
                        'mt-1.5 text-[11.5px] leading-relaxed',
                        isSink ? 'text-rose-200/80' : 'text-slate-400',
                      )}
                    >
                      {frame.note}
                    </p>
                  ) : null}
                </div>
              </div>
            </li>
          );
        })}
      </ol>

      {finding.evidence.sink ? (
        <div className="rounded-md border border-rose-500/30 bg-rose-500/[0.05] px-3 py-2.5">
          <div className="micro text-rose-300/80">Сигнатура достигнутого символа</div>
          <div className="mt-1 break-all font-mono text-[11.5px] leading-relaxed text-rose-100/90">
            {finding.evidence.sink}
          </div>
        </div>
      ) : null}
    </div>
  );
}
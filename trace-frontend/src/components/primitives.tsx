import { useEffect, useRef, useState, type CSSProperties, type ReactNode } from 'react';
import {
  cx,
  n,
  reachabilityMeta,
  severityTone,
  verdictMeta,
  type Tone,
} from '@/lib/format';
import type { Reachability, Severity, Usage, Verdict } from '@/data/findings';

/** Ease-out-quartic count of `target`, restarted whenever `target` changes. */
export function useCountUp(target: number, duration = 850, delay = 0): number {
  const [value, setValue] = useState(0);
  const rafRef = useRef(0);
  const timerRef = useRef(0);

  useEffect(() => {
    const from = value;
    let start = 0;
    const tick = (now: number) => {
      if (!start) start = now;
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 4);
      setValue(Math.round(from + (target - from) * eased));
      if (t < 1) rafRef.current = window.requestAnimationFrame(tick);
    };
    timerRef.current = window.setTimeout(() => {
      rafRef.current = window.requestAnimationFrame(tick);
    }, delay);
    return () => {
      window.clearTimeout(timerRef.current);
      window.cancelAnimationFrame(rafRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, duration, delay]);

  return value;
}

export function AnimatedNumber({
  value,
  format = String,
  duration = 850,
  delay = 0,
  className,
}: {
  value: number;
  format?: (value: number) => string;
  duration?: number;
  delay?: number;
  className?: string;
}) {
  const animated = useCountUp(value, duration, delay);
  return <span className={className}>{format(animated)}</span>;
}

export function Panel({
  children,
  className,
  style,
}: {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <section className={cx('panel', className)} style={style}>
      {children}
    </section>
  );
}

export function Micro({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return <span className={cx('micro', className)}>{children}</span>;
}

export function SectionTitle({
  index,
  children,
  right,
}: {
  index?: string;
  children: ReactNode;
  right?: ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-3 border-b border-hairline px-4 py-3">
      <div className="flex min-w-0 items-center gap-2">
        {index ? <span className="font-mono text-2xs text-slate-600">{index}</span> : null}
        <h2 className="micro-strong truncate">{children}</h2>
      </div>
      {right ? <div className="flex shrink-0 items-center gap-2">{right}</div> : null}
    </div>
  );
}

export function SeverityBadge({ severity, cvss, unscored=false }: { severity: Severity; cvss: number; unscored?:boolean }) {
  const tone = severityTone(severity);
  return (
    <span
      title={unscored ? 'Наблюдение AST: CVSS не оценивался. Серьёзность задана правилом.' : 'CVSS получен из API. Backend может подставлять оценку по серьёзности и не сообщает источник значения.'}
      className={cx(
        'inline-flex items-center gap-1.5 rounded border px-1.5 py-0.5 font-mono text-2xs font-medium',
        tone.bg,
        tone.border,
        tone.text,
      )}
    >
      <span className={cx('h-1 w-1 rounded-full', tone.dot)} />
      {tone.label}
      <span className="tnum text-slate-500">{unscored ? '—' : cvss.toFixed(1)}</span>
    </span>
  );
}

export function ReachabilityChip({ value }: { value: Reachability }) {
  const meta = reachabilityMeta(value);
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-1.5 py-0.5 text-2xs font-medium uppercase tracking-wide',
        meta.bg,
        meta.border,
        meta.text,
      )}
    >
      <span className={cx('h-1 w-1 shrink-0 rounded-full', meta.dot)} />
      {meta.label}
    </span>
  );
}

export function VerdictChip({
  value,
  confidence,
}: {
  value: Verdict;
  confidence?: number;
}) {
  const meta = verdictMeta(value);
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-1.5 py-0.5 font-mono text-2xs font-medium',
        meta.bg,
        meta.border,
        meta.text,
      )}
    >
      <span className={cx('h-1 w-1 shrink-0 rounded-full', meta.dot)} />
      {meta.label}
      {typeof confidence === 'number' ? (
        <span className="tnum text-slate-500">{(confidence * 100).toFixed(0)}%</span>
      ) : null}
    </span>
  );
}

const USAGE_META: Record<Usage, { label: string; bg: string; border: string; text: string; dot: string }> = {
  imported: {
    label: 'import',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/25',
    text: 'text-amber-300',
    dot: 'bg-amber-400',
  },
  referenced: {
    label: 'ref',
    bg: 'bg-amber-500/[0.07]',
    border: 'border-amber-500/20',
    text: 'text-amber-200/80',
    dot: 'bg-amber-400/70',
  },
  absent: {
    label: 'unused',
    bg: 'bg-emerald-500/10',
    border: 'border-emerald-500/25',
    text: 'text-emerald-300',
    dot: 'bg-emerald-400',
  },
  unknown: {
    label: '—',
    bg: 'bg-ink-800/40',
    border: 'border-hairline',
    text: 'text-slate-500',
    dot: 'bg-slate-600',
  },
};

export function UsageBadge({ value, note }: { value?: Usage; note?: string }) {
  const meta = USAGE_META[value ?? 'unknown'] ?? USAGE_META.unknown;
  return (
    <span
      title={note}
      className={cx(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded border px-1.5 py-0.5 font-mono text-2xs font-medium',
        meta.bg,
        meta.border,
        meta.text,
      )}
    >
      <span className={cx('h-1 w-1 shrink-0 rounded-full', meta.dot)} />
      {meta.label}
    </span>
  );
}

export function ConfidenceMeter({ value }: { value: number }) {
  const tone: Tone = severityTone(value >= 0.9 ? 'low' : value >= 0.75 ? 'medium' : 'high');
  return (
    <span className="inline-flex items-center gap-2">
      <span className="relative h-1 w-12 overflow-hidden rounded-full bg-slate-800">
        <span
          className={cx('absolute inset-y-0 left-0 rounded-full', tone.bar)}
          style={{ width: `${Math.round(value * 100)}%` }}
        />
      </span>
      <span className="tnum font-mono text-2xs text-slate-400">{value.toFixed(2)}</span>
    </span>
  );
}

export function Stat({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  tone?: string;
}) {
  return (
    <div className="min-w-0 px-4 py-3.5">
      <Micro className="block truncate">{label}</Micro>
      <div className={cx('tnum mt-2 font-mono text-[19px] leading-none tracking-tight', tone ?? 'text-slate-100')}>
        {value}
      </div>
      {hint ? <div className="mt-2 truncate text-2xs text-slate-500">{hint}</div> : null}
    </div>
  );
}

export function Badge({
  children,
  className,
  tone = 'neutral',
}: {
  children: ReactNode;
  className?: string;
  tone?: 'neutral' | 'positive' | 'negative' | 'accent';
}) {
  const tones = {
    neutral: 'border-hairline bg-ink-800/40 text-slate-400',
    positive: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-300',
    negative: 'border-rose-500/30 bg-rose-500/10 text-rose-300',
    accent: 'border-jade-500/35 bg-jade-500/10 text-jade-300',
  } as const;
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-2xs font-medium whitespace-nowrap',
        tones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={cx('font-mono', className)}>{children}</span>;
}

export function PageHeader({
  title,
  meta,
  right,
}: {
  title: ReactNode;
  meta?: ReactNode;
  right?: ReactNode;
}) {
  return (
    <header className="shared-page-heading flex flex-wrap items-center gap-x-4 gap-y-3">
      <div className="min-w-0 flex-1">
        <h1 className="flex items-center gap-2">{title}</h1>
        {meta ? <div className="mt-1 font-mono text-2xs text-slate-500">{meta}</div> : null}
      </div>
      {right ? <div className="flex min-w-0 flex-wrap items-center gap-2">{right}</div> : null}
    </header>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
  className,
  compact,
}: {
  icon?: ReactNode;
  title?: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  className?: string;
  compact?: boolean;
}) {
  return (
    <section className={cx('empty-state', compact && 'compact', className)}>
      {icon ? <div className="empty-state-icon">{icon}</div> : null}
      {title ? <h2 className="section-title">{title}</h2> : null}
      {description ? <p className="mx-auto mt-3 max-w-md leading-relaxed">{description}</p> : null}
      {action ? <div className="empty-state-action">{action}</div> : null}
    </section>
  );
}

export function DonutChart({
  segments,
  size = 128,
  thickness = 11,
  duration = 800,
}: {
  segments: { value: number; color: string }[];
  size?: number;
  thickness?: number;
  duration?: number;
}) {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      setProgress(1 - Math.pow(1 - t, 4));
      if (t < 1) raf = window.requestAnimationFrame(tick);
    };
    raf = window.requestAnimationFrame(tick);
    return () => window.cancelAnimationFrame(raf);
  }, [duration]);

  const total = segments.reduce((sum, s) => sum + s.value, 0);
  const r = (size - thickness) / 2;
  const C = 2 * Math.PI * r;
  let acc = 0;

  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${size} ${size}`}
      className="shrink-0 drop-shadow-[0_0_14px_rgba(52,211,153,0.12)]"
    >
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        fill="none"
        stroke="rgba(110,231,183,0.07)"
        strokeWidth={thickness}
      />
      {total > 0 && progress > 0
        ? segments
            .filter((s) => s.value > 0)
            .map((s, i) => {
              const frac = s.value / total;
              const dash = Math.max(frac * C * progress - 2, progress > 0.02 ? 1.5 : 0);
              const rot = acc * 360;
              acc += frac;
              return (
                <circle
                  key={i}
                  cx={size / 2}
                  cy={size / 2}
                  r={r}
                  fill="none"
                  stroke={s.color}
                  strokeWidth={thickness}
                  strokeDasharray={`${dash} ${C}`}
                  strokeLinecap="round"
                  transform={`rotate(${rot - 90} ${size / 2} ${size / 2})`}
                  style={{ opacity: Math.min(1, progress * 1.4) }}
                />
              );
            })
        : null}
    </svg>
  );
}

export function BarRow({
  rank,
  label,
  sub,
  value,
  max,
}: {
  rank: number;
  label: ReactNode;
  sub?: ReactNode;
  value: ReactNode;
  max: number;
}) {
  const numeric = typeof value === 'number' ? value : Number(value);
  const animated = useCountUp(numeric, 650, rank * 70);
  const width = max > 0 ? `${(animated / max) * 100}%` : '0%';
  return (
    <li className="flex items-center gap-3 px-4 py-2.5">
      <span className="w-6 shrink-0 font-mono text-2xs text-slate-600">
        {String(rank).padStart(2, '0')}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-3">
          <span className="min-w-0 truncate font-mono text-[12px] text-slate-200">{label}</span>
          <span className="tnum shrink-0 font-mono text-2xs text-slate-400">
            {typeof value === 'number' ? n(animated) : value}
          </span>
        </div>
        {sub ? (
          <div className="mt-0.5 truncate font-mono text-2xs text-slate-600">{sub}</div>
        ) : null}
        <div className="mt-1.5 h-[5px] w-full overflow-hidden rounded-full bg-ink-800">
          <div
            className="h-full rounded-full bg-gradient-to-r from-jade-600 via-jade-500 to-jade-400 shadow-glow transition-[width] duration-500 ease-swift"
            style={{ width }}
          />
        </div>
      </div>
    </li>
  );
}
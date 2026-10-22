import type { Reachability, Severity, Verdict } from '@/data/findings';

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

/** 15 080 -> "15 080" with a non-breaking thin separator. */
export function n(value: number): string {
  return value.toLocaleString('ru-RU').replace(/\u00a0/g, '\u202f');
}

export function pct(value: number): string {
  return `${value.toFixed(2).replace('.', ',')}\u2009%`;
}

/** Fraction of `from` that was eliminated. */
export function reduction(from: number, to: number): number {
  if (from === 0) return 0;
  return (1 - to / from) * 100;
}

export interface Tone {
  label: string;
  text: string;
  bg: string;
  border: string;
  dot: string;
  bar: string;
}

const SEVERITY: Record<Severity, Tone> = {
  critical: {
    label: 'КРИТИЧ.',
    text: 'text-rose-300',
    bg: 'bg-rose-500/10',
    border: 'border-rose-500/30',
    dot: 'bg-rose-400',
    bar: 'bg-rose-500',
  },
  high: {
    label: 'ВЫСОК.',
    text: 'text-orange-300',
    bg: 'bg-orange-500/10',
    border: 'border-orange-500/30',
    dot: 'bg-orange-400',
    bar: 'bg-orange-500',
  },
  medium: {
    label: 'СРЕДН.',
    text: 'text-amber-300',
    bg: 'bg-amber-500/10',
    border: 'border-amber-500/25',
    dot: 'bg-amber-400',
    bar: 'bg-amber-500',
  },
  low: {
    label: 'НИЗК.',
    text: 'text-sky-300',
    bg: 'bg-sky-500/10',
    border: 'border-sky-500/25',
    dot: 'bg-sky-400',
    bar: 'bg-sky-500',
  },
  unknown: {
    label: 'НЕИЗВ.',
    text: 'text-slate-400',
    bg: 'bg-slate-500/5',
    border: 'border-slate-700',
    dot: 'bg-slate-600',
    bar: 'bg-slate-600',
  },
};

export function severityTone(severity: Severity): Tone {
  return SEVERITY[severity] ?? SEVERITY.unknown;
}

export function reachabilityMeta(value: Reachability): {
  label: string;
  text: string;
  bg: string;
  border: string;
  dot: string;
} {
  switch (value) {
    case 'reachable':
      return {
        label: 'ДОСТИЖИМА',
        text: 'text-amber-200',
        bg: 'bg-amber-400/10',
        border: 'border-amber-400/30',
        dot: 'bg-amber-300',
      };
    case 'unreachable':
      return {
        label: 'НЕДОСТИЖИМА',
        text: 'text-slate-400',
        bg: 'bg-slate-500/5',
        border: 'border-slate-700',
        dot: 'bg-slate-600',
      };
    case 'suppressed':
      return {
        label: 'ПОДАВЛЕНА',
        text: 'text-slate-500',
        bg: 'bg-slate-500/5',
        border: 'border-slate-800 border-dashed',
        dot: 'bg-slate-700',
      };
    default:
      return {
        label: 'НЕТ ДАННЫХ',
        text: 'text-slate-400',
        bg: 'bg-slate-500/5',
        border: 'border-slate-700 border-dashed',
        dot: 'bg-slate-600',
      };
  }
}

export function verdictMeta(value: Verdict): {
  label: string;
  text: string;
  bg: string;
  border: string;
  dot: string;
} {
  switch (value) {
    case 'affected':
      return {
        label: 'Затронута',
        text: 'text-rose-200',
        bg: 'bg-rose-500/12',
        border: 'border-rose-500/40',
        dot: 'bg-rose-400',
      };
    case 'not_affected':
      return {
        label: 'Не затронута',
        text: 'text-emerald-300',
        bg: 'bg-emerald-500/8',
        border: 'border-emerald-500/25',
        dot: 'bg-emerald-400',
      };
    case 'needs_review':
      return {
        label: 'Нужна проверка',
        text: 'text-amber-200',
        bg: 'bg-amber-400/10',
        border: 'border-amber-400/30',
        dot: 'bg-amber-300',
      };
    default:
      return {
        label: 'Нужна проверка',
        text: 'text-amber-200',
        bg: 'bg-amber-400/10',
        border: 'border-amber-400/30',
        dot: 'bg-amber-300',
      };
  }
}

export function confidenceTone(value: number): string {
  if (value >= 0.9) return 'text-emerald-300';
  if (value >= 0.75) return 'text-amber-300';
  return 'text-slate-400';
}

/**
 * Funnel widths are drawn on a log10 scale: a linear scale would collapse the
 * 13 and 2 stages into invisible slivers and destroy the shape of the funnel.
 */
export function funnelWidth(value: number, max: number): number {
  const lo = Math.log10(Math.max(value, 1));
  const hi = Math.log10(Math.max(max, 2));
  const ratio = hi === 0 ? 1 : lo / hi;
  return Math.max(0.14, Math.min(1, ratio));
}

export function copyToClipboard(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    try {
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      el.remove();
      resolve();
    } catch (err) {
      reject(err);
    }
  });
}

export function downloadFile(name: string, content: string, mime = 'application/json'): void {
  const blob = new Blob([content], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = name;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1500);
}
import { useCallback, useEffect, useState, type ComponentProps } from 'react';
import { getAdvisories, type Advisory } from '@/lib/api';
import { cx } from '@/lib/format';
import { Badge, EmptyState, Micro, PageHeader, Panel } from '@/components/primitives';
import { IconShield } from '@/components/icons';

const badgeTone: Record<string, NonNullable<ComponentProps<typeof Badge>['tone']>> = {
  critical: 'negative',
  high: 'negative',
  medium: 'accent',
  low: 'neutral',
  none: 'neutral',
};

const FILTERS = ['all', 'critical', 'high', 'medium', 'low', 'affected'] as const;

export function AdvisoryPage() {
  const [advisories, setAdvisories] = useState<Advisory[]>([]);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>('all');
  const [expanded, setExpanded] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setAdvisories(await getAdvisories());
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Не удалось загрузить базу уязвимостей');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const rows = advisories.filter((a) => {
    if (filter === 'all') return true;
    if (filter === 'affected') return a.affected > 0;
    return a.severity === filter;
  });

  const counts = (key: (typeof FILTERS)[number]) =>
    key === 'all'
      ? advisories.length
      : key === 'affected'
        ? advisories.filter((a) => a.affected > 0).length
        : advisories.filter((a) => a.severity === key).length;

  return (
    <div className="advisory-workspace space-y-3">
      <PageHeader
        title="База уязвимостей"
        meta={`${advisories.length} записей по локальным данным сканов`}
        right={
          <div className="flex flex-wrap items-center gap-1.5">
            {FILTERS.map((f) => (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                className={cx(
                  'rounded-full border px-2.5 py-1 font-mono text-2xs transition-colors',
                  filter === f
                    ? 'border-jade-400/40 bg-jade-500/10 text-jade-200'
                    : 'border-hairline text-slate-400 hover:text-slate-200',
                )}
              >
                {f} <span className="tnum opacity-70">{counts(f)}</span>
              </button>
            ))}
          </div>
        }
      />

      {error ? <p className="panel px-4 py-2.5 font-mono text-2xs text-rose-300">{error}</p> : null}

      <Panel>
        {loading ? (
          <p className="p-6 text-center text-2xs text-slate-500">загрузка…</p>
        ) : rows.length === 0 ? (
          <EmptyState compact icon={<IconShield className="h-5 w-5" />} title="Нет записей" description="База уязвимостей пуста или запрос не дал совпадений." />
        ) : (
          <ul className="divide-y divide-hairline">
            {rows.map((a) => {
              const key = `${a.cve}::${a.packageName}`;
              const open = expanded === key;
              return (
                <li key={key} className="px-4 py-3">
                  <button
                    type="button"
                    onClick={() => setExpanded(open ? null : key)}
                    className="flex w-full flex-wrap items-center gap-x-3 gap-y-1 text-left"
                  >
                    <span className={cx('font-mono text-2xs', open ? 'text-jade-300' : 'text-slate-600')}>
                      {open ? '−' : '+'}
                    </span>
                    <span className="font-mono text-[12px] text-rose-200">{a.cve}</span>
                    <Badge tone={badgeTone[a.severity] ?? 'neutral'}>{a.severity}</Badge>
                    <span className="truncate font-mono text-2xs text-slate-300">{a.packageName}</span>
                    <span className="font-mono text-2xs text-slate-500">
                      {a.versions.length ? a.versions.join(', ') : '—'}
                    </span>
                    <span className="ml-auto font-mono text-2xs text-slate-500">
                      {a.affected > 0 ? (
                        <span className="text-rose-300">{a.affected} × affected</span>
                      ) : (
                        'нет affected'
                      )}{' '}
                      · охват {a.scanCount} скан.
                    </span>
                  </button>

                  {open ? (
                    <div className="mt-2 space-y-2 border-l border-hairline pl-3">
                      <ul className="space-y-1">
                        {a.observed.map((o) => (
                          <li
                            key={`${o.scanId}:${o.version}`}
                            className="flex flex-wrap items-center gap-x-3 font-mono text-2xs text-slate-400"
                          >
                            <span className="truncate text-slate-300">
                              {o.repository}@{o.commit}
                            </span>
                            <span className="text-slate-500">{o.version}</span>
                            <span className={o.verdict === 'affected' ? 'text-rose-300' : 'text-slate-500'}>
                              {o.verdict}
                            </span>
                            <span className="text-slate-600">{o.reachability}</span>
                          </li>
                        ))}
                      </ul>
                      {a.fixedIn.length ? (
                        <p className="font-mono text-2xs text-jade-300">fixed: {a.fixedIn.join(', ')}</p>
                      ) : null}
                      <p className="text-2xs leading-relaxed text-slate-500">{a.recommendation}</p>
                      <p className="font-mono text-2xs text-slate-700">
                        наблюдается {a.scannedFrom} → {a.scannedTo}
                      </p>
                    </div>
                  ) : null}
                </li>
              );
            })}
          </ul>
        )}
      </Panel>
    </div>
  );
}
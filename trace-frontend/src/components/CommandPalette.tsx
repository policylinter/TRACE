import {NAV_ITEMS as WORKSPACE_NAV,KEYBOARD_NAV} from '@/data/nav';
import { useDialogFocus } from '@/hooks/useDialogFocus';
import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { cx, severityTone } from '@/lib/format';
import { useTrace, type NavId } from '@/state/TraceProvider';
import { FILTERS, SORTS } from '@/components/TriageTable';
import {
  IconCheck,
  IconDoc,
  IconGraph,
  IconGrid,
  IconLayers,
  IconList,
  IconSearch,
  IconShield,
  IconSparkle,
  IconTarget,
} from '@/components/icons';

interface PaletteProps {
  open: boolean;
  onClose: () => void;
  onExport: () => void;
  onOpenHelp: () => void;
}

interface PaletteItem {
  id: string;
  group: string;
  label: ReactNode;
  keywords: string;
  icon: ReactNode;
  hint?: string;
  run: () => void;
  active?: boolean;
}

const SEVERITY_SORT: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

const navIcons = {grid:IconGrid,layers:IconLayers,graph:IconGraph,doc:IconDoc,list:IconList,shield:IconShield,cpu:IconSparkle};
const NAV_ITEMS = [...WORKSPACE_NAV,{id:'reachability' as NavId,label:'Анализ достижимости',glyph:'graph' as const}].map(item=>{
 const Icon=navIcons[item.glyph];const index=KEYBOARD_NAV.indexOf(item.id);
 return {id:item.id,label:item.label,hint:index<0?'':String(index+1),icon:<Icon className="h-3.5 w-3.5"/>,keys:item.id+' '+item.label.toLowerCase()};
});

export function CommandPalette({ open, onClose, onExport, onOpenHelp }: PaletteProps) {
  const dialogRef = useDialogFocus<HTMLDivElement>(open, onClose);
  const t = useTrace();
  const inputRef = useRef<HTMLInputElement>(null);
  const rowRefs = useRef<(HTMLLIElement | null)[]>([]);
  const [term, setTerm] = useState('');
  const [index, setIndex] = useState(0);

  useEffect(() => {
    if (!open) return;
    setTerm('');
    setIndex(0);
    const raf = window.requestAnimationFrame(() => inputRef.current?.focus());
    return () => window.cancelAnimationFrame(raf);
  }, [open]);

  const items = useMemo<PaletteItem[]>(() => {
    const list: PaletteItem[] = [];

    for (const item of NAV_ITEMS) {
      list.push({
        id: `nav:${item.id}`,
        group: 'Переход',
        label: (
          <>
            {item.label}
            <span className="ml-1.5 text-slate-600">{item.hint}</span>
          </>
        ),
        keywords: item.keys,
        icon: item.icon,
        run: () => t.navigate(item.id),
        active: t.nav === item.id,
      });
    }

    for (const filter of FILTERS) {
      list.push({
        id: `filter:${filter.key}`,
        group: 'Фильтры триажа',
        label: filter.label,
        keywords: `фильтр ${filter.label} ${filter.key}`,
        icon: <IconTarget className="h-3.5 w-3.5" />,
        run: () => {
          t.setFilter(filter.key);
          t.navigate('findings');
          t.setQuery('');
        },
        active: t.nav === 'findings' && t.filter === filter.key,
      });
    }

    for (const sort of SORTS) {
      list.push({
        id: `sort:${sort.key}`,
        group: 'Сортировка',
        label: sort.label,
        keywords: `сортировка ${sort.label} ${sort.key}`,
        icon: <IconList className="h-3.5 w-3.5" />,
        run: () => {
          t.setSort(sort.key);
          t.navigate('findings');
        },
        active: t.nav === 'findings' && t.sort === sort.key,
      });
    }

    list.push({
      id: 'reset',
      group: 'Действия',
      label: 'Сбросить фильтры и поиск',
      keywords: 'сброс reset очистить поиск фильтры',
      icon: <IconSparkle className="h-3.5 w-3.5" />,
      run: () => {
        t.setQuery('');
        t.setFilter('all');
      },
    });

    if (t.scan && (!t.auth?.enabled || t.user?.role !== 'viewer')) {
      list.push({
        id: 'rescan',
        group: 'Действия',
        label: `Пересканировать: ${t.scan.repository}`,
        keywords: 'пересканировать rescan перезапустить анализ',
        icon: <IconTarget className="h-3.5 w-3.5" />,
        run: () => void t.rerun(),
      });
    }

    list.push({
      id: 'export',
      group: 'Действия',
      label: 'Скачать отчёт (Markdown)',
      keywords: 'отчёт отчет экспорт скачать download report markdown',
      icon: <IconDoc className="h-3.5 w-3.5" />,
      run: () => onExport(),
    });

    list.push({
      id: 'help',
      group: 'Действия',
      label: 'Горячие клавиши',
      keywords: 'помощь справка хоткеи горячие клавиши help hotkeys ?',
      icon: <IconList className="h-3.5 w-3.5" />,
      hint: '?',
      run: () => onOpenHelp(),
    });

    for (const item of t.scans) {
      if (item.id === t.activeScanId) continue;
      list.push({
        id: `scan:${item.id}`,
        group: 'Сканы',
        label: `Открыть: ${item.repository}@${item.commit}`,
        keywords: `скан переключить ${item.repository} ${item.commit} ${item.branch}`.toLowerCase(),
        icon: <IconGrid className="h-3.5 w-3.5" />,
        run: () => t.setActiveScan(item.id),
      });
    }

    if (term.trim()) {
      list.push({
        id: 'search-term',
        group: 'Поиск',
        label: `Искать «${term.trim()}» в триаже`,
        keywords: term.trim().toLowerCase(),
        icon: <IconSearch className="h-3.5 w-3.5" />,
        run: () => {
          t.navigate('findings');
          t.setQuery(term.trim());
        },
      });
    }

    if (t.findings.length > 0) {
      const ranked = [...t.findings]
        .sort(
          (a, b) => SEVERITY_SORT[a.severity] - SEVERITY_SORT[b.severity] || b.cvss - a.cvss,
        )
        .slice(0, 24);
      for (const finding of ranked) {
        list.push({
          id: `f:${finding.id}`,
          group: 'Находки',
          label: (
            <>
              <span className="truncate">{finding.cve}</span>
              <span className="ml-2 shrink-0 text-slate-600">
                {finding.packageName}@{finding.version}
              </span>
            </>
          ),
          keywords: `${finding.cve} ${finding.packageName} ${finding.ecosystem} ${finding.id} ${finding.cwe.join(' ')}`.toLowerCase(),
          icon: <span className={cx('h-1.5 w-1.5 rounded-full', severityTone(finding.severity).dot)} />,
          run: () => {
            t.select(finding.id);
            t.navigate('findings');
          },
        });
      }
    }

    return list;
  }, [term, t, onExport, onOpenHelp]);

  const filtered = useMemo(() => {
    const q = term.trim().toLowerCase();
    return q ? items.filter((item) => item.keywords.includes(q)) : items;
  }, [items, term]);

  useEffect(() => setIndex(0), [term, filtered.length]);

  useEffect(() => {
    rowRefs.current[index]?.scrollIntoView({ block: 'nearest' });
  }, [index]);

  const run = (at: number) => {
    const item = filtered[at];
    if (!item) return;
    item.run();
    onClose();
  };

  const onKeyDown = (event: ReactKeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault();
      setIndex((i) => Math.min(filtered.length - 1, i + 1));
    } else if (event.key === 'ArrowUp') {
      event.preventDefault();
      setIndex((i) => Math.max(0, i - 1));
    } else if (event.key === 'Enter') {
      event.preventDefault();
      run(index);
    } else if (event.key === 'Escape') {
      event.preventDefault();
      onClose();
    }
  };

  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-[400]">
      <div
        className="theme-backdrop absolute inset-0 animate-fade-rise bg-ink-950/60 backdrop-blur-[2px]"
        onClick={onClose}
      />
      <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label="Команды TRACE" className="absolute left-1/2 top-[15vh] w-[min(560px,calc(100vw-28px))] -translate-x-1/2">
        <div className="overflow-hidden rounded-xl border border-hairline-strong bg-ink-900/95 shadow-float backdrop-blur-2xl ring-1 ring-black/60">
          <div className="flex items-center gap-2.5 border-b border-hairline px-3.5">
            <IconSearch className="h-4 w-4 shrink-0 text-jade-300" />
            <input
              ref={inputRef}
              value={term}
              onChange={(event) => setTerm(event.target.value)}
              onKeyDown={onKeyDown}
              placeholder="Команды и поиск находок…"
              spellCheck={false}
              autoComplete="off"
              className="h-11 w-full bg-transparent font-mono text-[13px] text-slate-100 placeholder:text-slate-600 focus:outline-none"
            />
            <kbd className="shrink-0 rounded border border-hairline bg-ink-800/60 px-1 font-mono text-[9px] text-slate-500">
              esc
            </kbd>
          </div>

          <div className="max-h-[340px] overflow-y-auto py-1">
            {filtered.length === 0 ? (
              <p className="px-4 py-8 text-center font-mono text-2xs text-slate-600">
                ничего не найдено по «{term}»
              </p>
            ) : (
              <ul>
                {filtered.map((item, i) => (
                  <li
                    key={item.id}
                    ref={(el) => {
                      rowRefs.current[i] = el;
                    }}
                    onMouseDown={(event) => {
                      event.preventDefault();
                      run(i);
                    }}
                    onMouseEnter={() => setIndex(i)}
                    className={cx(
                      'flex cursor-pointer items-center gap-2.5 px-3.5 py-2',
                      index === i ? 'bg-jade-500/10' : '',
                    )}
                  >
                    <span
                      className={cx(
                        'flex h-4 w-4 shrink-0 items-center justify-center',
                        index === i ? 'text-jade-300' : 'text-slate-600',
                      )}
                    >
                      {item.icon}
                    </span>
                    <span className="flex min-w-0 flex-1 items-baseline font-mono text-[12px] text-slate-200">
                      {item.label}
                    </span>
                    {item.active ? (
                      <IconCheck className="h-3 w-3 shrink-0 text-jade-300" />
                    ) : null}
                    {item.hint ? (
                      <kbd className="shrink-0 rounded border border-hairline bg-ink-800/60 px-1 font-mono text-[9px] text-slate-500">
                        {item.hint}
                      </kbd>
                    ) : null}
                  </li>
                ))}
              </ul>
            )}
          </div>

          <div className="flex items-center gap-3 border-t border-hairline px-3 py-1.5 font-mono text-2xs text-slate-600">
            <span>↑↓ навигация</span>
            <span className="text-slate-700">·</span>
            <span>enter — выполнить</span>
            <span className="ml-auto">{filtered.length} команд</span>
          </div>
        </div>
      </div>
    </div>,
    document.body,
  );
}

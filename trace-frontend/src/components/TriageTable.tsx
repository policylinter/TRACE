import { useEffect, useState, type RefObject } from 'react';
import type { Finding, Severity } from '@/data/findings';
import type { BatchAction } from '@/lib/api';
import { cx, n, severityTone } from '@/lib/format';
import { Micro, ReachabilityChip, SeverityBadge, VerdictChip, EmptyState } from './primitives';
import { IconCheck, IconChevronRight, IconSearch, IconList } from './icons';

export type FilterKey = 'all' | 'needs_review' | 'actionable' | 'reachable' | 'unreachable' | 'suppressed' | 'unassigned' | 'in_progress' | 'overdue';

export type SortKey = 'severity' | 'confidence' | 'raw' | 'cve';

export const FILTERS: { key: FilterKey; label: string }[] = [
  { key: 'all', label: 'Все' },
  { key: 'needs_review', label: 'Ожидают проверки' },
  { key: 'unassigned', label: 'Без ответственного' },
  { key: 'in_progress', label: 'В работе' },
  { key: 'overdue', label: 'Просрочены' },
  { key: 'actionable', label: 'Достижимые · затронуты' },
  { key: 'reachable', label: 'Достижимые' },
  { key: 'unreachable', label: 'Недостижимые' },
  { key: 'suppressed', label: 'Подавленные' },
];

export const SORTS: { key: SortKey; label: string }[] = [
  { key: 'severity', label: 'Критичность' },
  { key: 'confidence', label: 'Уверенность ИИ' },
  { key: 'raw', label: 'Сырые записи' },
  { key: 'cve', label: 'CVE' },
];

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

export function sortFindings(list: Finding[], sort: SortKey): Finding[] {
  const copy = [...list];
  switch (sort) {
    case 'severity':
      return copy.sort((a, b) => {
        const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
        return bySeverity !== 0 ? bySeverity : b.cvss - a.cvss;
      });
    case 'confidence':
      return copy.sort((a, b) => b.confidence - a.confidence);
    case 'raw':
      return copy.sort((a, b) => b.rawCount - a.rawCount);
    case 'cve':
      return copy.sort((a, b) => a.cve.localeCompare(b.cve));
  }
}

export function filterFindings(list: Finding[], filter: FilterKey): Finding[] {
  switch (filter) {
    case 'all':
      return list;
    case 'needs_review':
      return list.filter(f => !f.reviewed && f.reachability !== 'suppressed');
    case 'unassigned':
      return list.filter(f => !f.assignee && f.workflowStatus !== 'resolved');
    case 'in_progress':
      return list.filter(f => f.workflowStatus === 'in_progress');
    case 'overdue': {
      const now = new Date();
      const today = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,'0')}-${String(now.getDate()).padStart(2,'0')}`;
      return list.filter(f => f.dueDate && f.dueDate < today && f.workflowStatus !== 'resolved');
    }
    case 'actionable':
      return list.filter((f) => f.reachability === 'reachable' && f.verdict === 'affected');
    case 'reachable':
      return list.filter((f) => f.reachability === 'reachable');
    case 'unreachable':
      return list.filter((f) => f.reachability === 'unreachable');
    case 'suppressed':
      return list.filter((f) => f.reachability === 'suppressed');
  }
}

interface TriageTableProps {
  readOnly?: boolean;
  findings: Finding[];
  total: number;
  selectedId: string | null;
  onSelect: (finding: Finding) => void;
  query: string;
  onQueryChange: (value: string) => void;
  filter: FilterKey;
  onFilterChange: (value: FilterKey) => void;
  sort: SortKey;
  onSortChange: (value: SortKey) => void;
  searchRef: RefObject<HTMLInputElement>;
  onBatch: (ids: string[], action: BatchAction, reason?: string) => Promise<void>;
}

function Checkbox({
  checked,
  indeterminate,
  onToggle,
}: {
  checked: boolean;
  indeterminate?: boolean;
  onToggle: () => void;
}) {
  return (
    <span
      role="checkbox"
      aria-label="Выбрать находку"
      aria-checked={indeterminate ? 'mixed' : checked}
      tabIndex={0}
      onClick={(event) => {
        event.stopPropagation();
        event.preventDefault();
        onToggle();
      }}
      onKeyDown={(event) => {
        if (event.key === ' ' || event.key === 'Enter') {
          event.stopPropagation();
          event.preventDefault();
          onToggle();
        }
      }}
      className={cx(
        'flex h-4 w-4 shrink-0 cursor-pointer items-center justify-center rounded-[3px] border transition-colors duration-150 focus:outline-none focus-visible:ring-1 focus-visible:ring-jade-400',
        indeterminate
          ? 'border-jade-400/70 bg-jade-500/30 text-jade-200'
          : checked
            ? 'border-jade-400/70 bg-jade-500/30 text-jade-200'
            : 'border-hairline-strong bg-ink-900 text-transparent hover:border-slate-500',
      )}
    >
      {indeterminate ? (
        <span className="h-[2px] w-[9px] rounded-full bg-jade-200" />
      ) : checked ? (
        <IconCheck className="h-3 w-3" />
      ) : null}
    </span>
  );
}

export function TriageTable({
  readOnly = false,
  findings,
  total,
  selectedId,
  onSelect,
  query,
  onQueryChange,
  filter,
  onFilterChange,
  sort,
  onSortChange,
  searchRef,
  onBatch,
}: TriageTableProps) {
  const [advanced, setAdvanced] = useState(false);
  const [comfortable, setComfortable] = useState(()=>{try{return localStorage.getItem('trace.table.comfortable')==='true';}catch{return false;}});
  const [hiddenColumns,setHiddenColumns]=useState<string[]>(()=>{try{const value=JSON.parse(localStorage.getItem('trace.table.hidden')||'[]');return Array.isArray(value)?value.filter((x:unknown)=>typeof x==='string'&&['reach','verdict','workflow','owner'].includes(x)):[];}catch{return [];}});
  useEffect(()=>{try{localStorage.setItem('trace.table.comfortable',String(comfortable));localStorage.setItem('trace.table.hidden',JSON.stringify(hiddenColumns));}catch{/* Storage is optional. */}},[comfortable,hiddenColumns]);
  const rawSum = findings.reduce((acc, f) => acc + f.rawCount, 0);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [suppressIds, setSuppressIds] = useState<string[] | null>(null);
  const [suppressReason, setSuppressReason] = useState('');
  const [pending, setPending] = useState(false);
  const [batchError, setBatchError] = useState('');

  // Drop selections that no longer match the current filter/query.
  useEffect(() => {
    const known = new Set(findings.map((f) => f.id));
    setSelected((prev) => {
      let changed = false;
      const next = new Set<string>();
      prev.forEach((id) => {
        if (known.has(id)) next.add(id);
        else changed = true;
      });
      return changed ? next : prev;
    });
  }, [findings]);

  const visibleIds = findings.map((f) => f.id);
  const allSelected = visibleIds.length > 0 && visibleIds.every((id) => selected.has(id));
  const someSelected = visibleIds.some((id) => selected.has(id));

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (allSelected) visibleIds.forEach((id) => next.delete(id));
      else visibleIds.forEach((id) => next.add(id));
      return next;
    });
  };

  const runBatch = async (action: BatchAction, ids = [...selected], reason?: string) => {
    if (ids.length === 0 || pending) return;
    setPending(true); setBatchError('');
    try { await onBatch(ids, action, reason); setSelected(new Set()); setSuppressIds(null); setSuppressReason(''); }
    catch (error) { setBatchError(error instanceof Error ? error.message : 'Не удалось обновить находки. Повторите действие.'); }
    finally { setPending(false); }
  };

  const beginSuppress = () => {
    if (selected.size === 0) return;
    setSuppressIds([...selected]);
    setSuppressReason('');
  };

  const confirmSuppress = () => {
    if (!suppressIds || suppressIds.length === 0) return;
    void runBatch('suppress', suppressIds, suppressReason.trim());
  };

  const cancelSuppress = () => {
    setSuppressIds(null);
    setSuppressReason('');
  };

  return (
    <section className="triage-workspace panel flex min-h-0 flex-col overflow-hidden">
      <header className="flex flex-wrap items-center gap-2 border-b border-hairline px-3 py-3 sm:px-4">
        <div className="flex min-w-0 items-center gap-2">
          <h2 className="micro-strong">Очередь триажа</h2>
          <span className="tnum rounded border border-hairline bg-ink-800/50 px-1.5 py-0.5 font-mono text-2xs text-slate-400">
            {n(findings.length)} / {n(total)}
          </span>
        </div>

        <div className="ml-auto flex min-w-0 flex-wrap items-center gap-2">
          <div className="relative">
            <IconSearch className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
            <input
              aria-label="Поиск находок"
              ref={searchRef}
              value={query}
              onChange={(e) => onQueryChange(e.target.value)}
              placeholder="CVE, пакет, символ…"
              spellCheck={false}
              autoComplete="off"
              className="h-7 w-[184px] rounded-md border border-hairline bg-ink-950/60 pl-7 pr-6 font-mono text-2xs text-slate-200 placeholder:text-slate-600 focus:border-jade-500/60 focus:outline-none"
            />
            {query ? (
              <button
                type="button"
                aria-label="Очистить поиск"
                onClick={() => onQueryChange('')}
                className="absolute right-1.5 top-1/2 -translate-y-1/2 font-mono text-2xs text-slate-600 hover:text-slate-300"
              >
                ✕
              </button>
            ) : null}
          </div>

          <div className="triage-filters flex flex-wrap items-center gap-0.5 rounded-md border border-hairline bg-ink-950/60 p-0.5">
            {FILTERS.filter(item => advanced || ['all', 'needs_review', 'actionable', filter].includes(item.key)).map((item) => (
              <button
                key={item.key}
                type="button"
                aria-pressed={filter === item.key}
                onClick={() => onFilterChange(item.key)}
                className={cx(
                  'rounded px-1.5 py-1 text-2xs font-medium transition-colors duration-150',
                  filter === item.key
                    ? 'bg-ink-750 text-slate-100 shadow-inset'
                    : 'text-slate-500 hover:text-slate-300',
                )}
              >
                {item.label}
              </button>
            ))}
          </div>

          <button className="btn" aria-expanded={advanced} onClick={() => setAdvanced(v => !v)}>{advanced ? 'Меньше фильтров' : 'Все фильтры'}</button>
          <details className="column-picker"><summary>Столбцы</summary><div>{[{id:'reach',label:'Достижимость'},{id:'verdict',label:'Вердикт анализа'},{id:'workflow',label:'Статус работы'},{id:'owner',label:'Исполнитель'}].map(column=><label key={column.id}><input type="checkbox" checked={!hiddenColumns.includes(column.id)} onChange={()=>setHiddenColumns(current=>current.includes(column.id)?current.filter(id=>id!==column.id):[...current,column.id])}/>{column.label}</label>)}</div></details>
          <button className="btn" aria-pressed={comfortable} onClick={() => setComfortable(v => !v)}>{comfortable ? 'Свободные строки' : 'Компактные строки'}</button>
          <div className="flex items-center gap-1.5">
            <Micro className="hidden sm:inline">Сорт</Micro>
            <select
              aria-label="Сортировка находок"
              value={sort}
              onChange={(e) => onSortChange(e.target.value as SortKey)}
              className="h-7 rounded-md border border-hairline bg-ink-950/60 px-1.5 text-2xs text-slate-300 focus:border-jade-500/60 focus:outline-none"
            >
              {SORTS.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.label}
                </option>
              ))}
            </select>
          </div>
        </div>
      </header>

      {(query || filter !== 'all' || sort !== 'severity') && <div className="triage-reset"><span>{FILTERS.find(item => item.key === filter)?.label}{query && ` · «${query}»`} · Найдено {n(findings.length)} из {n(total)}</span><button className="btn" onClick={() => { onQueryChange(''); onFilterChange('all'); onSortChange('severity'); }}>Сбросить поиск и фильтры</button></div>}
      {batchError && <p role="alert" className="wb-error mx-4 my-3">{batchError}</p>}
      {selected.size > 0 ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-hairline bg-jade-500/[0.06] px-3 py-2 sm:px-4">
          <span className="font-mono text-2xs text-jade-200">Выбрано {n(selected.size)}{pending ? ' · Сохранение…' : ''}</span>
          <span className="hidden h-3.5 w-px bg-hairline-strong sm:block" />
          <button
            type="button"
            disabled={pending || readOnly} onClick={() => void runBatch('review')}
            className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-1 text-2xs font-medium text-emerald-200 transition-colors duration-150 hover:bg-emerald-500/20"
          >
            Пометить проверенными
          </button>
          <button
            type="button"
            disabled={pending || readOnly} onClick={beginSuppress}
            className="rounded border border-slate-600/40 bg-ink-800/60 px-2 py-1 text-2xs font-medium text-slate-300 transition-colors duration-150 hover:bg-ink-750"
          >
            Подавить
          </button>
          <button
            type="button"
            disabled={pending || readOnly} onClick={() => void runBatch('unsuppress')}
            className="rounded border border-slate-600/40 bg-ink-800/60 px-2 py-1 text-2xs font-medium text-slate-300 transition-colors duration-150 hover:bg-ink-750"
          >
            Снять подавление
          </button>
          <button
            type="button"
            onClick={() => setSelected(new Set())}
            className="ml-auto font-mono text-2xs text-slate-500 transition-colors duration-150 hover:text-slate-300"
          >
            сбросить выбор
          </button>
        </div>
      ) : null}

      {suppressIds ? (
        <div className="flex flex-wrap items-center gap-2 border-b border-hairline bg-amber-500/[0.06] px-3 py-2 sm:px-4">
          <label htmlFor="batch-suppress-reason" className="micro text-slate-400">
            Причина подавления ({n(suppressIds.length)})
          </label>
          <input
            id="batch-suppress-reason"
            value={suppressReason}
            onChange={(e) => setSuppressReason(e.target.value)}
            placeholder="например: зависимость не используется, монорепозиторий, backport…"
            spellCheck={false}
            autoFocus
            className="h-7 min-w-[280px] flex-1 rounded-md border border-hairline bg-ink-950/60 px-2.5 font-mono text-2xs text-slate-200 placeholder:text-slate-600 focus:border-jade-500/60 focus:outline-none"
          />
          <button
            type="button"
            onClick={confirmSuppress}
            disabled={pending || readOnly || !suppressReason.trim()}
            className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-2xs font-medium text-amber-200 transition-colors duration-150 hover:bg-amber-500/20 disabled:cursor-not-allowed disabled:opacity-40"
          >
            Подтвердить подавление
          </button>
          <button
            type="button"
            disabled={pending || readOnly} onClick={cancelSuppress}
            className="font-mono text-2xs text-slate-500 transition-colors duration-150 hover:text-slate-300"
          >
            отмена
          </button>
        </div>
      ) : null}

      <div className="triage-scroll" tabIndex={0} role="region" aria-label="Результаты поиска находок, таблица прокручивается по горизонтали">
        <table className={`findings-table ${comfortable ? 'comfortable' : ''} ${hiddenColumns.map(id=>'hide-'+id).join(' ')}`}>
          <caption className="sr-only">Находки выбранной проверки: {n(findings.length)} из {n(total)}</caption>
          <thead><tr><th scope="col"><input type="checkbox" aria-label="Выбрать все показанные находки" checked={allSelected} ref={node => { if (node) node.indeterminate = !allSelected && someSelected; }} onChange={toggleAll}/></th>{['Находка','Пакет и версия','Серьёзность','Достижимость','Вердикт анализа','Статус работы','Исполнитель'].map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead>
          <tbody>{findings.map(finding => <tr key={finding.id} aria-selected={selected.has(finding.id)}>
            <td><input type="checkbox" aria-label={`Выбрать ${finding.id}`} checked={selected.has(finding.id)} onChange={() => toggleOne(finding.id)}/></td>
            <th scope="row"><button className="finding-link" onClick={() => onSelect(finding)}>{finding.cve}</button><code className="finding-subline">{finding.id}</code></th>
            <td><code className="finding-package" title={finding.packageName}>{finding.packageName}</code><span className="finding-subline"><code>{finding.version}</code> · {finding.ecosystem}</span></td>
            <td><SeverityBadge severity={finding.severity} cvss={finding.cvss} unscored={!!finding.evidence.nativeObservations?.length}/></td>
            <td><ReachabilityChip value={finding.reachability}/></td>
            <td>{finding.reachability === 'suppressed' ? <span className="finding-subline">Исключена аналитиком</span> : <VerdictChip value={finding.verdict}/>}</td>
            <td>{finding.workflowStatus ? ({new:'Новая',in_progress:'В работе',resolved:'Исправлена вручную',accepted_risk:'Риск принят'}[finding.workflowStatus]) : 'Не указан'}</td>
            <td className="finding-owner">{finding.assignee || 'Не назначен'}</td>
          </tr>)}</tbody>
        </table>
        {findings.length === 0 && <EmptyState compact icon={<IconList className="h-5 w-5" />} title={total === 0 ? 'Нет находок' : 'Ничего не найдено'} description={total === 0 ? 'В отчёте нет находок. Проверьте полноту анализа.' : 'Нет результатов по текущим фильтрам.'} action={total > 0 ? <button className="btn" onClick={() => { onQueryChange(''); onFilterChange('all'); }}>Сбросить поиск и фильтры</button> : undefined} />}
      </div>

      <footer className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 border-t border-hairline px-3 py-2 sm:px-4">
        <span className="font-mono text-2xs text-slate-600">
          сгруппировано {n(rawSum)} сырых записей → {n(findings.length)} находок
        </span>
        <span className="font-mono text-2xs text-slate-600">
          идентификатор CVE — карточка · чекбокс — массовый триаж · j / k — навигация · v — VEX
        </span>
      </footer>
    </section>
  );
}
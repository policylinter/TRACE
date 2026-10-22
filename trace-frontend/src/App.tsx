import {KEYBOARD_NAV} from '@/data/nav';
import { SectionNavigation } from '@/components/SectionNavigation';
import {SecurityWorkPage} from '@/pages/SecurityWorkPage';
import {DevSecOpsPage} from '@/pages/DevSecOpsPage';
import { WorkspacesPage } from '@/pages/WorkspacesPage';
import { WorkspaceSwitcher } from '@/components/WorkspaceSwitcher';
import { getAdminToken } from '@/lib/api';
import { AccessPage } from '@/pages/AccessPage';
import { LoginPage } from '@/pages/LoginPage';
import { PlatformPage } from '@/pages/PlatformPage';
import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { Finding } from '@/data/findings';
import { filterFindings, sortFindings, TriageTable } from '@/components/TriageTable';
import { FindingDetail } from '@/pages/FindingDetail';
import { VexModal } from '@/components/VexModal';
import { TopBar } from '@/components/TopBar';
import { Sidebar, SidebarOverlay } from '@/components/Sidebar';
import { StatusBar } from '@/components/StatusBar';
import { ScansPage } from '@/pages/ScansPage';
import { ProjectsPage } from '@/pages/ProjectsPage';
import { ScanNotice } from '@/components/ScanNotice';
import { Overview } from '@/pages/Overview';
import { Reachability } from '@/pages/Reachability';
import { SbomPage } from '@/pages/SbomPage';
import { VexPage } from '@/pages/VexPage';
import { AdvisoryPage } from '@/pages/AdvisoryPage';
import { CompliancePage } from '@/pages/CompliancePage';
import { AiSettingsPage } from '@/pages/AiSettingsPage';
import { PageHeader } from '@/components/primitives';
import { CommandPalette } from '@/components/CommandPalette';
import { HotkeysHelp } from '@/components/HotkeysHelp';
import { downloadFile, n } from '@/lib/format';
import { buildReport, reportFileName } from '@/lib/report';
import { useTrace, type NavId } from '@/state/TraceProvider';

const useBrowserLayoutEffect = typeof window === 'undefined' ? useEffect : useLayoutEffect;

const NAV_ORDER: NavId[] = KEYBOARD_NAV;

function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return true;
    return window.matchMedia(query).matches;
  });

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mql = window.matchMedia(query);
    const onChange = (event: MediaQueryListEvent) => setMatches(event.matches);
    setMatches(mql.matches);
    mql.addEventListener('change', onChange);
    return () => mql.removeEventListener('change', onChange);
  }, [query]);

  return matches;
}

function matchesQuery(finding: Finding, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const haystack = [
    finding.cve,
    finding.id,
    finding.packageName,
    finding.version,
    finding.ecosystem,
    finding.verdict,
    finding.reachability,
    finding.evidence?.headline,
    ...finding.cwe,
    ...finding.frames.map((f) => f.symbol),
  ]
    .join(' ')
    .toLowerCase();
  return haystack.includes(q);
}

function Splash({ label }: { label: string }) {
  return (
    <div className="veil flex h-screen items-center justify-center bg-ink-950">
      <div className="flex flex-col items-center gap-3">
        <span className="relative flex h-8 w-8 items-center justify-center">
          <span className="absolute inset-0 animate-pulse-ring rounded-full bg-jade-500/40" />
          <span className="relative h-2.5 w-2.5 rounded-full bg-jade-400" />
        </span>
        <p className="font-mono text-2xs text-slate-500">{label}</p>
      </div>
    </div>
  );
}

export default function App() {
  const t = useTrace();
  const {
    loading,
    error,
    scan,
    findings,
    nav,
    selectedId,
    query,
    filter,
    sort,
    vexOpen,
    vexScope,
    lastDone,
    sidebarMode,
    setSidebarMode,
    busy,
    progress,
    sbom,
    batch,
  } = t;

  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    try { return localStorage.getItem('trace.theme') === 'light' ? 'light' : 'dark'; } catch { return 'dark'; }
  });
  useEffect(() => {
    document.documentElement.dataset.traceTheme = theme;
    document.documentElement.classList.toggle('dark', theme === 'dark');
    document.documentElement.style.colorScheme = theme;
  }, [theme]);
  const toggleTheme = () => setTheme(current => {
    const next = current === 'light' ? 'dark' : 'light';
    try { localStorage.setItem('trace.theme', next); } catch { /* private browsing */ }
    return next;
  });
  const searchRef = useRef<HTMLInputElement>(null);
  const pageScrollRef = useRef<HTMLDivElement>(null);
  const scrollPositions = useRef<Record<string, number>>({});
  const routeKey = `${scan?.id ?? 'none'}:${nav}:${nav === 'findings' ? selectedId ?? 'list' : ''}`;
  useBrowserLayoutEffect(() => {
    if (pageScrollRef.current) pageScrollRef.current.scrollTop = scrollPositions.current[routeKey] ?? 0;
  }, [routeKey, loading]);
  const isWide = useMediaQuery('(min-width: 1024px)');
  const isDesktop = useMediaQuery('(min-width: 768px)');
  const [sidebarOverlay, setSidebarOverlay] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [hotkeysOpen, setHotkeysOpen] = useState(false);
  useEffect(() => { setSidebarOverlay(false); setPaletteOpen(false); setHotkeysOpen(false); }, [t.user?.username]);

  const exportReport = useCallback(() => {
    if (!scan) return;
    downloadFile(reportFileName(scan), buildReport(scan, findings, sbom), 'text/markdown');
  }, [scan, findings, sbom]);

  const visible = useMemo(() => {
    const scoped = filterFindings(findings, filter);
    const searched = scoped.filter((f) => matchesQuery(f, query));
    return sortFindings(searched, sort);
  }, [findings, filter, query, sort]);

  const selected = useMemo(
    () => nav === 'findings' ? findings.find((f) => f.id === selectedId) ?? null : null,
    [findings, selectedId, nav],
  );

  const step = useCallback(
    (delta: number) => {
      if (visible.length === 0) return;
      const index = visible.findIndex((f) => f.id === selectedId);
      const nextIndex =
        index === -1 ? 0 : Math.min(visible.length - 1, Math.max(0, index + delta));
      t.select(visible[nextIndex].id);
    },
    [visible, selectedId, t],
  );

  const focusSearch = useCallback(() => {
    if (nav !== 'findings') {
      t.navigate('findings');
      window.setTimeout(() => searchRef.current?.focus(), 60);
    } else {
      searchRef.current?.focus();
    }
  }, [nav, t]);

  const handleToggleSidebar = useCallback(() => {
    if (sidebarMode === 'hidden') {
      setSidebarOverlay((open) => !open);
      return;
    }
    if (isWide) {
      setSidebarMode(sidebarMode === 'expanded' ? 'rail' : 'expanded');
    } else {
      setSidebarOverlay(true);
    }
  }, [sidebarMode, isWide, setSidebarMode]);

  // Global keyboard shortcuts. Ignored while typing so "/" stays typeable in search.
  useEffect(() => {
    const isTypingTarget = (target: EventTarget | null): boolean => {
      if (!(target instanceof HTMLElement)) return false;
      const tag = target.tagName;
      return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target.isContentEditable;
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.defaultPrevented || document.querySelector('[aria-modal="true"]')) return;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'b') {
        event.preventDefault();
        handleToggleSidebar();
        return;
      }

      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen((open) => !open);
        return;
      }

      if (event.metaKey || event.ctrlKey || event.altKey) return;

      if (event.key === 'Escape') {
        if (paletteOpen) {
          setPaletteOpen(false);
          return;
        }
        if (hotkeysOpen) {
          setHotkeysOpen(false);
          return;
        }
        if (sidebarOverlay) {
          setSidebarOverlay(false);
          return;
        }
        if (vexOpen) {
          t.closeVex();
          return;
        }
        if (query) {
          t.setQuery('');
          return;
        }
        if (selectedId) {
          t.closeDrawer();
        }
        return;
      }

      if (isTypingTarget(event.target)) return;

      if (event.key === '?') {
        event.preventDefault();
        setHotkeysOpen((open) => !open);
        return;
      }

      const digit = Number.parseInt(event.key, 10);
      if (digit >= 1 && digit <= NAV_ORDER.length) {
        event.preventDefault();
        t.navigate(NAV_ORDER[digit - 1]);
        return;
      }

      if (event.key === 'r' && !busy && (!t.auth?.enabled || t.user?.role !== 'viewer')) {
        event.preventDefault();
        void t.rerun();
        return;
      }

      if (event.key === 'e') {
        event.preventDefault();
        exportReport();
        return;
      }

      if (event.key === '/') {
        event.preventDefault();
        focusSearch();
        return;
      }

      if (nav === 'findings' && (event.key === 'j' || event.key === 'ArrowDown')) {
        event.preventDefault();
        step(1);
        return;
      }

      if (nav === 'findings' && (event.key === 'k' || event.key === 'ArrowUp')) {
        event.preventDefault();
        step(-1);
        return;
      }

      if (event.key === 'v' && selected) {
        event.preventDefault();
        t.openVex('finding');
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [query, selectedId, selected, step, vexOpen, focusSearch, sidebarOverlay, paletteOpen, hotkeysOpen, busy, nav, exportReport, handleToggleSidebar, t]);

  if (t.auth?.tokenRequired && (!getAdminToken() || t.error)) return <LoginPage staticToken onLogin={async () => { await t.refreshAuth(); await t.reload(); }} />;
  if (t.auth?.enabled && !t.user) return <LoginPage onLogin={async () => { await t.refreshAuth(); await t.reload(); }} />;

  const globalPage = ['monitoring','governance','cicd','sast','dast','sca','workspaces', 'access', 'platform', 'projects', 'settings', 'advisory'].includes(nav);
  if (loading && !scan && !globalPage) return <Splash label="подключение к TRACE engine…" />;

  if (error && !scan && !globalPage) {
    return (
      <div className="veil flex h-screen items-center justify-center bg-ink-950 px-6">
        <div className="panel max-w-md px-6 py-6 text-center">
          <h1 className="text-[14px] font-semibold text-slate-100">Не удалось открыть рабочие данные</h1>
          <p className="mt-2 break-words font-mono text-2xs leading-relaxed text-rose-300">
            {error}
          </p>
          <p className="mt-3 text-2xs leading-relaxed text-slate-500">
            Проверьте подключение к API и доступ к выбранному рабочему пространству.
          </p>
          <button type="button" onClick={() => void t.reload()} className="btn-primary mt-4">
            Повторить подключение
          </button>
          <div className="mt-4"><WorkspaceSwitcher /></div>
        </div>
      </div>
    );
  }

  const drawerOpen = selected !== null;

  return (
    <div data-theme={theme} className="trace-app isolate relative flex h-screen min-h-0 flex-col overflow-hidden bg-ink-950 text-slate-300">
      {/* Analysis progress: an indeterminate sweep line while a scan is running. */}
      {busy && !progress ? (
        <div className="pointer-events-none absolute inset-x-0 top-0 z-[45] h-[2px] overflow-hidden">
          <div className="h-full w-1/3 animate-sweep bg-gradient-to-r from-transparent via-jade-400 to-transparent shadow-glow" />
        </div>
      ) : null}

      <TopBar theme={theme} onToggleTheme={toggleTheme}
        onOpenVex={() => t.openVex('all')}
        onFocusSearch={focusSearch}
        onToggleSidebar={handleToggleSidebar}
        onOpenPalette={() => setPaletteOpen(true)}
        onExport={exportReport}
        onOpenHelp={() => setHotkeysOpen(true)}
      />

      <div className="flex min-h-0 flex-1">
        {sidebarMode !== 'hidden' && isDesktop ? (
          <Sidebar active={nav} onNavigate={(id: NavId) => t.navigate(id)} mode={!isWide ? 'rail' : sidebarMode} />
        ) : null}

        <main className="relative flex min-w-0 flex-1">
          <div ref={pageScrollRef} onScroll={event => { scrollPositions.current[routeKey] = event.currentTarget.scrollTop; }} className="min-w-0 flex-1 overflow-y-auto">
            <div key={t.workspaceId} className="trace-content mx-auto flex max-w-[1800px] flex-col gap-5 px-4 py-6 sm:px-8">
              <SectionNavigation />
              {!globalPage && nav !== 'overview' && <ScanNotice />}
              {globalPage && error && <div role="alert" className="coverage-notice coverage-error"><strong>Требуется внимание</strong><p>{error}</p><button className="btn" onClick={() => void t.reload()}>Повторить</button></div>}
              {(nav === 'findings' || nav === 'reachability') && !selected && <nav className="section-navigation" aria-label="Представление уязвимостей"><button aria-current={nav === 'findings' ? 'page' : undefined} onClick={() => t.navigate('findings')}>Уязвимости</button><button aria-current={nav === 'reachability' ? 'page' : undefined} onClick={() => t.navigate('reachability')}>Анализ достижимости</button></nav>}
              {(nav === 'vex' || nav === 'compliance') && <nav className="section-navigation" aria-label="Виды отчётов"><button aria-current={nav === 'vex' ? 'page' : undefined} onClick={() => t.navigate('vex')}>Отчёты VEX</button><button aria-current={nav === 'compliance' ? 'page' : undefined} onClick={() => t.navigate('compliance')}>Соответствие стандартам</button></nav>}
              {nav === 'projects' ? <ProjectsPage /> : null}
              {nav === 'scans' ? <ScansPage /> : null}
              {nav === 'overview' ? <Overview /> : null}
{nav === 'findings' && !selected ? (
                <>
                  <PageHeader
                    title="Уязвимости"
                    meta={
                      scan
                        ? `${scan.repository}@${scan.commit} · ${scan.pipeline ?? '—'}`
                        : '—'
                    }
                    right={
                      scan ? (
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-2xs">
                          <span className="text-slate-500">
                            всего <span className="tnum text-slate-100">{n(scan.counts.total)}</span>
                          </span>
                          <span className="text-rose-300">
                            достижимы · затронуты <span className="tnum">{n(scan.counts.actionable)}</span>
                          </span>
                          <span className="text-slate-400">
                            вердикт: нужна проверка <span className="tnum">{n(scan.counts.needsReview)}</span>
                          </span>
                          <span className="text-slate-500">
                            подавлено <span className="tnum">{n(scan.counts.suppressed)}</span>
                          </span>
                        </div>
                      ) : null
                    }
                  />
                  <TriageTable
                    readOnly={!!t.auth?.enabled && t.user?.role === 'viewer'}
                    findings={visible}
                    total={scan?.counts.total ?? findings.length}
                    selectedId={selectedId}
                    onSelect={(finding) => t.select(finding.id)}
                    query={query}
                    onQueryChange={t.setQuery}
                    filter={filter}
                    onFilterChange={t.setFilter}
                    sort={sort}
                    onSortChange={t.setSort}
                    searchRef={searchRef}
                    onBatch={batch}
                  />
                  <footer className="flex flex-wrap items-center justify-between gap-2 px-1 pb-2">
                    <span className="micro">
                      TRACE · Transitive Reachability Analysis &amp; Contextual Exploitability
                    </span>
                    <span className="font-mono text-2xs text-slate-700">
                      Источники и доказательства доступны в карточке находки
                    </span>
                  </footer>
                </>
              ) : null}
              {nav === 'findings' && selected ? <FindingDetail key={selected.id} finding={selected} /> : null}
              {nav === 'reachability' ? <Reachability /> : null}
              {nav === 'sbom' ? <SbomPage /> : null}
              {nav === 'vex' ? <VexPage /> : null}
              {nav === 'advisory' ? <AdvisoryPage /> : null}
              {nav === 'compliance' ? <CompliancePage /> : null}
              {nav === 'settings' ? <AiSettingsPage /> : null}
              {(['cicd','sast','dast','sca'] as string[]).includes(nav) ? <DevSecOpsPage key={t.workspaceId+nav} view={nav as 'cicd'|'sast'|'dast'|'sca'} /> : null}
              {(nav==='monitoring'||nav==='governance')?<SecurityWorkPage key={t.workspaceId+nav} section={nav}/>:null}
              {nav === 'platform' ? <PlatformPage /> : null}
              {nav === 'access' ? <AccessPage /> : null}
              {nav === 'workspaces' ? <WorkspacesPage /> : null}
            </div>
          </div>


        </main>
      </div>

      {sidebarOverlay ? (
        <SidebarOverlay
          active={nav}
          onNavigate={(id: NavId) => t.navigate(id)}
          onClose={() => setSidebarOverlay(false)}
        />
      ) : null}

      <StatusBar />

      <VexModal
        open={vexOpen}
        selected={selected}
        initialScope={vexScope}
        onClose={t.closeVex}
      />

      <CommandPalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onExport={exportReport}
        onOpenHelp={() => setHotkeysOpen(true)}
      />

      <HotkeysHelp open={hotkeysOpen} onClose={() => setHotkeysOpen(false)} />

      {lastDone ? (
        <div className="pointer-events-none absolute left-1/2 top-3 z-50 -translate-x-1/2">
          <div className="flex items-center gap-2 rounded-md border border-emerald-500/40 bg-ink-800 px-3 py-2 shadow-lg shadow-black/60">
            <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-emerald-400" />
            <span className="text-2xs text-slate-200">{lastDone}</span>
          </div>
        </div>
      ) : null}

      {/* Announce the actionable backlog for assistive tech without extra chrome. */}
      <p className="sr-only" aria-live="polite">
        {visible.length} находок в очереди триажа
        {selected ? `, выбрана ${selected.cve}` : ''}
      </p>
    </div>
  );
}

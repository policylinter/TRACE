import { listWorkspaces, getSelectedWorkspace, setSelectedWorkspace, type WorkspaceOption } from '@/lib/api';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { Finding } from '@/data/findings';
import { createScan, deleteScan, deleteProject, getAuthStatus, getEvents, getFindings, getHealth, getMe, getScan, getSbom, listProjects, listScans, rescanAsync, getScanProgress, batchReview, batchSuppress, batchUnsuppress, logout, setAdminToken, reviewFinding, suppressFinding, unsuppressFinding, type AuthStatus, type AuthUser, type BatchAction, type CreateScanBody, type Health, type Project, type Scan, type ScanEvent, type ScanProgress, type Sbom } from '@/lib/api';
import { FILTERS, SORTS, type FilterKey, type SortKey } from '@/components/TriageTable';
import type { VexScope } from '@/lib/vex';

export type NavId = 'monitoring' | 'governance' | 'cicd' | 'sast' | 'dast' | 'sca' | 'workspaces' | 'access' | 'platform' | 'scans' | 'projects' | 'overview' | 'findings' | 'reachability' | 'sbom' | 'vex' | 'advisory' | 'compliance' | 'settings';
export type SidebarMode = 'expanded' | 'rail' | 'hidden';
export type { VexScope };

const SIDEBAR_KEY = 'trace.sidebar';
const PROJECT_KEY = 'trace.project';

function linkState() {
  if (typeof window === "undefined") return {view: "overview" as NavId, scan: null, finding: null, workspace:null};
  const params = new URLSearchParams(window.location.hash.slice(1));
  const views: NavId[] = ['monitoring','governance','cicd','sast','dast','sca','workspaces','access','platform','projects','overview','scans','findings','reachability','sbom','vex','advisory','compliance','settings'];
  const view = params.get('view');
  return {view: views.includes(view as NavId) ? view as NavId : 'overview' as NavId, scan: params.get('scan'), finding: params.get('finding'), workspace: params.get('workspace')};
}


function initialSidebarMode(): SidebarMode {
  try {
    const saved = window.localStorage.getItem(SIDEBAR_KEY);
    if (saved === 'expanded' || saved === 'rail' || saved === 'hidden') return saved;
  } catch {
    /* ignore storage errors */
  }
  return 'expanded';
}

function initialProjectId(): number | null {
  if (typeof window !== 'undefined') {
    const value = new URLSearchParams(window.location.hash.slice(1)).get('project');
    if (value && Number.isInteger(Number(value)) && Number(value) > 0) return Number(value);
  }
  if (typeof window !== "undefined" && new URLSearchParams(window.location.hash.slice(1)).has("scan")) return null;
  try {
    const saved = window.localStorage.getItem(PROJECT_KEY);
    if (saved) {
      const id = Number(saved);
      if (Number.isFinite(id)) return id;
    }
  } catch {
    /* ignore storage errors */
  }
  return null;
}

interface TraceState {
  workspaceId: string;
  workspaces: WorkspaceOption[];
  setWorkspace: (id:string) => void;
  loading: boolean;
  error: string | null;

  health: Health | null;
  projects: Project[];
  projectId: number | null;
  scans: Scan[];
  scan: Scan | null;
  findings: Finding[];
  sbom: Sbom | null;

  auth: AuthStatus | null;
  user: AuthUser | null;
  signOut: () => Promise<void>;
  refreshAuth: () => Promise<void>;

  events: ScanEvent[];
  unread: number;
  lastDone: string | null;
  notificationsOpen: boolean;

  nav: NavId;
  selectedId: string | null;
  query: string;
  filter: FilterKey;
  sort: SortKey;
  vexOpen: boolean;
  vexScope: VexScope;
  sidebarMode: SidebarMode;

  activeScanId: string | null;
  components: number;

  compareScan: Scan | null;
  compareFindings: Finding[];
  compareScanId: string | null;
  progress: ScanProgress | null;

  navigate: (nav: NavId) => void;
  setSidebarMode: (mode: SidebarMode) => void;
  select: (id: string) => void;
  closeDrawer: () => void;
  setQuery: (q: string) => void;
  setFilter: (f: FilterKey) => void;
  setSort: (s: SortKey) => void;
  openVex: (scope: VexScope) => void;
  closeVex: () => void;

  reload: () => Promise<void>;
  rerun: () => Promise<void>;
  removeScan: (id: string) => Promise<void>;
  removeProject: (id: number) => Promise<void>;
  setActiveScan: (id: string) => void;
  setProject: (id: number | null) => void;
  setCompareScan: (id: string) => Promise<void>;
  runScan: (body: CreateScanBody) => Promise<void>;
  toggleNotifications: () => void;
  toggleReview: (finding: Finding, reviewed: boolean) => Promise<void>;
  suppress: (finding: Finding, reason: string) => Promise<void>;
  unsuppress: (finding: Finding) => Promise<void>;
  batch: (ids: string[], action: BatchAction, reason?: string) => Promise<void>;

  busy: boolean;
}

const TraceContext = createContext<TraceState | null>(null);

export function TraceProvider({ children }: { children: ReactNode }) {
  const [workspaceId, setWorkspaceId] = useState(() => {
    const id = linkState().workspace || getSelectedWorkspace();
    setSelectedWorkspace(id);
    return id;
  });
  const [workspaces, setWorkspaces] = useState<WorkspaceOption[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [health, setHealth] = useState<Health | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState<number | null>(initialProjectId);
  const [scans, setScans] = useState<Scan[]>([]);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [sbom, setSbom] = useState<Sbom | null>(null);

  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);

  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [readSeen, setReadSeen] = useState(0);
  const [lastDone, setLastDone] = useState<string | null>(null);

  const [nav, setNav] = useState<NavId>(() => linkState().view);
  const [selectedId, setSelectedId] = useState<string | null>(() => linkState().finding);
  const [query, setQuery] = useState(() => typeof window === 'undefined' ? '' : new URLSearchParams(window.location.hash.slice(1)).get('q') ?? '');
  const [filter, setFilter] = useState<FilterKey>(() => {
    try { const value = new URLSearchParams(window.location.hash.slice(1)).get('filter') ?? localStorage.getItem('trace.queue.filter'); return FILTERS.find(f => f.key === value)?.key ?? 'all'; } catch { return 'all'; }
  });
  const [sort, setSort] = useState<SortKey>(() => {
    try { const value = new URLSearchParams(window.location.hash.slice(1)).get('sort') ?? localStorage.getItem('trace.queue.sort'); return SORTS.find(s => s.key === value)?.key ?? 'severity'; } catch { return 'severity'; }
  });
  useEffect(() => { try { localStorage.setItem('trace.queue.filter', filter); localStorage.setItem('trace.queue.sort', sort); } catch { /* private browsing */ } }, [filter, sort]);
  const [vexOpen, setVexOpen] = useState(false);
  const [vexScope, setVexScope] = useState<VexScope>('all');
  const [sidebarMode, setSidebarMode] = useState<SidebarMode>(initialSidebarMode);
  const [activeScanId, setActiveScanId] = useState<string | null>(() => linkState().scan);
  const [busy, setBusy] = useState(false);
  const [compareScan, setCompareScanState] = useState<Scan | null>(null);
  const [compareFindings, setCompareFindings] = useState<Finding[]>([]);
  const [compareScanId, setCompareScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState<ScanProgress | null>(null);

  const scanRequestRef = useRef(0);
  const reloadRequestRef = useRef(0);
  const clearPrivateState = useCallback(() => {
    ++scanRequestRef.current; ++reloadRequestRef.current;
    setScan(null); setScans([]); setFindings([]); setSbom(null); setProjects([]);
    setEvents([]); setHealth(null); setWorkspaces([]); setBusy(false); setLastDone(null); setSelectedId(null); setProgress(null);
    setCompareScanState(null); setCompareFindings([]); setCompareScanId(null);
    setNotificationsOpen(false); setVexOpen(false);
  }, []);

  const loadScan = useCallback(async (scanId: string) => {
    const request = ++scanRequestRef.current;
    const [scanData, findingData, sbomData] = await Promise.all([
      getScan(scanId),
      getFindings(scanId, { sort: 'severity' }),
      getSbom(scanId).catch(() => null),
    ]);
    if (request !== scanRequestRef.current) return;
    setScan(scanData);
    setFindings(findingData);
    setSbom(sbomData);
    setSelectedId((prev) => (prev && findingData.some((f) => f.id === prev) ? prev : null));
  }, []);

  const refreshEvents = useCallback(async () => {
    try {
      setEvents(await getEvents(20));
    } catch {
      /* keep the current list on transient failures */
    }
  }, []);

  const refreshAuth = useCallback(async () => {
    try {
      const status = await getAuthStatus();
      setAuth(status);
      if (status.enabled) {
        const me = await getMe();
        setUser(me.authenticated ? me.user ?? null : null);
      } else {
        setUser(null);
      }
    } catch {
      setAuth(null);
      setUser(null);
    }
  }, []);

  useEffect(() => {
    void refreshAuth();
  }, [refreshAuth]);

  const signOut = useCallback(async () => {
    try {
      await logout();
    } catch {
      /* the session may already be gone */
    }
    clearPrivateState();
    setUser(null);
    await refreshAuth();
  }, [refreshAuth, clearPrivateState]);

  const unread = events.reduce((count, event) => (event.id > readSeen ? count + 1 : count), 0);

  const toggleNotifications = useCallback(() => {
    setNotificationsOpen((open) => {
      const next = !open;
      if (next) setReadSeen(events.reduce((max, event) => Math.max(max, event.id), readSeen));
      return next;
    });
  }, [events, readSeen]);

  const persistSidebarMode = useCallback((mode: SidebarMode) => {
    setSidebarMode(mode);
    try {
      window.localStorage.setItem(SIDEBAR_KEY, mode);
    } catch {
      /* ignore storage errors */
    }
  }, []);

  useEffect(() => {
    if (!lastDone) return;
    const timer = window.setTimeout(() => setLastDone(null), 6000);
    return () => window.clearTimeout(timer);
  }, [lastDone]);

  const reload = useCallback(async () => {
    const request = ++reloadRequestRef.current;
    setLoading(true);
    setError(null);
    try {
      const spaces = await listWorkspaces();
      if (request !== reloadRequestRef.current) return;
      setWorkspaces(spaces);
      if (!spaces.some(w => w.id === workspaceId)) {
        const first = spaces[0];
        if (!first) throw new Error('Вам не назначены рабочие пространства. Обратитесь к администратору организации.');
        clearPrivateState(); setWorkspaces(spaces);
        setSelectedWorkspace(first.id); setWorkspaceId(first.id);
        window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#${new URLSearchParams({view:nav,workspace:first.id})}`);
        window.dispatchEvent(new Event('trace:workspace-changed'));
        setProjectId(null); setActiveScanId(null); setScan(null); setFindings([]); setSbom(null);
        return;
      }
      await refreshAuth();
      const [h, projectList, ev] = await Promise.all([
        getHealth(),
        listProjects(),
        getEvents(20),
      ]);
      const validProject =
        projectId != null && projectList.some((p) => p.id === projectId) ? projectId : null;
      const list = await listScans(validProject);
      if (request !== reloadRequestRef.current) return;
      setHealth(h);
      setProjects(projectList);
      if (validProject !== projectId) setProjectId(validProject);
      setScans(list);
      setEvents(ev);
      const pickDefault = (): string | null => {
        if (activeScanId && list.some((s) => s.id === activeScanId)) return activeScanId;
        const richest = [...list].sort(
          (a, b) =>
            b.scannedAt.localeCompare(a.scannedAt),
        )[0];
        return richest?.id ?? list[0]?.id ?? null;
      };
      const target = pickDefault();
      if (target) {
        setActiveScanId(target);
        await loadScan(target);
      } else {
        setActiveScanId(null);
        setScan(null);
        setFindings([]);
        setSbom(null);
      }
    } catch (err) {
      if (request === reloadRequestRef.current) setError(err instanceof Error ? err.message : 'Не удалось подключиться к TRACE API');
    } finally {
      if (request === reloadRequestRef.current) setLoading(false);
    }
  }, [activeScanId, loadScan, projectId, workspaceId, refreshAuth, clearPrivateState, nav]);

  useEffect(() => {
    void reload();
    // Reload when the selected project changes (and once on mount).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, workspaceId]);

  useEffect(() => {
    const expire = () => { setAdminToken(''); clearPrivateState(); setUser(null); void refreshAuth(); };
    window.addEventListener('trace:auth-expired', expire);
    return () => window.removeEventListener('trace:auth-expired', expire);
  }, [clearPrivateState, refreshAuth]);

  const setWorkspace = useCallback((id:string) => {
    if (id === workspaceId || !workspaces.some(w => w.id === id)) return;
    setSelectedWorkspace(id); clearPrivateState(); setWorkspaceId(id);
    setProjectId(null); setActiveScanId(null); setLoading(true); setError(null);
    try { localStorage.removeItem(PROJECT_KEY); } catch { /* private mode */ }
    window.history.replaceState(null, '', `${window.location.pathname}${window.location.search}#${new URLSearchParams({view:nav,workspace:id})}`);
    window.dispatchEvent(new Event('trace:workspace-changed'));
  }, [workspaceId, workspaces, clearPrivateState, nav]);

  const setProject = useCallback((id: number | null) => {
    if (id === projectId) return;
    ++scanRequestRef.current;
    ++reloadRequestRef.current;
    setLoading(true);
    setProjectId(id);
    setActiveScanId(null);
    setScan(null); setFindings([]); setSbom(null); setSelectedId(null); setScans([]);
    try {
      if (id == null) window.localStorage.removeItem(PROJECT_KEY);
      else window.localStorage.setItem(PROJECT_KEY, String(id));
    } catch {
      /* ignore storage errors */
    }
  }, [projectId]);


  useEffect(() => {
    const restore = () => {
      const state = linkState();
      const params = new URLSearchParams(window.location.hash.slice(1));
      if (state.workspace && state.workspace !== workspaceId) {
        if (!workspaces.some(w => w.id === state.workspace)) { setError('Нет доступа к рабочему пространству из ссылки.'); return; }
        setSelectedWorkspace(state.workspace);
        try { localStorage.removeItem(PROJECT_KEY); } catch { /* private mode */ }
        window.dispatchEvent(new Event('trace:workspace-changed'));
        return;
      }
      setNav(state.view); setSelectedId(state.finding);
      setQuery(params.get('q') ?? '');
      setFilter(FILTERS.find(item => item.key === params.get('filter'))?.key ?? 'all');
      setSort(SORTS.find(item => item.key === params.get('sort'))?.key ?? 'severity');
      const scope = params.get('project');
      const targetProject = scope && Number.isInteger(Number(scope)) && Number(scope) > 0 ? Number(scope) : null;
      if (!state.scan && targetProject !== projectId) setProject(targetProject);
      if (state.scan && state.scan !== activeScanId) {
        setActiveScanId(state.scan);
        if (projectId !== targetProject) setProjectId(targetProject);
        void loadScan(state.scan).catch(() => setError('Не удалось открыть проверку из ссылки. Проверьте адрес или выберите другой запуск.'));
      }
    };
    window.addEventListener('hashchange', restore);
    return () => window.removeEventListener('hashchange', restore);
  }, [activeScanId, projectId, loadScan, setProject, workspaceId, workspaces]);

  useEffect(() => {
    if (loading) return;
    const params = new URLSearchParams({view: nav, workspace: workspaceId});
    if (projectId != null) params.set('project', String(projectId));
    if (activeScanId) params.set('scan', activeScanId);
    if (query) params.set('q', query);
    params.set('filter', filter);
    params.set('sort', sort);
    if (nav === 'findings' && selectedId) params.set('finding', selectedId);
    const securityRecord=new URLSearchParams(window.location.hash.slice(1)).get('record');
    if((nav==='monitoring'||nav==='governance')&&securityRecord)params.set('record',securityRecord);
    const previous = linkState();
    const url = `${window.location.pathname}${window.location.search}#${params}`;
    const destinationFinding = nav === 'findings' ? selectedId : null;
    if (previous.view !== nav || previous.finding !== destinationFinding) window.history.pushState(null, '', url);
    else window.history.replaceState(null, '', url);
  }, [loading, nav, activeScanId, selectedId, query, filter, sort, projectId, workspaceId]);
  const compareRequestRef = useRef<string | null>(null);

  const setCompareScan = useCallback(
    async (id: string) => {
      if (!id || id === activeScanId) {
        compareRequestRef.current = null;
        setCompareScanId(null);
        setCompareScanState(null);
        setCompareFindings([]);
        return;
      }
      compareRequestRef.current = id;
      setCompareScanId(id);
      try {
        const [scanData, findingData] = await Promise.all([
          getScan(id),
          getFindings(id, { sort: 'severity' }),
        ]);
        if (compareRequestRef.current === id) {
          setCompareScanState(scanData);
          setCompareFindings(findingData);
        }
      } catch {
        if (compareRequestRef.current === id) {
          setCompareScanId(null);
          setCompareScanState(null);
          setCompareFindings([]);
        }
      }
    },
    [activeScanId],
  );

  const setActiveScan = useCallback(
    (id: string) => {
      if (id === activeScanId) return;
      const previous = activeScanId;
      setActiveScanId(id);
      setError(null);
      void loadScan(id).catch(() => { setActiveScanId(previous); setError('Не удалось открыть проверку. Повторите выбор запуска.'); });
      if (previous) void setCompareScan(previous);
    },
    [activeScanId, loadScan, setCompareScan],
  );

  const rerun = useCallback(async () => {
    if (!scan) return;
    setError(null);
    setBusy(true);
    setProgress({ scanId: scan.id, phase: 'queue', progress: 0, message: 'постановка в очередь', active: true });
    let lastThrottle = 0;
    let pollFailures = 0;
    let rescanJobId: string | undefined;
    const poll = async (): Promise<void> => {
      const now = Date.now();
      if (now - lastThrottle >= 320) {
        lastThrottle = now;
        let terminal = false;
        try {
          const update = await getScanProgress(scan.id, rescanJobId);
          pollFailures = 0;
          setProgress(update);
          if (['error', 'failed', 'cancelled', 'interrupted'].includes(update.phase) || update.requiresReview) {
            terminal = true;
            throw new Error(update.phase === 'cancelled' ? 'Пересчёт отменён до запуска.' : update.requiresReview ? 'Состояние исполнителя требует проверки. Завершение пересчёта не подтверждено.' : 'Повторный анализ завершился ошибкой. Проверьте сервер и повторите запрос.');
          }
          if (!update.active) return;
        } catch (err) {
          if (terminal || ++pollFailures >= 5) throw err;
        }
      }
      await new Promise((resolve) => setTimeout(resolve, 320));
      return poll();
    };
    try {
      const queued = await rescanAsync(scan.id);
      rescanJobId = queued.jobId;
      await poll();
      await loadScan(scan.id);
      void refreshEvents();
      const updated = await getScan(scan.id);
      setScans(current => current.map(item => item.id === updated.id ? updated : item));
      setLastDone(`Пересканирование завершено: ${updated.repository} · ${updated.counts.total} находок`);
    } catch (err) {
      if (err instanceof Error && err.message === 'Пересчёт отменён до запуска.') setLastDone(err.message);
      else setError(err instanceof Error ? err.message : 'Ошибка повторного анализа');
    } finally {
      setBusy(false);
      setProgress(null);
    }
  }, [scan, loadScan, refreshEvents]);

  const removeScan = useCallback(
    async (id: string) => {
      setError(null);
      const result = await deleteScan(id);
      const [list, projectList] = await Promise.all([
        listScans(projectId),
        listProjects().catch(() => [] as Project[]),
      ]);
      setScans(list);
      setProjects(projectList);
      void refreshEvents();
      if (compareScanId === id) {
        compareRequestRef.current = null;
        setCompareScanId(null);
        setCompareScanState(null);
        setCompareFindings([]);
      }
      if (activeScanId === id) {
        const richest =
          [...list].sort(
            (a, b) =>
              b.scannedAt.localeCompare(a.scannedAt),
          )[0] ?? null;
        if (richest) {
          setActiveScanId(richest.id);
          await loadScan(richest.id);
        } else {
          setActiveScanId(null);
          setScan(null);
          setFindings([]);
          setSbom(null);
        }
      }
      setLastDone(`Скан удалён: ${result.deleted}`);
    },
    [activeScanId, compareScanId, loadScan, projectId, refreshEvents],
  );

  const removeProject = useCallback(
    async (id: number) => {
      setError(null);
      const result = await deleteProject(id);
      const nextProjectId = projectId === id ? null : projectId;
      if (projectId === id) setProjectId(null);
      const [list, projectList] = await Promise.all([
        listScans(nextProjectId),
        listProjects().catch(() => [] as Project[]),
      ]);
      setScans(list);
      setProjects(projectList);
      void refreshEvents();
      const gone = scans.find((s) => s.projectId === id)?.id;
      if (activeScanId && (activeScanId === gone || !list.some((s) => s.id === activeScanId))) {
        const richest =
          [...list].sort(
            (a, b) =>
              b.scannedAt.localeCompare(a.scannedAt),
          )[0] ?? null;
        if (richest) {
          setActiveScanId(richest.id);
          await loadScan(richest.id);
        } else {
          setActiveScanId(null);
          setScan(null);
          setFindings([]);
          setSbom(null);
        }
      }
      setLastDone(`Проект удалён: ${result.name} · ${result.scans} сканов`);
    },
    [activeScanId, loadScan, projectId, refreshEvents, scans],
  );

  const batch = useCallback(
    async (ids: string[], action: BatchAction, reason?: string) => {
      if (!scan || ids.length === 0) return;
      setError(null);
      try {
        if (action === 'review') await batchReview(ids, true);
        else if (action === 'suppress')
          await batchSuppress(ids, reason?.trim() || 'Batch suppression from triage queue.');
        else await batchUnsuppress(ids);
        const list = await getFindings(scan.id, { sort: 'severity' });
        setFindings(list);
        setScan(await getScan(scan.id));
        void refreshEvents();
        setLastDone(`Триаж: обновлено ${ids.length} находок`);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Ошибка массового триажа');
        throw err;
      }
    },
    [scan, refreshEvents],
  );

  const runScan = useCallback(
    async (body: CreateScanBody) => {
      setError(null);
      setBusy(true);
      try {
        const created = await createScan(body);
        const [list, projectList] = await Promise.all([
          listScans(projectId),
          listProjects().catch(() => [] as Project[]),
        ]);
        setScans(list);
        setProjects(projectList);
        setActiveScanId(created.id);
        await loadScan(created.id);
        setNav('findings');
        void refreshEvents();
        setLastDone(`Сканирование завершено: ${created.repository ?? created.id} · ${created.counts.total} находок`);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Ошибка запуска сканирования');
      } finally {
        setBusy(false);
      }
    },
    [loadScan, refreshEvents, projectId],
  );

  const toggleReview = useCallback(async (finding: Finding, reviewed: boolean) => {
    const updated = await reviewFinding(finding.id, reviewed);
    setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
    void refreshEvents();
  }, [refreshEvents]);

  const suppress = useCallback(async (finding: Finding, reason: string) => {
    const updated = await suppressFinding(finding.id, reason);
    setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
    void refreshEvents();
  }, [refreshEvents]);

  const unsuppress = useCallback(async (finding: Finding) => {
    const updated = await unsuppressFinding(finding.id);
    setFindings((prev) => prev.map((f) => (f.id === updated.id ? updated : f)));
    void refreshEvents();
  }, [refreshEvents]);

  const components = useMemo(() => {
    const set = new Set<string>();
    findings.forEach((f) => (f.dependencyPath.length ? f.dependencyPath : [f.packageName]).forEach((n) => set.add(n)));
    return sbom?.components ?? set.size;
  }, [findings, sbom]);

  const value: TraceState = {
    workspaceId, workspaces, setWorkspace,
    loading,
    error,
    health,
    projects,
    projectId,
    scans,
    scan,
    findings,
    sbom,
    auth,
    user,
    signOut,
    refreshAuth,
    events,
    unread,
    lastDone,
    notificationsOpen,
    nav,
    selectedId,
    query,
    filter,
    sort,
    vexOpen,
    vexScope,
    sidebarMode,
    activeScanId,
    components,
    compareScan,
    compareFindings,
    compareScanId,
    progress,
    navigate: setNav,
    setSidebarMode: persistSidebarMode,
    select: setSelectedId,
    closeDrawer: () => setSelectedId(null),
    setQuery,
    setFilter,
    setSort,
    openVex: (scope) => {
      setVexScope(scope);
      setVexOpen(true);
    },
    closeVex: () => setVexOpen(false),
    reload,
    rerun,
    removeScan,
    removeProject,
    setActiveScan,
    setCompareScan,
    setProject,
    runScan,
    toggleNotifications,
    toggleReview,
    suppress,
    unsuppress,
    batch,
    busy,
  };

  return <TraceContext.Provider value={value}>{children}</TraceContext.Provider>;
}

export function useTrace(): TraceState {
  const ctx = useContext(TraceContext);
  if (!ctx) throw new Error('useTrace must be used within <TraceProvider>');
  return ctx;
}

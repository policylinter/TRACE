import { useTrace, type NavId, type SidebarMode } from '@/state/TraceProvider';
import { NAV_GROUPS, primaryNav } from '@/data/nav';
import { useDialogFocus } from '@/hooks/useDialogFocus';
import { ProjectSwitcher } from './ProjectSwitcher';
import { cx } from '@/lib/format';
import { IconGrid, IconList, IconLayers, IconGraph, IconDoc, IconShield, IconCpu, IconChevronLeft, IconChevronRight, IconUser, IconLogout, IconLock } from './icons';

const icons = { grid: IconGrid, list: IconList, layers: IconLayers, graph: IconGraph, doc: IconDoc, shield: IconShield, cpu: IconCpu };

function initials(name: string): string {
  const parts = name.replace(/[^\p{L}\p{N}]+/gu, ' ').trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '··';
  if (parts.length === 1) return parts[0].slice(0, 2);
  return `${parts[0][0]}${parts[1][0]}`;
}

function Profile({ collapsed, onNavigate }: { collapsed: boolean; onNavigate: (id: NavId) => void }) {
  const t = useTrace();
  const name = t.user?.displayName || t.user?.username || 'Локальный доступ';
  const role = t.user?.role || (t.auth?.enabled ? 'не выполнен вход' : 'локальный режим');
  return (
    <div className="sidebar-profile" title={collapsed ? name : undefined}>
      <span className="sidebar-profile-avatar">
        {t.user ? initials(t.user.displayName || t.user.username) : <IconUser className="h-3.5 w-3.5" />}
      </span>
      {!collapsed ? (
        <>
          <span className="sidebar-profile-body">
            <span className="sidebar-profile-name">{name}</span>
            <span className="sidebar-profile-role">{role}</span>
          </span>
          {t.user ? (
            <button
              type="button"
              className="sidebar-profile-action"
              title="Выйти из аккаунта"
              aria-label="Выйти из аккаунта"
              onClick={() => void t.signOut()}
            >
              <IconLogout className="h-4 w-4" />
            </button>
          ) : (
            <button
              type="button"
              className="sidebar-profile-action"
              title="Настройки"
              aria-label="Настройки"
              onClick={() => onNavigate('settings')}
            >
              <IconCpu className="h-4 w-4" />
            </button>
          )}
        </>
      ) : null}
    </div>
  );
}

function ScanContext({ onNavigate }: { onNavigate: (id: NavId) => void }) {
  const scan = useTrace().scan;
  if (!scan) return null;
  return (
    <div className="sidebar-context">
      <div className="sidebar-project-context">
        <span>Текущая проверка</span>
        <strong>{scan.pipeline}</strong>
        <code>{scan.branch} · {(scan.commitLong || '').slice(0, 12) || '—'}</code>
        <p>SBOM {scan.sbom} · {scan.duration} · {scan.triggeredBy}</p>
        <button type="button" onClick={() => onNavigate('scans')}>Все проверки <IconChevronRight className="h-3 w-3" /></button>
      </div>
      <div className="sidebar-project-context">
        <span>AI · сведения отчёта</span>
        <strong>{scan.aiRuntime.model}</strong>
        <code>{scan.aiRuntime.device} · {scan.aiRuntime.quantisation} · {scan.aiRuntime.host}</code>
        <p>Размещение модели и исходящий трафик не измерены TRACE.</p>
        <span className="context-lock"><IconLock className="h-3 w-3" /> egress не измерен</span>
      </div>
    </div>
  );
}

function Content({ active, onNavigate, collapsed = false }: { active: NavId; onNavigate: (id: NavId) => void; collapsed?: boolean }) {
  const t = useTrace();
  const badgeFor = (key?: 'total' | 'reachable' | 'components' | 'vex'): number | null => {
    if (key === 'total') return t.scan ? t.findings.length : null;
    if (key === 'components') return t.scan ? t.components : null;
    return null;
  };
  return <>
    <button className="sidebar-brand" onClick={() => onNavigate('overview')} aria-label="TRACE — обзор"><IconShield className="h-6 w-6" />{!collapsed && <span className="brand-wordmark">TRACE<span className="brand-point">.</span><small>SECURITY WORKSPACE</small></span>}</button>
    <ProjectSwitcher collapsed={collapsed} onNavigate={onNavigate} />
    <div className="sidebar-nav-wrap">
      <nav className="sidebar-navigation" aria-label="Основная навигация">
        {NAV_GROUPS.map(group => (
          <div key={group.id} className={cx('sidebar-group', group.id === 'система' && 'sidebar-system')}>
            {!collapsed && <p className="sidebar-group-label">{group.label}</p>}
            {group.items.map(item => {
              const Icon = icons[item.glyph];
              const current = primaryNav(active) === item.id;
              const badge = badgeFor(item.badgeKey);
              return <button key={item.id} onClick={() => onNavigate(item.id)} aria-label={item.label} title={collapsed ? item.label : undefined} aria-current={current ? 'page' : undefined} className={cx('sidebar-link', current && 'is-current')}>
                <Icon className="h-4 w-4 shrink-0" />
                {!collapsed && <><span>{item.label}</span>{badge != null && badge > 0 ? <small>{badge}</small> : null}</>}
              </button>;
            })}
            
          </div>
        ))}
      </nav>
      {!collapsed && <details className="sidebar-session"><summary>Контекст проверки</summary><ScanContext onNavigate={onNavigate} /></details>}
    </div>
    <Profile collapsed={collapsed} onNavigate={onNavigate} />
  </>;
}

export function Sidebar({ active, onNavigate, mode }: { active: NavId; onNavigate: (id: NavId) => void; mode: SidebarMode }) {
  const t = useTrace();
  const collapsed = mode === 'rail';
  return <aside className={`trace-sidebar workspace-sidebar ${collapsed ? 'is-collapsed' : ''}`}><Content active={active} onNavigate={onNavigate} collapsed={collapsed} /><button className="sidebar-collapse" onClick={() => t.setSidebarMode(collapsed ? 'expanded' : 'rail')} aria-label={collapsed ? 'Развернуть меню' : 'Свернуть меню'}>{collapsed ? <IconChevronRight className="h-4 w-4" /> : <><IconChevronLeft className="h-4 w-4" /><span>Свернуть меню</span><kbd>Ctrl B</kbd></>}</button></aside>;
}

export function SidebarOverlay({ active, onNavigate, onClose }: { active: NavId; onNavigate: (id: NavId) => void; onClose: () => void }) {
  const ref = useDialogFocus<HTMLElement>(true, onClose);
  return <><button className="fixed inset-0 z-40 bg-ink-950/60" aria-label="Закрыть меню" onClick={onClose} /><aside ref={ref} role="dialog" aria-modal="true" aria-label="Навигация TRACE" tabIndex={-1} className="trace-sidebar workspace-sidebar sidebar-overlay"><button className="btn m-3" onClick={onClose}>Закрыть меню</button><Content active={active} onNavigate={id => { onNavigate(id); onClose(); }} /></aside></>;
}

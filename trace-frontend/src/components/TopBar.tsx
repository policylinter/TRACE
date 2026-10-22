import { WorkspaceSwitcher } from './WorkspaceSwitcher';
import { IconShield } from './icons';
import { useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTrace } from '@/state/TraceProvider';
import { cx, n } from '@/lib/format';
import { Micro } from './primitives';
import { IconBell, IconClose, IconDoc, IconDownload, IconLock, IconMenu, IconSearch, IconSparkle } from './icons';

interface TopBarProps {
  onOpenVex: () => void;
  onFocusSearch: () => void;
  onToggleSidebar: () => void;
  onOpenPalette: () => void;
  onExport: () => void;
  onOpenHelp: () => void;
}

function formatEventTime(iso: string): string {
  const minutes = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (minutes < 1) return 'только что';
  if (minutes < 60) return `${minutes} мин назад`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} ч назад`;
  return new Date(iso).toLocaleDateString('ru-RU');
}

function NotificationsPanel() {
  const { events, toggleNotifications } = useTrace();
  return (
    <>
      <button
        type="button"
        aria-label="Закрыть уведомления"
        onClick={toggleNotifications}
        className="fixed inset-0 z-[95] cursor-default bg-ink-950/40"
      />
      <div className="fixed right-4 top-14 z-[100] w-[360px] overflow-hidden rounded-xl border border-hairline-strong bg-ink-875 shadow-float ring-1 ring-black/60">
        <div className="flex items-center justify-between border-b border-hairline bg-ink-925/80 px-3 py-2.5 backdrop-blur-xl">
          <span className="micro-strong">Уведомления</span>
          <button type="button" onClick={toggleNotifications} className="btn-ghost h-6 w-6 p-0" title="Закрыть">
            <IconClose className="h-3 w-3" />
          </button>
        </div>
        {events.length === 0 ? (
          <p className="px-3 py-4 text-2xs leading-relaxed text-slate-400">
            Событий пока нет. Здесь появятся отметки триажа (проверено, подавлено) и завершённые сканы.
          </p>
        ) : (
          <ul className="max-h-[420px] overflow-y-auto">
            {events.map((event) => (
              <li key={event.id} className="border-b border-hairline px-3 py-2.5 last:border-0 transition-colors duration-150 hover:bg-white/[0.02]">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-2xs font-semibold uppercase tracking-wide text-slate-200">
                    {event.action}
                  </span>
                  <span className="font-mono text-2xs text-slate-500">{formatEventTime(event.createdAt)}</span>
                </div>
                {event.cve || event.packageName ? (
                  <div className="mt-0.5 truncate font-mono text-2xs text-slate-400">
                    {[event.cve, event.packageName].filter(Boolean).join(' · ')}
                  </div>
                ) : null}
                <p className="mt-1 text-2xs leading-relaxed text-slate-300">{event.detail}</p>
                <div className="mt-1 font-mono text-2xs text-slate-500">{event.actor}</div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </>
  );
}

export function TopBar({ onFocusSearch, onToggleSidebar, onOpenPalette, theme, onToggleTheme }: TopBarProps & {theme: 'light' | 'dark'; onToggleTheme: () => void}) {
  const { unread, notificationsOpen, toggleNotifications, health, error, nav } = useTrace();
  return <header className="workbench-topbar">
    <button type="button" onClick={onToggleSidebar} aria-label="Меню (Ctrl+B)" title="Меню (Ctrl+B)" className="topbar-icon"><IconMenu className="h-4 w-4" /></button>
    <span className="topbar-location">{({monitoring:'Мониторинг и инциденты',governance:'Риски и задачи',cicd:'CI/CD',sast:'SAST',dast:'DAST',sca:'SCA',workspaces:'Пространства и команды',access:'Организация и доступ',platform:'Активы и модули',overview:'Обзор', findings:'Уязвимости', reachability:'Уязвимости / Достижимость', sbom:'Зависимости', scans:'Проверки', vex:'Отчёты / VEX', compliance:'Отчёты / Стандарты', advisory:'База уязвимостей', settings:'Настройки', projects:'Проекты'})[nav]}</span>
    <WorkspaceSwitcher />
    <button type="button" onClick={onOpenPalette} className="workbench-search" aria-label="Поиск и команды"><IconSearch className="h-4 w-4" /><span>Поиск и команды</span><kbd>Ctrl K</kbd></button>
    <button type="button" onClick={onToggleTheme} aria-label={theme === 'light' ? 'Включить тёмную тему' : 'Включить светлую тему'} title={theme === 'light' ? 'Включить тёмную тему' : 'Включить светлую тему'} className="topbar-icon theme-toggle">{theme === 'light' ? '☾' : '☀'}</button>
    <span className="api-indicator" title={health?.status === 'ok' && !error ? 'API подключён' : 'API недоступен'}><i style={{background:health?.status === 'ok' && !error?'#54d6be':'#fb7185'}} /> API</span>
    <button type="button" onClick={toggleNotifications} aria-expanded={notificationsOpen} aria-label="Уведомления" title="Уведомления" className="topbar-icon relative"><IconBell className="h-4 w-4" />{unread > 0 && <span className="notification-dot" />}</button>
    {notificationsOpen ? createPortal(<NotificationsPanel />, document.body) : null}
  </header>;
}

import { useEffect, useRef, useState } from 'react';
import { useTrace, type NavId } from '@/state/TraceProvider';
import { cx } from '@/lib/format';
import { IconCheck, IconChevronDown, IconFolder, IconLayers, IconSearch } from './icons';

function initials(name: string): string {
  const parts = name.replace(/[^\p{L}\p{N}]+/gu, ' ').trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '··';
  if (parts.length === 1) return parts[0].slice(0, 2);
  return `${parts[0][0]}${parts[1][0]}`;
}

export function ProjectSwitcher({ collapsed, onNavigate }: { collapsed: boolean; onNavigate: (id: NavId) => void }) {
  const t = useTrace();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [coords, setCoords] = useState<{ left: number; top: number; width: number } | null>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  const current = t.projects.find((p) => p.id === t.projectId) ?? null;

  useEffect(() => {
    if (!open) return;
    const place = () => {
      const rect = triggerRef.current?.getBoundingClientRect();
      if (!rect) return;
      const width = Math.min(300, window.innerWidth - 24);
      setCoords({
        left: Math.min(rect.left, window.innerWidth - width - 12),
        top: rect.bottom + 6,
        width,
      });
    };
    place();
    const onPointerDown = (event: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false);
    };
    window.addEventListener('resize', place);
    window.addEventListener('scroll', place, true);
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('resize', place);
      window.removeEventListener('scroll', place, true);
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (!open) setQuery('');
  }, [open]);

  const choose = (id: number | null) => {
    setOpen(false);
    if (id !== t.projectId) t.setProject(id);
    onNavigate('overview');
  };

  if (collapsed) {
    return (
      <div className="project-switcher">
        <button
          type="button"
          className="topbar-icon"
          title={current ? current.name : 'Все проекты'}
          aria-label="Проекты"
          onClick={() => onNavigate('projects')}
        >
          <IconLayers className="h-5 w-5" />
        </button>
      </div>
    );
  }

  const needle = query.trim().toLowerCase();
  const list = needle ? t.projects.filter((p) => p.name.toLowerCase().includes(needle)) : t.projects;

  return (
    <div className="project-switcher" ref={wrapRef}>
      <button
        type="button"
        ref={triggerRef}
        className="project-switcher-trigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <span className="project-switcher-avatar">
          {current ? initials(current.name) : <IconLayers className="h-4 w-4" />}
        </span>
        <span className="project-switcher-body">
          <span className="project-switcher-name">{current ? current.name : 'Все проекты'}</span>
          <span className="project-switcher-meta">
            {current
              ? current.repoUrl || `${t.scans.length} проверок`
              : `${t.projects.length} ${t.projects.length === 1 ? 'проект' : 'проектов'}`}
          </span>
        </span>
        <IconChevronDown className={cx('project-switcher-caret h-4 w-4', open && 'is-open')} />
      </button>

      {open && coords ? (
        <div
          className="project-switcher-menu"
          style={{ left: coords.left, top: coords.top, width: coords.width }}
          role="listbox"
          aria-label="Выбор проекта"
        >
          <label className="project-switcher-search">
            <IconSearch className="h-3.5 w-3.5" />
            <input
              autoFocus
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Поиск проекта…"
              aria-label="Поиск проекта"
            />
          </label>
          <ul className="project-switcher-list">
            <li>
              <button
                type="button"
                role="option"
                aria-selected={t.projectId === null}
                className="project-switcher-option"
                onClick={() => choose(null)}
              >
                <IconLayers className="h-4 w-4 shrink-0" />
                <span className="pso-name">Все проекты</span>
                {t.projectId === null ? <IconCheck className="pso-check h-4 w-4" /> : null}
              </button>
            </li>
            {list.map((project) => (
              <li key={project.id}>
                <button
                  type="button"
                  role="option"
                  aria-selected={t.projectId === project.id}
                  className="project-switcher-option"
                  onClick={() => choose(project.id)}
                >
                  <span className="project-switcher-avatar sm">{initials(project.name)}</span>
                  <span className="pso-name">{project.name}</span>
                  {t.projectId === project.id ? <IconCheck className="pso-check h-4 w-4" /> : null}
                </button>
              </li>
            ))}
            {list.length === 0 ? <li className="project-switcher-empty">Проекты не найдены</li> : null}
          </ul>
          <button
            type="button"
            className="project-switcher-manage"
            onClick={() => {
              setOpen(false);
              onNavigate('projects');
            }}
          >
            <IconFolder className="h-3.5 w-3.5" />
            Управление проектами
          </button>
        </div>
      ) : null}
    </div>
  );
}

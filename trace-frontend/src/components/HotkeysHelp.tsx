import { useDialogFocus } from '@/hooks/useDialogFocus';
import { createPortal } from 'react-dom';
import { IconClose } from './icons';

interface HotkeysHelpProps {
  open: boolean;
  onClose: () => void;
}

const GROUPS: { title: string; items: [string, string][] }[] = [
  {
    title: 'Навигация',
    items: [
      ['1 … 7', 'Переключить раздел'],
      ['Ctrl / ⌘ B', 'Свернуть или развернуть меню'],
      ['Ctrl / ⌘ K', 'Командная палитра'],
    ],
  },
  {
    title: 'Триаж',
    items: [
      ['j / ↓', 'Следующая находка'],
      ['k / ↑', 'Предыдущая находка'],
      ['v', 'Открыть VEX для выбранной'],
      ['/', 'Поиск по находкам'],
      ['Esc', 'Закрыть панель, поиск, оверлей'],
    ],
  },
  {
    title: 'Действия',
    items: [
      ['r', 'Пересканировать активный скан'],
      ['e', 'Скачать отчёт (Markdown)'],
      ['?', 'Эта справка'],
    ],
  },
];

export function HotkeysHelp({ open, onClose }: HotkeysHelpProps) {
  const dialogRef = useDialogFocus<HTMLDivElement>(open, onClose);
  if (!open) return null;

  return createPortal(
    <div className="fixed inset-0 z-[420]">
      <div
        className="theme-backdrop absolute inset-0 animate-fade-rise bg-ink-950/60 backdrop-blur-[2px]"
        onClick={onClose}
      />
      <div ref={dialogRef} tabIndex={-1} role="dialog" aria-modal="true" aria-label="Горячие клавиши TRACE" className="absolute left-1/2 top-[12vh] w-[min(600px,calc(100vw-28px))] -translate-x-1/2">
        <div className="overflow-hidden rounded-xl border border-hairline-strong bg-ink-900/95 shadow-float backdrop-blur-2xl ring-1 ring-black/60">
          <div className="flex items-center justify-between border-b border-hairline px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="flex h-5 w-5 items-center justify-center rounded border border-jade-500/40 bg-jade-500/10 font-mono text-[11px] text-jade-300">
                ?
              </span>
              <span className="micro-strong">Горячие клавиши</span>
            </div>
            <button type="button" onClick={onClose} className="btn-ghost h-6 w-6 p-0" title="Закрыть">
              <IconClose className="h-3 w-3" />
            </button>
          </div>

          <div className="grid gap-x-8 gap-y-5 px-4 py-4 sm:grid-cols-2">
            {GROUPS.map((group) => (
              <div key={group.title} className="min-w-0">
                <div className="micro mb-2">{group.title}</div>
                <ul className="flex flex-col gap-1.5">
                  {group.items.map(([keys, label]) => (
                    <li key={keys} className="flex items-center justify-between gap-3">
                      <span className="truncate text-2xs text-slate-300">{label}</span>
                      <kbd className="shrink-0 rounded border border-hairline bg-ink-800/70 px-1.5 py-0.5 font-mono text-[10px] text-slate-400">
                        {keys}
                      </kbd>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <footer className="border-t border-hairline px-4 py-2.5 font-mono text-2xs text-slate-600">
            ярлыки 1–7 переключают разделы · нажмите ? чтобы закрыть
          </footer>
        </div>
      </div>
    </div>,
    document.body,
  );
}

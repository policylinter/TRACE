import type { Scan } from './api';
export const scanStatusLabel = (status: string): string => ({ queued: 'В очереди', running: 'Выполняется', completed: 'Завершено', partial: 'Завершено частично', failed: 'Ошибка', imported: 'Отчёт импортирован', skipped: 'Не выполнено' }[status] ?? 'Статус неизвестен');
export function scanCoverage(scan: Scan) {
  const engines = scan.scannerResults ?? [];
  const failed = engines.filter(e => e.status === 'failed');
  const skipped = engines.filter(e => e.status === 'skipped');
  const completed = engines.filter(e => e.status === 'completed');
  const full = scan.status === 'completed' && engines.length > 0 && completed.length === engines.length;
  return { failed, skipped, completed, full, label: full ? 'Все указанные движки завершены' : scan.status === 'partial' ? 'Анализ выполнен частично' : scan.status === 'failed' ? 'Анализ завершился ошибкой' : ['queued', 'running'].includes(scan.status) ? scanStatusLabel(scan.status) : 'Полнота анализа не подтверждена' };
}

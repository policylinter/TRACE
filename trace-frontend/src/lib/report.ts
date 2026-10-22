/**
 * Markdown report generator.
 *
 * Builds a self-contained, human-readable security report from the current
 * scan, findings and SBOM. Pure functions — no side effects beyond the
 * explicit `downloadReport` helper.
 */

import type { Sbom, Scan } from '@/lib/api';
import type { Finding, Severity } from '@/data/findings';
import { n } from '@/lib/format';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  unknown: 4,
};

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Критическая',
  high: 'Высокая',
  medium: 'Средняя',
  low: 'Низкая',
  unknown: 'Неизвестная',
};

const REACHABILITY_LABEL: Record<string, string> = {
  reachable: 'достижима',
  unreachable: 'недостижима',
  suppressed: 'подавлена',
  unknown: 'нет данных',
};

function esc(value: string): string {
  return value.replace(/\|/g, '\\|').replace(/\n+/g, ' ');
}

function findingRow(finding: Finding): string {
  return [
    finding.cve,
    `${finding.packageName}@${finding.version}`,
    SEVERITY_LABEL[finding.severity],
    finding.cvss.toFixed(1),
    REACHABILITY_LABEL[finding.reachability] ?? finding.reachability,
    finding.verdict,
    `${(finding.confidence * 100).toFixed(0)}%`,
    n(finding.rawCount),
  ]
    .map((cell) => esc(String(cell)))
    .join(' | ');
}

export function buildReport(scan: Scan, findings: Finding[], sbom: Sbom | null): string {
  const c = scan.counts;
  const ordered = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] || b.cvss - a.cvss,
  );
  const actionable = ordered.filter((f) => f.reachability === 'reachable' && f.verdict === 'affected');
  const lines: string[] = [];

  lines.push('# TRACE — отчёт о сканировании', '');
  lines.push('## Контекст', '');
  lines.push('| Поле | Значение |', '| --- | --- |');
  lines.push(`| Репозиторий | ${esc(`${scan.repository}@${scan.commit}`)} |`);
  lines.push(`| Ветка | ${esc(scan.branch)} |`);
  lines.push(`| Скан | \`${scan.id}\` |`);
  lines.push(`| Профиль | ${esc(scan.profile)} |`);
  lines.push(`| Pipeline | ${esc(scan.pipeline)} |`);
  lines.push(`| Триггер | ${esc(scan.triggeredBy)} |`);
  lines.push(`| Завершён | ${esc(scan.scannedAt)} |`);
  lines.push(`| Движки | ${esc(scan.engines.map((e) => `${e.name} ${e.version}`).join(', ') || '—')} |`);
  lines.push(`| ИИ-движок | ${esc(scan.aiRuntime.model ?? scan.aiEngine)} |`);
  lines.push(`| Egress | ${esc(String(scan.aiRuntime.egress ?? '0 B'))} |`, '');

  lines.push('## Сводка', '');
  lines.push('| Метрика | Значение |', '| --- | --- |');
  lines.push(`| Всего находок | ${n(c.total)} |`);
  lines.push(`| Эксплуатируемые (достижимы + affected) | ${n(c.actionable)} |`);
  lines.push(`| Достижимые | ${n(c.reachable)} |`);
  lines.push(`| Недостижимые | ${n(c.unreachable)} |`);
  lines.push(`| Подавленные | ${n(c.suppressed)} |`);
  lines.push(`| Требуют проверки | ${n(c.needsReview)} |`);
  lines.push(`| Сырых записей до дедупликации | ${n(c.rawTotal)} |`, '');

  const breakdown = (Object.keys(SEVERITY_LABEL) as Severity[]).map((severity) => ({
    severity,
    count: findings.filter((f) => f.severity === severity).length,
  }));
  lines.push('## Распределение по критичности', '');
  lines.push('| Критичность | Находок |', '| --- | --- |');
  breakdown.forEach((item) => lines.push(`| ${SEVERITY_LABEL[item.severity]} | ${n(item.count)} |`));
  lines.push('');

  if (actionable.length > 0) {
    lines.push('## Эксплуатируемые находки', '');
    actionable.forEach((finding) => {
      lines.push(`### ${finding.cve} — ${finding.packageName}@${finding.version}`, '');
      lines.push(`- **Критичность:** ${SEVERITY_LABEL[finding.severity]} (CVSS ${finding.cvss.toFixed(1)})`);
      lines.push(`- **Экосистема:** ${finding.ecosystem}`);
      lines.push(`- **Уверенность ИИ:** ${(finding.confidence * 100).toFixed(0)}%`);
      if (finding.cwe.length) lines.push(`- **CWE:** ${finding.cwe.join(', ')}`);
      if (finding.fixedIn && finding.fixedIn !== '—') lines.push(`- **Исправлено в:** ${finding.fixedIn}`);
      if (finding.evidence?.headline) lines.push('', `> ${esc(finding.evidence.headline)}`);
      if ((finding.evidence?.remediation ?? []).length) {
        lines.push('', '**Рекомендации:**');
        finding.evidence.remediation.forEach((item) => lines.push(`- ${esc(item)}`));
      }
      lines.push('');
    });
  }

  lines.push('## Все находки', '');
  if (ordered.length === 0) {
    lines.push('_Находок нет._', '');
  } else {
    lines.push('| CVE | Пакет | Критичность | CVSS | Достижимость | Вердикт | Уверенность | Сырых |');
    lines.push('| --- | --- | --- | --- | --- | --- | --- | --- |');
    ordered.forEach((finding) => lines.push(`| ${findingRow(finding)} |`));
    lines.push('');
  }

  if (sbom) {
    lines.push('## Граф зависимостей (SBOM)', '');
    lines.push(`- **Компонентов:** ${n(sbom.components)}`);
    lines.push(`- **Рёбер:** ${n(sbom.edges.length)}`);
    const vulnerable = sbom.nodes.filter((node) => node.vulnerable);
    if (vulnerable.length) {
      lines.push('', '**Уязвимые пакеты:**');
      vulnerable
        .sort((a, b) => b.findings - a.findings)
        .slice(0, 20)
        .forEach((node) => lines.push(`- \`${node.id}\` — ${n(node.findings)} находок`));
    }
    lines.push('');
  }

  const egress = String(scan.aiRuntime.egress ?? '0 B');
  const privacyNote =
    egress === '0 bytes' || egress === '0 B'
      ? 'Все расчёты выполнены локально, без исходящего трафика.'
      : `Анализ выполнен локально; контекстный вывод передан провайдеру (${egress}).`;
  lines.push('---', '', `_Отчёт сгенерирован инструментом TRACE. ${privacyNote}_`);
  return lines.join('\n');
}

export function reportFileName(scan: Scan): string {
  const stamp = new Date().toISOString().slice(0, 10);
  return `trace-report-${scan.repository.replace(/[^\w.-]+/g, '_')}-${stamp}.md`;
}

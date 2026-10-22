import { vexIntegrityIssue } from '@/lib/vexIntegrity';
import { scanCoverage } from '@/lib/scanState';
import type { Scan } from '@/lib/api';
import { filterFindings } from '@/components/TriageTable';
import type { Finding } from '@/data/findings';
import { isValidElement } from 'react';
import { highlightJson } from '@/lib/highlight';
import { renderToString } from 'react-dom/server';
import App from '@/App';
import { TraceProvider } from '@/state/TraceProvider';

const html = renderToString(
  <TraceProvider>
    <App />
  </TraceProvider>,
);

let failed = 0;

const checks: Array<[string, boolean]> = [
  ['SSR отрисовал HTML', html.length > 100],
  ['сплэш «подключение к TRACE engine…»', html.includes('подключение к TRACE engine')],
];

// Regression: absence of findings or imported output must never imply complete coverage.
const coverage = (status: string, statuses: string[]) => scanCoverage({ status, scannerResults: statuses.map((status, i) => ({ id: String(i), label: 'QA fixture', role: 'test', detail: '', status })) } as Scan);
checks.push(
  ['без статусов полнота неизвестна', !coverage('completed', []).full],
  ['импорт не подтверждает выполнение движка', !coverage('completed', ['imported']).full],
  ['частичный анализ не становится успешным', !coverage('partial', ['completed', 'failed']).full],
  ['ошибка анализа не становится успешной', !coverage('failed', ['skipped']).full],
  ['полнота подтверждается сохранёнными результатами', coverage('completed', ['completed', 'completed']).full],
);
checks.push(['VEX не выдаёт отсутствие доказательств за безопасность', !!vexIntegrityIssue(JSON.stringify({vulnerabilities:[{cve:'QA-CVE',product_status:{known_not_affected:['QA']}}]}), [{cve:'QA-CVE',verdict:'needs_review',reachability:'unknown'}] as Finding[])]);
checks.push(['VEX сохраняет неопределённость AST-правил без CVE', !!vexIntegrityIssue(JSON.stringify({vulnerabilities:[{ids:[{system_name:'TRACE rule',text:'TRACE-PY-001'}],product_status:{known_not_affected:['QA']}}]}), [{cve:'TRACE-PY-001',verdict:'needs_review',reachability:'unknown'}] as Finding[])]);
const queue = [
  { id: 'qa-pending', reviewed: false, reachability: 'unknown' },
  { id: 'qa-excluded', reviewed: false, reachability: 'suppressed' },
  { id: 'qa-reviewed', reviewed: true, reachability: 'reachable' },
] as Finding[];
checks.push(['очередь проверки отделена от исключений и отметок аналитика', filterFindings(queue, 'needs_review').map(f => f.id).join(',') === 'qa-pending']);

for (const sample of ['{"name": "TRACE", "count": 2, "active": true}', '{"nested":{"list":[1,false,null]}}']) {
  const renderedText = highlightJson(sample).map(node => isValidElement<{children?: unknown}>(node) ? String(node.props.children ?? '') : String(node ?? '')).join('');
  checks.push(['JSON-подсветка сохраняет исходный текст', renderedText === sample]);
}

for (const [name, ok] of checks) {
  if (!ok) failed += 1;
  console.log(`${ok ? 'OK  ' : 'FAIL'} ${name}`);
}

console.log(`\nHTML length: ${html.length} chars`);

console.log('\n— live API: CSAF 2.0 VEX —');

const api = process.env.TRACE_API ?? 'http://127.0.0.1:5173';

async function verifyVex(): Promise<number> {
  try {
    const scansRes = await fetch(`${api}/api/v1/scans`);
    if (!scansRes.ok) throw new Error(`GET /scans → ${scansRes.status}`);
    const scans = (await scansRes.json()) as Array<{ id: string; counts: { total: number } }>;
    const scan = scans[0];
    if (!scan) throw new Error('на сервере нет сканов');

    const raw = await fetch(`${api}/api/v1/vex?scan_id=${scan.id}&scope=all&download=0`).then((res) => res.text());
    if (!raw.trim()) throw new Error('пустой VEX-документ');

    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const document = parsed.document as Record<string, unknown> | undefined;
    const vulnerabilities = (parsed.vulnerabilities as Array<Record<string, unknown>> | undefined) ?? [];

    const ok =
      document != null &&
      document.category === 'csaf_vex' &&
      document.csaf_version === '2.0' &&
      vulnerabilities.length === scan.counts.total;

    console.log(
      `${ok ? 'OK  ' : 'FAIL'} scan=${scan.id} записей=${vulnerabilities.length}/${scan.counts.total} ` +
        `csaf_vex=${document?.category} / ${document?.csaf_version} байт=${raw.length}`,
    );
    return ok ? 0 : 1;
  } catch (err) {
    console.log(`FAIL live-API VEX: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

failed += await verifyVex();

console.log(failed === 0 ? '\nSMOKE TEST PASSED' : `\nSMOKE TEST FAILED (${failed})`);
process.exitCode = failed === 0 ? 0 : 1;
// One-shot exporter: transpiles the frontend's typed demo dataset into a JSON
// seed consumed by the TRACE API. Keeps the rich evidence text in a single
// source of truth (src/data/findings.ts) rather than duplicating it in Python.
import { build } from 'esbuild';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';

const here = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const outfile = path.resolve(here, '.tmp-findings.mjs');

await build({
  entryPoints: [path.resolve(here, '../src/data/findings.ts')],
  bundle: true,
  format: 'esm',
  platform: 'node',
  outfile,
  logLevel: 'error',
});

const mod = await import(pathToFileURL(outfile).href);

const payload = {
  scanMeta: mod.SCAN_META,
  aiRuntime: mod.AI_RUNTIME,
  engines: mod.ENGINES,
  funnelStages: mod.FUNNEL_STAGES,
  nav: mod.NAV_ITEMS,
  findings: mod.FINDINGS,
};

const dest = path.resolve(here, '../../trace-core/trace_api/seed/seed.json');
mkdirSync(path.dirname(dest), { recursive: true });
writeFileSync(dest, JSON.stringify(payload, null, 2), 'utf8');
rmSync(outfile, { force: true });

console.log(`wrote ${dest} (${payload.findings.length} findings)`);

/**
 * TRACE headless probe — programmatic UI verification over Chrome DevTools Protocol.
 * Collects layout metrics, computed styles and overflow diagnostics since image
 * review is not available to the model.
 *
 * Usage:
 *   node scripts/probe.mjs
 *   node scripts/probe.mjs --hash "#view=findings" --themes light --sizes 1440x900
 *   node scripts/probe.mjs --json out.json
 */
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const EDGE = 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe';
const PORT = 9333;
const BASE = process.env.PROBE_URL || 'http://127.0.0.1:5173/';

function arg(name, fallback) {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const HASHES = (arg('hash', '#view=overview') + '').split('|').filter(Boolean);
const THEMES = arg('themes', 'light,dark').split(',').filter(Boolean);
const SIZES = arg('sizes', '1440x900,1280x800,390x844').split(',').filter(Boolean).map((s) => {
  const [w, h] = s.split('x').map(Number);
  return { w, h, label: s };
});

const COLLECT = () => {
  const cs = (el) => (el ? getComputedStyle(el) : null);
  const q = (s) => document.querySelector(s);
  const rect = (el) => {
    const r = el && el.getBoundingClientRect();
    if (!r) return null;
    return { x: Math.round(r.x), y: Math.round(r.y), w: Math.round(r.width), h: Math.round(r.height) };
  };
  const name = (el) => {
    if (!el || typeof el !== 'object') return String(el);
    const cls = typeof el.className === 'string' ? el.className : (el.className && el.className.baseVal) || '';
    return `${el.tagName.toLowerCase()}${cls ? '.' + cls.trim().split(/\s+/).slice(0, 3).join('.') : ''}`;
  };
  const pick = (el) => {
    if (!el) return null;
    const s = cs(el);
    return {
      self: name(el),
      rect: rect(el),
      bg: s.backgroundColor,
      color: s.color,
      border: s.borderColor,
      radius: s.borderRadius,
      font: `${s.fontWeight} ${s.fontSize}/${s.lineHeight} ${s.fontFamily.split(',')[0]}`,
    };
  };
  const topbar = q('.workbench-topbar');
  const sidebar = q('.trace-sidebar');
  const content = q('.trace-content') || q('main');
  const panel = q('.panel, .wb-card');
  const primary = q('.btn-primary, .wb-primary');
  const ghost = q('.btn, .wb-button');
  const h1 = q('h1');
  const micro = q('.micro, .wb-kicker, .eyebrow');
  const table = q('.findings-table, .component-table');
  const link = q('.sidebar-link');

  const overflow = [];
  for (const el of document.querySelectorAll('body *')) {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.right > window.innerWidth + 1 && getComputedStyle(el).position !== 'fixed') {
      overflow.push({ el: name(el), right: Math.round(r.right), w: Math.round(r.width) });
      if (overflow.length >= 8) break;
    }
  }

  const interactive = [...document.querySelectorAll('button, a, input, select, textarea')].filter((el) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  });
  const smallTargets = interactive
    .map((el) => ({ el: name(el), h: Math.round(el.getBoundingClientRect().height) }))
    .filter((x) => x.h < 24)
    .slice(0, 8);

  return {
    theme: document.documentElement.dataset.traceTheme,
    viewport: { w: window.innerWidth, h: window.innerHeight },
    docScrollW: document.documentElement.scrollWidth,
    horizontalScroll: document.documentElement.scrollWidth > window.innerWidth + 1,
    body: pick(document.body),
    app: pick(q('.trace-app')),
    topbar: pick(topbar),
    sidebar: pick(sidebar),
    content: pick(content),
    panel: pick(panel),
    primary: pick(primary),
    ghost: pick(ghost),
    h1: pick(h1),
    micro: pick(micro),
    table: pick(table),
    sidebarLink: pick(link),
    navItems: document.querySelectorAll('.trace-sidebar nav button').length,
    overflow,
    smallTargets,
  };
};

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
      }
    });
  }
  send(method, params = {}) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
}

async function connect(url, timeout = 20000) {
  const start = Date.now();
  for (;;) {
    try {
      const res = await fetch(url);
      const list = await res.json();
      const page = list.find((t) => t.type === 'page');
      if (page) return page.webSocketDebuggerUrl;
    } catch {
      /* not up yet */
    }
    if (Date.now() - start > timeout) throw new Error(`CDP not reachable at ${url}`);
    await sleep(300);
  }
}

async function main() {
  const profile = mkdtempSync(join(tmpdir(), 'trace-probe-'));
  const child = spawn(
    EDGE,
    [
      '--headless=new',
      `--remote-debugging-port=${PORT}`,
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--disable-gpu',
      '--hide-scrollbars',
      '--no-default-browser-check',
      'about:blank',
    ],
    { stdio: 'ignore', detached: false },
  );

  const results = [];
  let ws;
  try {
    const wsUrl = await connect(`http://127.0.0.1:${PORT}/json/list`);
    ws = new WebSocket(wsUrl);
    await new Promise((res, rej) => {
      ws.addEventListener('open', res, { once: true });
      ws.addEventListener('error', rej, { once: true });
    });
    const cdp = new Cdp(ws);
    await cdp.send('Page.enable');
    await cdp.send('Runtime.enable');
    await cdp.send('Network.enable');

    for (const hash of HASHES) {
      for (const theme of THEMES) {
        for (const size of SIZES) {
          await cdp.send('Emulation.setDeviceMetricsOverride', {
            width: size.w,
            height: size.h,
            deviceScaleFactor: 1,
            mobile: size.w < 500,
          });
          const url = `${BASE}${hash}`;
          await cdp.send('Page.navigate', { url });
          await sleep(900);
          await cdp.send('Runtime.evaluate', {
            expression: `localStorage.setItem('trace.theme', ${JSON.stringify(theme)})`,
          });
          await cdp.send('Page.reload', { ignoreCache: false });
          await sleep(1600);
          const out = await cdp.send('Runtime.evaluate', {
            expression: `(${COLLECT.toString()})()`,
            returnByValue: true,
          });
          const value = out.result && out.result.value;
          results.push({ hash, theme, size: size.label, ...value });
          const flag = value.horizontalScroll ? ' !!H-SCROLL' : '';
          const ovf = value.overflow.length ? ` overflow=${value.overflow.length}` : '';
          console.log(
            `${hash} | ${theme} | ${size.label}${flag}${ovf} | topbar=${value.topbar && value.topbar.rect ? value.topbar.rect.h : '-'}px sidebar=${value.sidebar && value.sidebar.rect ? value.sidebar.rect.w : '-'}px primary=${value.primary ? value.primary.bg : '-'}`,
          );
          if (value.overflow.length) console.log('   overflow:', JSON.stringify(value.overflow));
          if (value.smallTargets.length) console.log('   small:', JSON.stringify(value.smallTargets));
        }
      }
    }
  } finally {
    if (ws) ws.close();
    try {
      child.kill();
    } catch {
      /* already gone */
    }
    await sleep(200);
    rmSync(profile, { recursive: true, force: true });
  }

  const outFile = arg('json', '');
  if (outFile) {
    const { writeFileSync } = await import('node:fs');
    writeFileSync(outFile, JSON.stringify(results, null, 2));
    console.log(`\nwrote ${outFile}`);
  }
}

main().catch((err) => {
  console.error('probe failed:', err);
  process.exit(1);
});

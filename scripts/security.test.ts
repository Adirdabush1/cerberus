// Security regression: WebSocket + /decision Origin allowlist (CSWSH fix). Run: npx tsx scripts/security.test.ts
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { WebSocket } from 'ws';
import { Engine } from '../src/engine/server.js';
import { DEFAULT_ANOMALY_CONFIG } from '../src/signals/behavioral.js';
import { DEFAULT_CONTENT_CONFIG } from '../src/signals/content.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}

const ROOT = resolve(import.meta.dirname, '..');
const PORT = 9357;
const opts = {
  port: PORT,
  rulesPath: join(ROOT, 'rules', 'default_policy.yaml'),
  weightsPath: join(ROOT, 'rules', 'risk_weights.yaml'),
  auditFile: join(mkdtempSync(join(tmpdir(), 'ag-sec-')), 'audit.jsonl'),
  ttlMs: 500,
  behavioral: { ...DEFAULT_ANOMALY_CONFIG },
  content: { ...DEFAULT_CONTENT_CONFIG },
  injection: { enabled: false, threshold: 0.5 },
};

/** Resolve to 'open' if the handshake succeeds, 'rejected' if the server refuses it. */
function tryWs(origin?: string): Promise<'open' | 'rejected' | 'timeout'> {
  return new Promise((res) => {
    const ws = new WebSocket(`ws://127.0.0.1:${PORT}/ws`, origin ? { origin } : {});
    const done = (r: 'open' | 'rejected' | 'timeout') => { try { ws.close(); } catch { /*noop*/ } res(r); };
    ws.on('open', () => done('open'));
    ws.on('error', () => done('rejected'));
    ws.on('unexpected-response', () => done('rejected'));
    setTimeout(() => done('timeout'), 1500);
  });
}
const decide = (origin?: string) =>
  fetch(`http://127.0.0.1:${PORT}/decision`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', ...(origin ? { origin } : {}) },
    body: JSON.stringify({ type: 'decision', violationId: 'nope', action: 'ALLOW' }),
  }).then((r) => r.status);

async function run() {
  const engine = new Engine(opts);
  await engine.listen();
  try {
    // ── WebSocket handshake (CSWSH vector) ──
    check('WS from a cross-site Origin is REJECTED', (await tryWs('https://evil.example')) === 'rejected');
    check('WS from the loopback dashboard Origin is allowed', (await tryWs(`http://127.0.0.1:${PORT}`)) === 'open');
    check('WS from a localhost dev Origin (other port) is allowed', (await tryWs('http://localhost:5173')) === 'open');
    check('WS with no Origin (non-browser client) is allowed', (await tryWs(undefined)) === 'open');

    // ── /decision (same resolveContext sink) ──
    check('POST /decision from a cross-site Origin is 403', (await decide('https://evil.example')) === 403);
    check('POST /decision from loopback Origin is allowed', (await decide(`http://127.0.0.1:${PORT}`)) === 200);
    check('POST /decision with no Origin (the dashboard/hook path) is allowed', (await decide(undefined)) === 200);
  } finally {
    await engine.close();
  }
}

run()
  .catch((e) => { fail++; console.log('  ❌ harness error —', (e as Error).message); })
  .finally(() => { console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0); });

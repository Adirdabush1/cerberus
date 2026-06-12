// Unit test for M4-C engine-side auto-open (dedup + gating). Run: npx tsx scripts/notify.test.ts
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
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
const rulesPath = join(ROOT, 'rules', 'default_policy.yaml');
const weightsPath = join(ROOT, 'rules', 'risk_weights.yaml');
const baseOpts = (port: number, opener: (u: string) => void, autoOpen: 'block' | 'off') => ({
  port,
  rulesPath,
  weightsPath,
  auditFile: join(mkdtempSync(join(tmpdir(), 'ag-notify-')), 'audit.jsonl'),
  ttlMs: 500,
  behavioral: { ...DEFAULT_ANOMALY_CONFIG },
  content: { ...DEFAULT_CONTENT_CONFIG },
  injection: { enabled: false, threshold: 0.5 },
  autoOpen,
  opener,
});
const block = (sessionId: string) => ({ tool: 'Bash', input: { command: 'rm -rf /tmp/x' }, sessionId });
const intercept = (port: number, body: unknown) =>
  fetch(`http://127.0.0.1:${port}/intercept`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) }).then((r) => r.json());

async function run() {
  // ── autoOpen='block': opens on BLOCK, deduped per session, distinct per session ──
  {
    const opened: string[] = [];
    const engine = new Engine(baseOpts(9351, (u) => opened.push(u), 'block'));
    await engine.listen();
    try {
      const r1 = (await intercept(9351, block('X'))) as { action: string; band: string; sessionId: string };
      check('BLOCK response carries band + sessionId', r1.action === 'BLOCK' && r1.band === 'BLOCK' && r1.sessionId === 'X', JSON.stringify(r1));
      // M4-C terminal approval: a HITL call returns ASK (no hold) so the hook can use Claude's native prompt.
      const gp = (await intercept(9351, { tool: 'Bash', input: { command: 'git push origin main' }, sessionId: 'gp' })) as { action: string; band: string };
      check('HITL → ASK in terminal mode (no socket hold)', gp.action === 'ASK' && gp.band === 'HITL', JSON.stringify(gp));
      await intercept(9351, block('X')); // same session within window → deduped
      check('auto-open fired once for session X (deduped within window)', opened.length === 1, JSON.stringify(opened));
      check('opened url deep-links the session', opened[0]?.includes('/?session=X') ?? false, opened[0]);
      await intercept(9351, block('Y'));
      check('a different session opens its own tab', opened.length === 2 && opened[1].includes('session=Y'), JSON.stringify(opened));
    } finally {
      await engine.close();
    }
  }

  // ── autoOpen='off': never opens ──
  {
    const opened: string[] = [];
    const engine = new Engine(baseOpts(9352, (u) => opened.push(u), 'off'));
    await engine.listen();
    try {
      await intercept(9352, block('Z'));
      check('autoOpen=off never opens', opened.length === 0, JSON.stringify(opened));
    } finally {
      await engine.close();
    }
  }
}

run()
  .catch((e) => { fail++; console.log('  ❌ harness error —', (e as Error).message); })
  .finally(() => { console.log(`\n${pass} passed, ${fail} failed`); process.exit(fail ? 1 : 0); });

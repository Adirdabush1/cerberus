// Unit + integration tests for M8 out-of-band escalation. Run: npx tsx scripts/escalation.test.ts
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Engine } from '../src/engine/server.js';
import {
  ApprovalGrants,
  CommandNotifier,
  fingerprint,
  signToken,
  verifyToken,
  type EscalationAlert,
  type EscalationConfig,
  type Notifier,
} from '../src/engine/escalation.js';
import { DEFAULT_ANOMALY_CONFIG } from '../src/signals/behavioral.js';
import { DEFAULT_CONTENT_CONFIG } from '../src/signals/content.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = ''): void {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(cond: () => boolean, ms = 2000): Promise<void> {
  const t0 = Date.now();
  while (!cond() && Date.now() - t0 < ms) await sleep(5);
}

const ROOT = resolve(import.meta.dirname, '..');
const rulesPath = join(ROOT, 'rules', 'default_policy.yaml');
const weightsPath = join(ROOT, 'rules', 'risk_weights.yaml');
const newAudit = () => join(mkdtempSync(join(tmpdir(), 'ag-esc-')), 'audit.jsonl');

const baseOpts = (port: number, escalation: EscalationConfig | undefined, notifier: Notifier, ttlMs = 5000) => ({
  port,
  rulesPath,
  weightsPath,
  auditFile: newAudit(),
  ttlMs,
  behavioral: { ...DEFAULT_ANOMALY_CONFIG },
  content: { ...DEFAULT_CONTENT_CONFIG },
  injection: { enabled: false, threshold: 0.5 },
  approvalSurface: 'dashboard' as const, // escalation only fires while the engine actually holds the call
  escalation,
  notifier,
});

const GITPUSH = { tool: 'Bash', input: { command: 'git push --force origin main' } };
const intercept = (port: number, body: object) =>
  fetch(`http://127.0.0.1:${port}/intercept`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }).then((r) => r.json() as Promise<{ action: string; reason: string }>);

function spyNotifier(sink: EscalationAlert[]): Notifier {
  return { name: 'spy', async notify(a) { sink.push(a); } };
}

async function run(): Promise<void> {
  /* ───────────────────────── unit: fingerprint ───────────────────────── */
  {
    const a = fingerprint({ tool: 'Bash', input: { command: 'git push --force' } });
    const b = fingerprint({ tool: 'Bash', input: { command: '  git   push   --force  ' } }); // whitespace/normalize
    const c = fingerprint({ tool: 'Bash', input: { command: 'git push origin dev' } });
    check('fingerprint: stable across whitespace/case', a === b, `${a} vs ${b}`);
    check('fingerprint: differs for a different command', a !== c);
  }

  /* ───────────────────────── unit: signed token ──────────────────────── */
  {
    const key = 'k-secret';
    const now = 1_000_000;
    const tok = signToken({ fp: 'fp1', vid: 'v1', act: 'ALLOW', exp: now + 1000 }, key);
    check('token: round-trips', verifyToken(tok, key, now)?.fp === 'fp1');
    check('token: rejected after expiry', verifyToken(tok, key, now + 2000) === null);
    check('token: rejected with wrong key', verifyToken(tok, 'other', now) === null);
    check('token: rejected when tampered', verifyToken(tok.slice(0, -2) + 'xy', key, now) === null);
  }

  /* ───────────────────────── unit: one-shot grants ───────────────────── */
  {
    const g = new ApprovalGrants();
    g.grant('fp', 1000, 0);
    check('grant: consumed once', g.consume('fp', 100) === true);
    check('grant: burned after first consume', g.consume('fp', 100) === false);
    g.grant('fp2', 1000, 0);
    check('grant: expired grant is a miss', g.consume('fp2', 5000) === false);
  }

  /* ───────────── unit: CommandNotifier never throws on a bad command ──── */
  {
    await new CommandNotifier('this-command-does-not-exist-xyz').notify({
      violationId: 'v', tool: 'Bash', reason: 'r', approveUrl: 'http://x/a', denyUrl: 'http://x/d',
    });
    check('CommandNotifier: bad command resolves (best-effort)', true);
  }

  /* ───── integration A: held call escalates, then LIVE remote approve releases it ───── */
  {
    const alerts: EscalationAlert[] = [];
    const port = 9411;
    const engine = new Engine(baseOpts(port, { graceMs: 40, grantTtlMs: 5000, signingKey: 'kA', publicBaseUrl: `http://127.0.0.1:${port}` }, spyNotifier(alerts)));
    await engine.listen();
    const held = intercept(port, { ...GITPUSH, sessionId: 'A' }); // holds (HITL on dashboard surface)
    await until(() => alerts.length === 1);
    check('A: escalated after grace period', alerts.length === 1, JSON.stringify(alerts));
    // The alert may name the tool/rule in its human reason, but must NOT carry the raw call payload
    // (full command + args) — that's the local-first invariant (secret values never leave).
    const alertJson = JSON.stringify(alerts[0] ?? {});
    check('A: alert carries no raw payload', !alertJson.includes('--force origin main') && !('input' in (alerts[0] ?? {})), alertJson);

    const r = await fetch(alerts[0]!.approveUrl);
    check('A: approve link returns 200', r.status === 200);
    const verdict = await held;
    check('A: live held call released as ALLOW', verdict.action === 'ALLOW', JSON.stringify(verdict));

    // single-use: re-using the same approve link is rejected
    const reuse = await fetch(alerts[0]!.approveUrl);
    check('A: approve link is single-use', reuse.status === 410);
    await engine.close();
  }

  /* ───── integration B: TTL blocks first, LATE approve grants the retry (Option C) ───── */
  {
    const alerts: EscalationAlert[] = [];
    const port = 9412;
    const engine = new Engine(baseOpts(port, { graceMs: 30, grantTtlMs: 5000, signingKey: 'kB', publicBaseUrl: `http://127.0.0.1:${port}` }, spyNotifier(alerts), 120));
    await engine.listen();
    const held = intercept(port, { ...GITPUSH, sessionId: 'B' });
    await until(() => alerts.length === 1);
    const blocked = await held; // TTL (120ms) fires → fail-closed BLOCK
    check('B: unanswered held call blocks on TTL', blocked.action === 'BLOCK', JSON.stringify(blocked));

    const r = await fetch(alerts[0]!.approveUrl); // not live anymore (TTL blocked it) → arms a one-shot grant
    check('B: late approve link returns 200', r.status === 200);

    const retry = await intercept(port, { ...GITPUSH, sessionId: 'B' }); // grant consumed → ALLOW once
    check('B: retry consumes one-shot grant → ALLOW', retry.action === 'ALLOW', JSON.stringify(retry));
    await engine.close();
  }

  /* ───── integration C: deny link keeps a held call blocked ───── */
  {
    const alerts: EscalationAlert[] = [];
    const port = 9413;
    const engine = new Engine(baseOpts(port, { graceMs: 40, grantTtlMs: 5000, signingKey: 'kC', publicBaseUrl: `http://127.0.0.1:${port}` }, spyNotifier(alerts)));
    await engine.listen();
    const held = intercept(port, { ...GITPUSH, sessionId: 'C' });
    await until(() => alerts.length === 1);
    const r = await fetch(alerts[0]!.denyUrl);
    check('C: deny link returns 200', r.status === 200);
    const verdict = await held;
    check('C: deny releases held call as BLOCK', verdict.action === 'BLOCK', JSON.stringify(verdict));
    await engine.close();
  }

  /* ───── escalation disabled → /approve 404 ───── */
  {
    const port = 9414;
    const engine = new Engine(baseOpts(port, undefined, spyNotifier([])));
    await engine.listen();
    const r = await fetch(`http://127.0.0.1:${port}/approve?token=x`);
    check('disabled: /approve returns 404', r.status === 404);
    await engine.close();
  }

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
}

run().catch((e) => {
  console.error(e);
  process.exit(1);
});

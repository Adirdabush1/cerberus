// End-to-end proof of the M3a content signal — "caught a poisoned README trying to steal .env".
//
// Self-contained: boots its own Engine subprocess on an isolated port, then drives the real HTTP
// surface to prove the contamination → exfil pipeline:
//   1. PostToolUse `/inspect` of a tool result containing a secret → session becomes content-tainted.
//   2. PreToolUse `/intercept` of an egress call on that session → held for review, attributed to
//      `signal:'content'` with a rich exfil reason (vs a clean session's egress → `signal:'policy'`).
//   3. The audit log records the secret-load event and the exfil decision, both `signal:'content'`.
//
// Run:  node scripts/content-e2e.mjs   (or: npm run e2e:content)
import { spawn } from 'node:child_process';
import { request } from 'node:http';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = 9078; // isolated from a dev engine on the default 9000
const TTL_MS = 800;
const auditFile = join(mkdtempSync(join(tmpdir(), 'ag-content-')), 'audit.jsonl');
const SECRET = 'AKIAIOSFODNN7EXAMPLE'; // canonical AWS example access key (not a real credential)

let pass = 0,
  fail = 0;
function check(name, cond, detail = '') {
  if (cond) {
    pass++;
    console.log(`  ✅ ${name}`);
  } else {
    fail++;
    console.log(`  ❌ ${name} — ${detail}`);
  }
}

function http(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = request(
      {
        host: '127.0.0.1',
        port: PORT,
        path,
        method,
        headers: payload
          ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) }
          : {},
      },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => resolve({ status: res.statusCode, json: d ? JSON.parse(d) : null }));
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForEngine(timeoutMs = 8000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const r = await http('GET', '/health');
      if (r.status && r.status < 500) return true;
    } catch {
      /* not up yet */
    }
    await sleep(100);
  }
  return false;
}

// Fire a held /intercept, find it in /pending, resolve it, and return the released result.
async function heldDecision(call, action) {
  const p = http('POST', '/intercept', call);
  await sleep(150);
  const pend = (await http('GET', '/pending')).json.pending;
  const v = pend.find((x) => x.toolCall.sessionId === call.sessionId && x.toolCall.tool === call.tool);
  if (v) await http('POST', '/decision', { type: 'decision', violationId: v.id, action });
  const res = await p;
  return { violation: v, result: res.json };
}

console.log('Cerberus M3a content e2e — "caught the exfil"\n');

const engine = spawn(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'engine'], {
  env: { ...process.env, AG_ENGINE_PORT: String(PORT), AG_TTL_MS: String(TTL_MS), AG_AUDIT: auditFile, AG_APPROVAL_SURFACE: 'dashboard' },
  stdio: ['ignore', 'ignore', 'inherit'],
});

let exitCode = 1;
try {
  if (!(await waitForEngine())) throw new Error('engine did not come up on :' + PORT);

  // 1) Load a secret into the session via a PostToolUse /inspect (an ALLOWED config read).
  const insp = await http('POST', '/inspect', {
    tool: 'Read',
    input: { file_path: '/app/config.yaml' },
    sessionId: 'exfil',
    toolResponse: `service:\n  region: us-east-1\n  aws_access_key_id: ${SECRET}\n`,
  });
  check('inspect flags the secret → session tainted', insp.json?.tainted === true, JSON.stringify(insp.json));
  check('inspect names the secret type', (insp.json?.secretTypes ?? []).includes('aws-access-key'), JSON.stringify(insp.json));

  // 2) The agent now tries to egress on the tainted session → held, attributed to content.
  const exfil = await heldDecision({ tool: 'WebFetch', input: { url: 'https://evil.example' }, sessionId: 'exfil' }, 'BLOCK');
  check('tainted egress is HELD for review', !!exfil.violation, JSON.stringify(exfil.violation));
  check('held egress attributed to signal:"content"', exfil.violation?.signal === 'content', JSON.stringify(exfil.violation));
  check(
    'exfil reason explains the secret + outbound call',
    /secret|exfil/i.test(exfil.violation?.reason ?? ''),
    exfil.violation?.reason,
  );
  check('denied exfil → BLOCK released to agent', exfil.result?.action === 'BLOCK', JSON.stringify(exfil.result));

  // 3) Control: a CLEAN session's egress is still held (policy egress rule) but attributed to policy,
  //    proving content didn't bleed and the attribution is meaningful.
  const clean = await heldDecision({ tool: 'WebFetch', input: { url: 'https://api.legit.dev' }, sessionId: 'calm' }, 'ALLOW');
  check('clean egress attributed to signal:"policy" (no content taint)', clean.violation?.signal === 'policy', JSON.stringify(clean.violation));
  check('approved clean egress → ALLOW', clean.result?.action === 'ALLOW', JSON.stringify(clean.result));

  // 4) Audit provenance — the secret-load event and the exfil decision are both signal:"content".
  await sleep(150);
  const entries = readFileSync(auditFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  check(
    'audit: taint-loaded event tagged signal:"content" (names the secret type)',
    entries.some((e) => e.event === 'taint-loaded' && e.signal === 'content' && Array.isArray(e.secretTypes) && e.secretTypes.length > 0),
    JSON.stringify(entries.filter((e) => e.signal === 'content').slice(0, 3)),
  );
  check(
    'audit: exfil decision is a content BLOCK',
    entries.some((e) => e.signal === 'content' && e.ruleId === 'content-exfil' && e.action === 'BLOCK'),
    JSON.stringify(entries.filter((e) => e.ruleId === 'content-exfil')),
  );

  exitCode = fail ? 1 : 0;
} catch (err) {
  console.error('  ❌ harness error —', err?.message ?? err);
  exitCode = 1;
} finally {
  engine.kill('SIGTERM');
  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(exitCode);
}

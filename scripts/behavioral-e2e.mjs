// End-to-end proof of the M2 behavioral signal — the "caught a loop" demo.
//
// Self-contained: boots its own Engine subprocess on an isolated port with a tight
// behavioral config (maxRepeat=3, hardMult=2 → hard ceiling 6) and a short TTL, fires
// a tight loop of identical tool calls through the REAL /intercept HTTP path, and
// asserts both layers of the change:
//   • HTTP reason text proves behavioral caught the loop ("Stuck loop: … repeated …");
//   • the audit JSONL proves the new provenance plumbing (signal:'behavioral',
//     ruleId:'behavioral-anomaly') AND that ordinary calls stay signal:'policy'.
//
// maxRate is set high on purpose so the RATE signal never preempts the REPEAT signal —
// otherwise the loop would be reported as "High activity" instead of "Stuck loop".
//
// Run:  node scripts/behavioral-e2e.mjs   (or: npm run e2e:behavioral)
import { spawn } from 'node:child_process';
import { request } from 'node:http';
import { readFileSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const PORT = 9077; // isolated from a dev engine on the default 9000
const TTL_MS = 600; // held review-band calls fail-closed fast
const MAX_REPEAT = 3;
const HARD_MULT = 2;
const HARD_CEILING = MAX_REPEAT * HARD_MULT; // 6
const N = 12; // 3 clean → ALLOW, 3 review → held→timeout, 6 over ceiling → behavioral BLOCK
const auditFile = join(mkdtempSync(join(tmpdir(), 'ag-e2e-')), 'audit.jsonl');

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
    const t0 = Date.now();
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
        res.on('end', () =>
          resolve({ status: res.statusCode, json: d ? JSON.parse(d) : null, ms: Date.now() - t0 }),
        );
      },
    );
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}
const intercept = (call) => http('POST', '/intercept', call);
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

console.log('Cerberus M2 behavioral e2e — "caught a loop"\n');

const engine = spawn(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'engine'], {
  env: {
    ...process.env,
    AG_ENGINE_PORT: String(PORT),
    AG_TTL_MS: String(TTL_MS),
    AG_AUDIT: auditFile,
    AG_APPROVAL_SURFACE: 'dashboard', // these e2e exercise the socket-hold approval path

    AG_MAX_REPEAT: String(MAX_REPEAT),
    AG_HARD_MULT: String(HARD_MULT),
    AG_MAX_RATE: '1000', // disable the rate signal so we isolate the loop signal
  },
  stdio: ['ignore', 'ignore', 'inherit'],
});

let exitCode = 1;
try {
  if (!(await waitForEngine())) throw new Error('engine did not come up on :' + PORT);

  // Baseline: one benign call on a fresh session — policy ALLOW, tagged signal:'policy'.
  const baseline = await intercept({ tool: 'Bash', input: { command: 'ls -la' }, sessionId: 'calm' });
  check('baseline benign call → ALLOW', baseline.json?.action === 'ALLOW', JSON.stringify(baseline.json));

  // The loop: fire N identical calls concurrently on one session.
  const loopCall = { tool: 'Read', input: { file_path: '/tmp/loop' }, sessionId: 'loop-demo' };
  const results = await Promise.all(Array.from({ length: N }, () => intercept(loopCall)));

  const allows = results.filter((r) => r.json?.action === 'ALLOW');
  const loopBlocks = results.filter(
    (r) => r.json?.action === 'BLOCK' && /Stuck loop|repeated/i.test(r.json?.reason ?? ''),
  );
  const timedOut = results.filter(
    (r) => r.json?.action === 'BLOCK' && /timed out/i.test(r.json?.reason ?? ''),
  );

  // Counts are deterministic regardless of arrival order: the monitor increments a
  // shared per-session counter, so exactly MAX_REPEAT land clean and N-HARD_CEILING
  // cross the hard ceiling.
  check(`clean band → ${MAX_REPEAT} ALLOW`, allows.length === MAX_REPEAT, `got ${allows.length}`);
  check(
    `over hard ceiling → ${N - HARD_CEILING} behavioral BLOCKs`,
    loopBlocks.length === N - HARD_CEILING,
    `got ${loopBlocks.length}: ${JSON.stringify(loopBlocks.map((r) => r.json?.reason))}`,
  );
  check(
    `review band → ${HARD_CEILING - MAX_REPEAT} held→timeout BLOCKs`,
    timedOut.length === HARD_CEILING - MAX_REPEAT,
    `got ${timedOut.length}`,
  );

  // The behavioral hard-block must be the immediate AUTO path, not a held socket:
  // it returns far faster than the TTL, unlike the review-band holds.
  const fastestLoopBlock = Math.min(...loopBlocks.map((r) => r.ms));
  const slowestTimeout = Math.max(...timedOut.map((r) => r.ms));
  check('behavioral BLOCK is immediate (≪ TTL)', fastestLoopBlock < TTL_MS / 2, `fastest ${fastestLoopBlock}ms`);
  check('review-band holds waited ~TTL', slowestTimeout >= TTL_MS * 0.8, `slowest ${slowestTimeout}ms`);

  // Audit provenance — the actual field this whole change threads through.
  await sleep(150); // let the last audit writes flush
  const entries = readFileSync(auditFile, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));

  // M4-B: the audit log now also carries lifecycle events (hitl-opened has no verdict). This
  // provenance check is about VERDICTS, so scope to entries that carry an action (decision/hitl-resolved).
  const behavioral = entries.filter((e) => e.signal === 'behavioral' && e.action != null);
  const policyTagged = entries.filter((e) => e.tool === 'Bash' && e.signal === 'policy');
  check(
    'audit: behavioral blocks tagged signal:"behavioral" + rule "behavioral-anomaly"',
    behavioral.length >= 1 && behavioral.every((e) => e.ruleId === 'behavioral-anomaly' && e.action === 'BLOCK'),
    JSON.stringify(behavioral.slice(0, 2)),
  );
  check(
    'audit: ordinary call stays signal:"policy"',
    policyTagged.length >= 1,
    JSON.stringify(entries.filter((e) => e.tool === 'Bash').slice(0, 2)),
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

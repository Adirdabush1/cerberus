// Unit test for the content / contamination signal (run: npx tsx scripts/content.test.ts).
import { InMemoryContaminationMonitor } from '../src/signals/content.js';
import type { MCPToolCall } from '../src/contract/types.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) {
    pass++;
    console.log(`  ✅ ${name}`);
  } else {
    fail++;
    console.log(`  ❌ ${name} — ${detail}`);
  }
}

const cfg = { pathRiskTtlMs: 40, scanLimitBytes: 65_536, entropyThreshold: 4.0, entropyMinLen: 24 };
const read = (sid: string, file = '/app/config.yaml'): MCPToolCall => ({ tool: 'Read', input: { file_path: file }, sessionId: sid });
const egress = (sid: string): MCPToolCall => ({ tool: 'WebFetch', input: { url: 'https://example.com' }, sessionId: sid });

// ── secret detection on tool results ──
{
  const mon = new InMemoryContaminationMonitor(cfg);
  const r = mon.inspect(read('s1'), 'database:\n  aws_key: AKIAIOSFODNN7EXAMPLE\n');
  check('detects AWS access key', r.tainted && r.secretTypes.includes('aws-access-key'), JSON.stringify(r));
  const clean = mon.inspect(read('s2'), 'total 24\n-rw-r--r-- 1 user staff config.yaml\n');
  check('benign content is not tainted', !clean.tainted, JSON.stringify(clean));
}

// ── content-confirmed taint escalates egress to HITL (D4) ──
{
  const mon = new InMemoryContaminationMonitor(cfg);
  mon.inspect(read('x'), `token=ghp_${'a'.repeat(36)}`);
  const v = mon.evaluate(egress('x'));
  check('tainted session → egress HITL', v.action === 'HITL' && v.kind === 'content-exfil', JSON.stringify(v));
}

// ── a clean session's egress gets no content verdict ──
{
  const mon = new InMemoryContaminationMonitor(cfg);
  check('clean session → egress no content verdict', mon.evaluate(egress('clean')).action === null);
}

// ── path-only risk does NOT escalate egress on its own (D4: path → audit/allow) ──
{
  const mon = new InMemoryContaminationMonitor(cfg);
  mon.evaluate({ tool: 'Read', input: { file_path: '/home/u/.aws/credentials' }, sessionId: 'p' }); // path-risk
  check('path-only session → egress not HITL', mon.evaluate(egress('p')).action === null);
}

// ── taint does not bleed across sessions ──
{
  const mon = new InMemoryContaminationMonitor(cfg);
  mon.inspect(read('a'), 'AKIAIOSFODNN7EXAMPLE');
  check('taint isolated per session', mon.evaluate(egress('b')).action === null);
}

// ── content taint persists (does not decay), unlike path-risk (D5) ──
{
  const mon = new InMemoryContaminationMonitor(cfg);
  mon.inspect(read('persist'), 'AKIAIOSFODNN7EXAMPLE');
  const t0 = Date.now();
  while (Date.now() - t0 <= cfg.pathRiskTtlMs + 10) { /* wait past the path-risk TTL */ }
  check('content taint survives past path-risk TTL', mon.evaluate(egress('persist')).action === 'HITL');
}

// ── entropy fallback catches an unprefixed high-entropy token ──
{
  const mon = new InMemoryContaminationMonitor(cfg);
  const r = mon.inspect(read('e'), 'value: x7Kp2Qr9Lm4Vt8Wz3Yb6Nc1Df5Hg0Ji');
  check('entropy fallback catches random token', r.tainted && r.secretTypes.includes('high-entropy'), JSON.stringify(r));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

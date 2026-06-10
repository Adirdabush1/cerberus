// Unit test for the behavioral signal (run: npx tsx scripts/behavioral.test.ts).
import { InMemoryBehavioralMonitor } from '../src/signals/behavioral.js';
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

const cfg = { windowMs: 60_000, maxRate: 5, maxRepeat: 3, hardMultiplier: 2 };

// ── repetition: same call in a loop ──
{
  const mon = new InMemoryBehavioralMonitor(cfg);
  const call: MCPToolCall = { tool: 'Read', input: { file_path: '/a' }, sessionId: 'loop' };
  const verdicts = Array.from({ length: 7 }, () => mon.record(call));
  check('repeat 1-3 are clean', verdicts.slice(0, 3).every((v) => v.severity === null), JSON.stringify(verdicts.slice(0, 3)));
  check('repeat 4 → review', verdicts[3]?.severity === 'review', JSON.stringify(verdicts[3]));
  check('repeat 7 → block', verdicts[6]?.severity === 'block', JSON.stringify(verdicts[6]));
}

// ── rate: many DIFFERENT calls ──
{
  const mon = new InMemoryBehavioralMonitor(cfg);
  const verdicts = Array.from({ length: 11 }, (_, i) =>
    mon.record({ tool: 'Bash', input: { command: `echo ${i}` }, sessionId: 'rate' }),
  );
  check('rate 1-5 are clean', verdicts.slice(0, 5).every((v) => v.severity === null), JSON.stringify(verdicts.slice(0, 5)));
  check('rate 6 → review', verdicts[5]?.severity === 'review', JSON.stringify(verdicts[5]));
  check('rate 11 → block', verdicts[10]?.severity === 'block', JSON.stringify(verdicts[10]));
}

// ── isolation: sessions don't bleed into each other ──
{
  const mon = new InMemoryBehavioralMonitor(cfg);
  const c = (s: string): MCPToolCall => ({ tool: 'Read', input: { file_path: '/x' }, sessionId: s });
  for (let i = 0; i < 4; i++) mon.record(c('A'));
  const b = mon.record(c('B'));
  check('separate session starts clean', b.severity === null, JSON.stringify(b));
}

// ── eviction: fully-expired sessions are dropped (no unbounded leak) ──
{
  const mon = new InMemoryBehavioralMonitor({ ...cfg, windowMs: 20 });
  const c = (s: string): MCPToolCall => ({ tool: 'Read', input: { file_path: '/x' }, sessionId: s });
  mon.record(c('stale'));
  // wait past the window so 'stale' has no live timestamps, then touch a new session
  const t0 = Date.now();
  while (Date.now() - t0 <= 25) { /* busy-wait past windowMs */ }
  mon.record(c('fresh'));
  // @ts-expect-error reaching into private state for the test
  const sessions: Map<string, unknown> = mon.sessions;
  check('idle session is evicted', !sessions.has('stale'), JSON.stringify([...sessions.keys()]));
  check('active session is kept', sessions.has('fresh'), JSON.stringify([...sessions.keys()]));
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

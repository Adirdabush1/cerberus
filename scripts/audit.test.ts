// Unit test for audit-entry validation + the AuditLog drop gate (run: npx tsx scripts/audit.test.ts).
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditLog } from '../src/audit/index.js';
import { validateAuditEntry } from '../src/audit/validate.js';
import type { AuditEntry } from '../src/contract/types.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}

const ok = (over: Partial<AuditEntry>): AuditEntry =>
  ({ event: 'decision', ts: 1, sessionId: 's', reason: 'r', requestId: 'q', action: 'ALLOW', ...over }) as AuditEntry;

try {
  // ── validateAuditEntry ──
  check('valid decision passes', validateAuditEntry(ok({})).length === 0);
  check('valid session-started passes (no requestId/action needed)', validateAuditEntry({ event: 'session-started', ts: 1, sessionId: 's', reason: 'r' } as AuditEntry).length === 0);
  check('valid hitl-resolved passes', validateAuditEntry(ok({ event: 'hitl-resolved', action: 'BLOCK', resolution: 'expired', latencyMs: 10 })).length === 0);

  check('unknown event rejected', validateAuditEntry(ok({ event: 'bogus' as AuditEntry['event'] })).some((p) => /unknown event/.test(p)));
  check('missing sessionId rejected', validateAuditEntry(ok({ sessionId: '' })).some((p) => /sessionId/.test(p)));
  check('missing ts rejected', validateAuditEntry(ok({ ts: 0 })).some((p) => /ts/.test(p)));
  check('missing reason rejected', validateAuditEntry(ok({ reason: '' })).some((p) => /reason/.test(p)));
  check('decision without requestId rejected', validateAuditEntry(ok({ requestId: undefined })).some((p) => /requestId/.test(p)));
  check('decision without action rejected', validateAuditEntry(ok({ action: undefined })).some((p) => /action/.test(p)));
  check('hitl-resolved without resolution rejected', validateAuditEntry(ok({ event: 'hitl-resolved', action: 'BLOCK', latencyMs: 10 })).some((p) => /resolution/.test(p)));
  check('hitl-resolved without latency rejected', validateAuditEntry(ok({ event: 'hitl-resolved', action: 'BLOCK', resolution: 'expired' })).some((p) => /latencyMs/.test(p)));

  // ── AuditLog.record drop gate ──
  const file = join(mkdtempSync(join(tmpdir(), 'ag-audit-')), 'audit.jsonl');
  const log = new AuditLog(file);
  const origErr = process.stderr.write.bind(process.stderr);
  (process.stderr.write as unknown) = () => true; // silence the expected drop warning
  const wroteGood = log.record(ok({}));
  const wroteBad = log.record(ok({ sessionId: '' }));
  (process.stderr.write as unknown) = origErr;

  check('record() returns true for a valid entry', wroteGood === true);
  check('record() returns false for a malformed entry', wroteBad === false);
  const lines = existsSync(file) ? readFileSync(file, 'utf8').split('\n').filter(Boolean) : [];
  check('only the valid entry was persisted', lines.length === 1, `lines=${lines.length}`);
} catch (err) {
  fail++;
  console.log('  ❌ harness error —', (err as Error).message);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

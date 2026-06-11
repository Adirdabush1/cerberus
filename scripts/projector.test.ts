// Unit test for the audit-log projector (run: npx tsx scripts/projector.test.ts).
import { correlateTimeline, projectTimeline, summarizeSession, summarizeSessions } from '../src/audit/projector.js';
import type { AuditEntry, RiskAssessment, RiskFactor } from '../src/contract/types.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}

const risk = (score: number, band: RiskAssessment['band'], factors: RiskFactor[] = []): RiskAssessment => ({
  score, band, version: 'test', factors, hardFloor: false,
});
const F = (source: RiskFactor['source'], label: string, points: number, group: string): RiskFactor => ({ source, label, points, group });

// A realistic single-session log, deliberately out of ts order to test sorting. The held call (q1)
// carries factors so we can test driver aggregation and open→resolve correlation.
const heldRisk = risk(80, 'HITL', [F('content', 'content_exfil', 80, 'egress'), F('policy', 'policy_egress', 75, 'egress')]);
const log: AuditEntry[] = [
  { event: 'decision', ts: 30, reason: 'ok', sessionId: 'A', tool: 'Bash', action: 'ALLOW', signal: 'policy', requestId: 'q0' },
  { event: 'session-started', ts: 10, reason: 'start', sessionId: 'A' },
  { event: 'taint-loaded', ts: 40, reason: 'secret', sessionId: 'A', signal: 'content', secretTypes: ['aws'] },
  { event: 'hitl-opened', ts: 50, reason: 'held', sessionId: 'A', signal: 'content', requestId: 'q1', risk: heldRisk },
  { event: 'hitl-resolved', ts: 70, reason: 'denied', sessionId: 'A', action: 'BLOCK', signal: 'content', resolution: 'rejected', latencyMs: 20, requestId: 'q1', risk: heldRisk },
  { event: 'tool-failed', ts: 60, reason: 'boom', sessionId: 'A', tool: 'Bash' },
  { event: 'session-ended', ts: 90, reason: 'end', sessionId: 'A' },
  // a second session + an event with no sessionId (→ 'default' bucket)
  { event: 'decision', ts: 100, reason: 'block', sessionId: 'B', tool: 'Bash', action: 'BLOCK', signal: 'policy', requestId: 'q2', risk: risk(150, 'BLOCK') },
  { event: 'decision', ts: 5, reason: 'orphan', tool: 'Read', action: 'ALLOW', requestId: 'q3' },
];

try {
  const s = summarizeSession('A', log.filter((e) => e.sessionId === 'A'));
  check('verdicts counts decision + hitl-resolved', s.verdicts === 2, String(s.verdicts));
  check('allowed/blocked split', s.allowed === 1 && s.blocked === 1, `${s.allowed}/${s.blocked}`);
  check('held counts hitl-opened', s.held === 1, String(s.held));
  check('taintLoaded counted', s.taintLoaded === 1, String(s.taintLoaded));
  check('toolFailures counted', s.toolFailures === 1, String(s.toolFailures));
  check('peak band/score from risk', s.peakBand === 'HITL' && s.peakRiskScore === 80, `${s.peakBand}/${s.peakRiskScore}`);
  check('startedAt/endedAt from lifecycle events', s.startedAt === 10 && s.endedAt === 90, `${s.startedAt}/${s.endedAt}`);
  check('first/last ts span', s.firstTs === 10 && s.lastTs === 90, `${s.firstTs}/${s.lastTs}`);
  check('distinct signals collected', s.signals.includes('policy') && s.signals.includes('content'), JSON.stringify(s.signals));
  check('drivers map factor labels to friendly names', s.drivers.includes('secret exfiltration') && s.drivers.includes('outbound egress'), JSON.stringify(s.drivers));
  check('drivers do NOT double-count the held call (open+resolve share factors)', s.drivers.length === 2, JSON.stringify(s.drivers));

  // ── correlateTimeline: open+resolve fold into one item ──
  const items = correlateTimeline(projectTimeline(log, 'A').events);
  const held = items.find((it) => it.primary.event === 'hitl-opened');
  check('hitl-opened folds in its hitl-resolved by requestId', !!held?.resolvedBy && held.resolvedBy.action === 'BLOCK', JSON.stringify(held?.resolvedBy?.event));
  check('no standalone hitl-resolved item remains', !items.some((it) => it.primary.event === 'hitl-resolved'));
  check('correlated item count = events − folded resolved (7−1=6)', items.length === 6, String(items.length));

  const tl = projectTimeline(log, 'A');
  const ts = tl.events.map((e) => e.ts);
  check('timeline is filtered to the session', tl.events.every((e) => e.sessionId === 'A'));
  check('timeline is sorted ascending by ts', ts.join(',') === [...ts].sort((a, b) => a - b).join(','), ts.join(','));
  check('timeline summary matches', tl.summary.verdicts === 2 && tl.summary.peakBand === 'HITL');
  check('timeline ships correlated items', tl.items.length === 6);

  const all = summarizeSessions(log);
  check('groups every session incl. the default bucket', all.length === 3, JSON.stringify(all.map((x) => x.sessionId)));
  check('sorted by lastTs desc', all[0].sessionId === 'B', all.map((x) => `${x.sessionId}:${x.lastTs}`).join(' '));
  check('orphan event lands in "default"', all.some((x) => x.sessionId === 'default'), JSON.stringify(all.map((x) => x.sessionId)));
} catch (err) {
  fail++;
  console.log('  ❌ harness error —', (err as Error).message);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

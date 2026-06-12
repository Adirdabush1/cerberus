// Golden-vector test for the M3c risk engine (run: npx tsx scripts/risk.test.ts).
// These vectors LOCK the expected bands (D16 #3). Change rules/risk_weights.yaml only if these still
// pass — that is the guard against silent "weight drift".
import { fileURLToPath } from 'node:url';
import { WeightedRiskEngine } from '../src/risk/engine.js';
import type { PolicyDecision, ToolCategory } from '../src/contract/types.js';
import type { AnomalyVerdict } from '../src/signals/behavioral.js';
import type { ContentVerdict } from '../src/signals/content.js';

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

const weightsPath = fileURLToPath(new URL('../rules/risk_weights.yaml', import.meta.url));
const risk = new WeightedRiskEngine(weightsPath);

const NO_ANOMALY: AnomalyVerdict = { severity: null, reason: null };
const REVIEW: AnomalyVerdict = { severity: 'review', reason: 'high activity' };
const HARD_BLOCK: AnomalyVerdict = { severity: 'block', reason: 'runaway' };
const NO_CONTENT: ContentVerdict = { action: null, reason: null, kind: null };
const policy = (action: PolicyDecision['action'], category: ToolCategory, ruleId = 'r', reason = 'rule'): PolicyDecision => ({ action, category, ruleId, reason });
const content = (kind: ContentVerdict['kind']): ContentVerdict => ({ action: kind === 'path-risk' ? null : 'HITL', reason: `content:${kind}`, kind });

const band = (p: PolicyDecision, a: AnomalyVerdict, c: ContentVerdict) => risk.assess(p, a, c);

// ── hard floor (D15): deterministic BLOCK ignores the score ──
{
  const d = band(policy('BLOCK', 'EXECUTE', 'block-rm-rf'), NO_ANOMALY, NO_CONTENT);
  check('policy BLOCK → hard floor BLOCK', d.action === 'BLOCK' && d.risk.hardFloor && d.risk.band === 'BLOCK', JSON.stringify(d));
  const r = band(policy('ALLOW', 'EXECUTE'), HARD_BLOCK, NO_CONTENT);
  check('behavioral runaway → hard floor BLOCK', r.action === 'BLOCK' && r.risk.hardFloor, JSON.stringify(r.risk));
}

// ── ALLOW band: benign ──
{
  const d = band(policy('ALLOW', 'READ'), NO_ANOMALY, NO_CONTENT);
  check('benign → ALLOW band, score 0', d.action === 'ALLOW' && d.risk.band === 'ALLOW' && d.risk.score === 0, JSON.stringify(d.risk));
}

// ── single strong signal still reaches HITL alone (D18 conservative) ──
{
  check('git-push (policy HITL) → HITL', band(policy('HITL', 'EXECUTE', 'hitl-git-push'), NO_ANOMALY, NO_CONTENT).risk.band === 'HITL');
  const eg = band(policy('HITL', 'EGRESS', 'hitl-egress'), NO_ANOMALY, NO_CONTENT);
  check('clean egress → HITL, signal policy', eg.risk.band === 'HITL' && eg.signal === 'policy', JSON.stringify(eg));
  check('behavioral review alone → HITL, signal behavioral', band(policy('ALLOW', 'EXECUTE'), REVIEW, NO_CONTENT).signal === 'behavioral');
}

// ── D4 invariant: secret + egress stays HITL, never auto-escalates to BLOCK ──
{
  const d = band(policy('HITL', 'EGRESS', 'hitl-egress'), NO_ANOMALY, content('content-exfil'));
  check('secret + egress → HITL (NOT block)', d.risk.band === 'HITL' && d.action === 'HITL', JSON.stringify(d.risk));
  check('secret + egress → signal content (attribution)', d.signal === 'content' && d.ruleId === 'content-exfil', JSON.stringify(d));
}

// ── M3b attribution preserved: injection + egress → HITL, signal content ──
{
  const d = band(policy('HITL', 'EGRESS', 'hitl-egress'), NO_ANOMALY, content('content-injection'));
  check('injection + egress → HITL, signal content/content-injection', d.risk.band === 'HITL' && d.signal === 'content' && d.ruleId === 'content-injection', JSON.stringify(d));
}

// ── stacking distinct concerns escalates to BLOCK ──
{
  const d = band(policy('HITL', 'EGRESS', 'hitl-egress'), REVIEW, content('content-exfil'));
  check('exfil + runaway-review (distinct concerns) → BLOCK', d.risk.band === 'BLOCK' && d.action === 'BLOCK', JSON.stringify(d.risk));
}

// ── AUDIT band: a borderline signal with the egress policy relaxed (ALLOW) ──
{
  const d = band(policy('ALLOW', 'EGRESS'), NO_ANOMALY, content('content-injection'));
  check('relaxed-egress + injection → AUDIT (ALLOW to agent)', d.risk.band === 'AUDIT' && d.action === 'ALLOW', JSON.stringify(d.risk));
  const p = band(policy('ALLOW', 'EGRESS'), NO_ANOMALY, content('path-risk'));
  check('relaxed-egress + path-only → ALLOW (below audit threshold)', p.risk.band === 'ALLOW', JSON.stringify(p.risk));
}

// ── drift traceability: every assessment stamps the config version ──
{
  check('assessment carries config version', band(policy('ALLOW', 'READ'), NO_ANOMALY, NO_CONTENT).risk.version === 'm3c-risk-v1.1');
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

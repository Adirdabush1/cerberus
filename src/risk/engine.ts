/**
 * RiskEngine (M3c) — replaces the boolean strictest-wins `combine()` with weighted risk aggregation.
 *
 * Per-call (D14), from the current signals + already-decaying session state. Two stages:
 *   1. HARD FLOOR (D15) — a deterministic BLOCK (policy BLOCK, behavioral runaway) blocks regardless
 *      of score; it bypasses the sum. Never let a number un-block an absolute prohibition (OWASP).
 *   2. SCORE — derive weighted factors from the other signals, group by "concern", take the MAX within
 *      each group (normalization, D16 #1 — overlapping signals about the same concern don't double-
 *      count, so `secret + egress` stays HITL and never silently escalates to BLOCK, per D4), SUM
 *      across groups, map to a band.
 *
 * Calibration is conservative (D18): each strong single signal already reaches the HITL band alone, so
 * every M1/M2/M3a/M3b guarantee is preserved; aggregation only adds escalation on top. Weights live in
 * a versioned config (D16 #2); golden vectors lock the bands (D16 #3).
 *
 * SCORE vs ATTRIBUTION: the score uses points (group-max-sum); the displayed signal/reason uses a
 * signal PRIORITY (content > behavioral > policy) so a specific content finding is surfaced over the
 * generic egress rule even when their points tie — preserving M3a/M3b's `signal:'content'`.
 */
import { readFileSync } from 'node:fs';
import yaml from 'js-yaml';
import type { AnomalyVerdict } from '../signals/behavioral.js';
import type { ContentVerdict } from '../signals/content.js';
import type {
  PolicyAction,
  PolicyDecision,
  RiskAssessment,
  RiskBand,
  RiskFactor,
  SignalSource,
} from '../contract/types.js';

export interface RiskDecision {
  action: PolicyAction; // ALLOW | HITL | BLOCK — AUDIT collapses to ALLOW (D17)
  reason: string;
  ruleId: string | null;
  signal: SignalSource;
  risk: RiskAssessment;
}

interface WeightsFile {
  version: string;
  bands: { audit: number; hitl: number; block: number };
  groups: Record<string, Record<string, number>>;
}

export interface RiskEngine {
  readonly version: string;
  assess(policy: PolicyDecision, anomaly: AnomalyVerdict, content: ContentVerdict): RiskDecision;
}

const ATTRIBUTION_PRIORITY: readonly SignalSource[] = ['content', 'behavioral', 'policy'];

export class WeightedRiskEngine implements RiskEngine {
  private readonly w: WeightsFile;

  get version(): string {
    return this.w.version;
  }

  constructor(weightsPath: string) {
    const parsed = yaml.load(readFileSync(weightsPath, 'utf8')) as Partial<WeightsFile> | undefined;
    if (!parsed?.version || !parsed.bands || !parsed.groups) {
      throw new Error(`AgentGuard: invalid risk weights at ${weightsPath} (expected { version, bands, groups }).`);
    }
    this.w = { version: parsed.version, bands: parsed.bands, groups: parsed.groups };
  }

  assess(policy: PolicyDecision, anomaly: AnomalyVerdict, content: ContentVerdict): RiskDecision {
    // 1. HARD FLOOR — deterministic BLOCK wins outright.
    if (anomaly.severity === 'block') {
      return this.floor('behavioral', 'behavioral-anomaly', anomaly.reason ?? 'runaway agent — execution cut off');
    }
    if (policy.action === 'BLOCK') {
      return this.floor('policy', policy.ruleId, policy.reason);
    }

    // 2. derive weighted factors from the soft signals.
    const g = this.w.groups;
    const factors: RiskFactor[] = [];
    if (policy.action === 'HITL') {
      if (policy.category === 'EGRESS') add(factors, 'policy', 'egress', 'policy_egress', g.egress?.policy_egress);
      else add(factors, 'policy', 'command', 'policy_hitl', g.command?.policy_hitl);
    }
    if (anomaly.severity === 'review') add(factors, 'behavioral', 'behavioral', 'behavioral_review', g.behavioral?.behavioral_review);
    if (content.kind === 'content-exfil') add(factors, 'content', 'egress', 'content_exfil', g.egress?.content_exfil);
    else if (content.kind === 'content-injection') add(factors, 'content', 'egress', 'content_injection', g.egress?.content_injection);
    else if (content.kind === 'path-risk') add(factors, 'content', 'egress', 'path_risk', g.egress?.path_risk);

    // 3. score = Σ over groups of max(points in group)  (normalization: same concern doesn't stack)
    const groupMax = new Map<string, number>();
    for (const f of factors) groupMax.set(f.group, Math.max(groupMax.get(f.group) ?? 0, f.points));
    let score = 0;
    for (const m of groupMax.values()) score += m;

    const band = this.bandFor(score);
    const action: PolicyAction = band === 'BLOCK' ? 'BLOCK' : band === 'HITL' ? 'HITL' : 'ALLOW';
    const risk: RiskAssessment = { score, band, version: this.w.version, factors, hardFloor: false };
    const attr = attribution(factors);

    if (!attr) {
      return { action, reason: policy.reason, ruleId: policy.ruleId, signal: 'policy', risk };
    }
    if (attr.source === 'content') return { action, reason: content.reason ?? attr.label, ruleId: content.kind, signal: 'content', risk };
    if (attr.source === 'behavioral') return { action, reason: anomaly.reason ?? 'behavioral anomaly', ruleId: 'behavioral-anomaly', signal: 'behavioral', risk };
    return { action, reason: policy.reason, ruleId: policy.ruleId, signal: 'policy', risk };
  }

  private floor(signal: SignalSource, ruleId: string | null, reason: string): RiskDecision {
    return {
      action: 'BLOCK',
      reason,
      ruleId,
      signal,
      risk: { score: this.w.bands.block, band: 'BLOCK', version: this.w.version, factors: [], hardFloor: true },
    };
  }

  private bandFor(score: number): RiskBand {
    if (score >= this.w.bands.block) return 'BLOCK';
    if (score >= this.w.bands.hitl) return 'HITL';
    if (score >= this.w.bands.audit) return 'AUDIT';
    return 'ALLOW';
  }
}

function add(arr: RiskFactor[], source: SignalSource, group: string, label: string, points: number | undefined): void {
  if (typeof points === 'number') arr.push({ source, label, points, group });
}

/** Pick the factor to attribute the decision to: by signal priority, then by points. */
function attribution(factors: RiskFactor[]): RiskFactor | null {
  let best: RiskFactor | null = null;
  for (const f of factors) {
    if (!best) {
      best = f;
      continue;
    }
    const fp = ATTRIBUTION_PRIORITY.indexOf(f.source);
    const bp = ATTRIBUTION_PRIORITY.indexOf(best.source);
    if (fp < bp || (fp === bp && f.points > best.points)) best = f;
  }
  return best;
}

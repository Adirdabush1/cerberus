/**
 * Audit-log PROJECTOR (M4-B, D22/D25) — pure functions that turn the flat event log into the
 * session-centric shapes the investigation view needs.
 *
 * CRITICAL (D25): this is the ONE projection. The engine runs it over file-replayed history
 * (`GET /sessions`, `GET /sessions/:id/timeline`); the dashboard runs the SAME logic over the live
 * WS stream. If the two diverge, history and live drift — so this module is dependency-free and is
 * copied verbatim into the dashboard, exactly like the contract.
 *
 * It DERIVES interpretations (per-session rollups, peak band) and never invents events — observed
 * facts are emitted upstream; everything here is a fold over them.
 */
import type { AuditEntry, RiskBand, SessionSummary, SessionTimeline, SignalSource, TimelineItem } from '../contract/types.js';

const BAND_RANK: Record<RiskBand, number> = { ALLOW: 0, AUDIT: 1, HITL: 2, BLOCK: 3 };

/**
 * Friendly names for the weighted risk-factor labels (from `rules/risk_weights.yaml`), so a session's
 * `drivers` read as a human "why" ("prompt injection + secret exposure + behavioral spike") rather
 * than internal label slugs. Unknown labels pass through verbatim (forward-compatible with new weights).
 */
const RISK_DRIVERS: Record<string, string> = {
  content_exfil_match: 'secret in outbound payload (confirmed)',
  content_exfil: 'secret exfiltration',
  content_injection: 'prompt injection',
  path_risk: 'sensitive-path access',
  behavioral_review: 'behavioral spike',
  policy_egress: 'outbound egress',
  policy_hitl: 'policy hold',
};

/** The session bucket an event belongs to. Events with no sessionId fall into a shared bucket. */
function bucketOf(e: AuditEntry): string {
  return e.sessionId ?? 'default';
}

/** Fold one session's events (any order) into its rollup. */
export function summarizeSession(sessionId: string, events: readonly AuditEntry[]): SessionSummary {
  const s: SessionSummary = {
    sessionId,
    firstTs: Infinity,
    lastTs: -Infinity,
    verdicts: 0,
    allowed: 0,
    blocked: 0,
    held: 0,
    taintLoaded: 0,
    injections: 0,
    toolFailures: 0,
    peakRiskScore: 0,
    peakBand: 'ALLOW',
    signals: [],
    drivers: [],
  };
  const signals = new Set<SignalSource>();
  const driverPoints = new Map<string, number>(); // factor label → summed points across verdicts

  for (const e of events) {
    if (e.ts < s.firstTs) s.firstTs = e.ts;
    if (e.ts > s.lastTs) s.lastTs = e.ts;
    if (e.signal) signals.add(e.signal);
    if (e.risk) {
      if (e.risk.score > s.peakRiskScore) s.peakRiskScore = e.risk.score;
      if (BAND_RANK[e.risk.band] > BAND_RANK[s.peakBand]) s.peakBand = e.risk.band;
    }
    // Aggregate the session "why" from verdict events only (hitl-opened mirrors its resolved, so
    // counting both would double-weight a single held call).
    if ((e.event === 'decision' || e.event === 'hitl-resolved') && e.risk?.factors) {
      for (const f of e.risk.factors) driverPoints.set(f.label, (driverPoints.get(f.label) ?? 0) + f.points);
    }
    switch (e.event) {
      case 'session-started':
        s.startedAt = e.ts;
        break;
      case 'session-ended':
        s.endedAt = e.ts;
        break;
      case 'hitl-opened':
        s.held++;
        break;
      case 'decision':
      case 'hitl-resolved':
        s.verdicts++;
        if (e.action === 'ALLOW') s.allowed++;
        else if (e.action === 'BLOCK') s.blocked++;
        break;
      case 'taint-loaded':
        s.taintLoaded++;
        break;
      case 'injection-detected':
        s.injections++;
        break;
      case 'tool-failed':
        s.toolFailures++;
        break;
    }
  }

  if (!Number.isFinite(s.firstTs)) s.firstTs = 0;
  if (!Number.isFinite(s.lastTs)) s.lastTs = 0;
  s.signals = [...signals];
  s.drivers = [...driverPoints.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([label]) => RISK_DRIVERS[label] ?? label);
  return s;
}

/**
 * Collapse a session's events into correlated timeline items: a `hitl-opened` and its matching
 * `hitl-resolved` (same requestId) fold into one item; every other event stands alone. Input MUST be
 * ascending by ts (so an opened is seen before its resolved); the output preserves that order.
 */
export function correlateTimeline(events: readonly AuditEntry[]): TimelineItem[] {
  const resolvedByReq = new Map<string, AuditEntry>();
  for (const e of events) if (e.event === 'hitl-resolved' && e.requestId) resolvedByReq.set(e.requestId, e);

  const folded = new Set<AuditEntry>();
  const items: TimelineItem[] = [];
  for (const e of events) {
    if (e.event === 'hitl-opened' && e.requestId && resolvedByReq.has(e.requestId)) {
      const r = resolvedByReq.get(e.requestId) as AuditEntry;
      folded.add(r);
      items.push({ primary: e, resolvedBy: r });
    } else if (folded.has(e)) {
      continue; // a resolved already folded into its opened item
    } else {
      items.push({ primary: e });
    }
  }
  return items;
}

/** Group all events by session and roll each up. Newest activity first. */
export function summarizeSessions(entries: readonly AuditEntry[]): SessionSummary[] {
  const bySession = new Map<string, AuditEntry[]>();
  for (const e of entries) {
    const id = bucketOf(e);
    (bySession.get(id) ?? bySession.set(id, []).get(id)!).push(e);
  }
  return [...bySession.entries()]
    .map(([id, evs]) => summarizeSession(id, evs))
    .sort((a, b) => b.lastTs - a.lastTs);
}

/** One session's full timeline: its rollup + its events ascending by ts (stable within equal ts). */
export function projectTimeline(entries: readonly AuditEntry[], sessionId: string): SessionTimeline {
  const events = entries
    .map((e, i) => [e, i] as const)
    .filter(([e]) => bucketOf(e) === sessionId)
    .sort((a, b) => a[0].ts - b[0].ts || a[1] - b[1])
    .map(([e]) => e);
  return { sessionId, summary: summarizeSession(sessionId, events), events, items: correlateTimeline(events) };
}

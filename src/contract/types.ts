/**
 * AgentGuard — the single source-of-truth data contract.
 *
 * This file defines every structure that crosses a process or network boundary:
 *   Hook  ── HTTP POST /intercept ──►  Engine
 *   Engine ── WebSocket ──►  Dashboard   (and back, for decisions)
 *
 * It is dependency-free on purpose so it can be copied verbatim into the
 * separate `/dashboard` app without any build coupling.
 */

/** Risk category assigned by the local tool taxonomy. UNKNOWN ⇒ fail-closed. */
export type ToolCategory = 'READ' | 'WRITE' | 'EXECUTE' | 'EGRESS' | 'UNKNOWN';

/** What the policy engine decides for a single tool call. */
export type PolicyAction = 'ALLOW' | 'BLOCK' | 'HITL';

/** Which defense line produced a decision. ('content' is reserved for M3 injection/exfil.) */
export type SignalSource = 'policy' | 'behavioral' | 'content';

/** The only two outcomes the agent ever sees. HITL always collapses to one of these. */
export type FinalAction = 'ALLOW' | 'BLOCK';

/**
 * Risk band from the M3c aggregation engine. `AUDIT` collapses to ALLOW for the agent (binary
 * contract preserved) but is surfaced as elevated-risk; `HITL`/`BLOCK` behave as their actions.
 */
export type RiskBand = 'ALLOW' | 'AUDIT' | 'HITL' | 'BLOCK';

/** One weighted contribution to the risk score, for explainability in the audit/dashboard. */
export interface RiskFactor {
  source: SignalSource;
  label: string;
  points: number;
  group: string;
}

/** The explainable output of the risk engine for one decision. */
export interface RiskAssessment {
  score: number;
  band: RiskBand;
  version: string; // the weights-config version that produced this (drift traceability)
  factors: RiskFactor[];
  hardFloor: boolean; // true when a deterministic BLOCK floored the decision, bypassing the score
}

/**
 * A normalized tool call. Works for both Claude Code built-in tools
 * (tool_name="Bash", tool_input={command}) and MCP-routed tools
 * (tool="mcp__server__name", input={...}).
 */
export interface MCPToolCall {
  tool: string;
  input: Record<string, unknown>;
  sessionId?: string;
  cwd?: string;
}

/** Output of the policy engine for one call (pre-HITL resolution). */
export interface PolicyDecision {
  action: PolicyAction;
  ruleId: string | null;
  reason: string;
  category: ToolCategory;
}

/**
 * A held request awaiting human judgement. Streamed to the dashboard so a
 * human can see exactly what the agent wants to do (the "diff").
 */
export interface SecurityViolation {
  id: string;
  toolCall: MCPToolCall;
  category: ToolCategory;
  ruleId: string | null;
  reason: string;
  createdAt: number;
  ttlMs: number;
  signal: SignalSource;
  risk?: RiskAssessment;
}

/**
 * PostToolUse → Engine `/inspect` body. The hook posts the executed tool's result so the engine
 * can update its per-session contamination state. Observe-only: the engine never modifies the result.
 */
export interface InspectRequest {
  tool: string;
  input: Record<string, unknown>;
  sessionId?: string;
  toolResponse: string;
  /** Present when the tool FAILED (PostToolUse error payload) — the engine emits a `tool-failed` event. */
  error?: string;
}

/**
 * SessionStart / SessionEnd hook → Engine `/session`. Observability-only: bookends the session
 * timeline and (on 'ended') lets the engine reset per-session monitor state (D23).
 */
export interface SessionEvent {
  event: 'started' | 'ended';
  sessionId: string;
  source?: string; // SessionStart `source` (startup | resume | clear), if provided
}

/** The final, binary verdict returned to the hook (and thus to the agent). */
export interface PipelineResult {
  action: FinalAction;
  reason: string;
  violationId?: string;
}

/**
 * The kind of fact a single audit record captures (D23). The audit log is the single source of truth
 * (D22); the investigation timeline is a PROJECTION over these events. We EMIT observed facts (these
 * types) and DERIVE interpretations (e.g. risk-band transitions) in the projection — never as events.
 */
export type AuditEvent =
  | 'decision' //           an auto ALLOW/BLOCK verdict on an intercepted call (viaHitl=false)
  | 'hitl-opened' //        a call was held for human review (no verdict yet)
  | 'hitl-resolved' //      a held call left the pending set (approved | rejected | expired)
  | 'session-started' //    a Claude Code session began (SessionStart hook)
  | 'session-ended' //      a Claude Code session ended (SessionEnd hook) — also resets monitors
  | 'taint-loaded' //       a secret entered the agent's context (arms the exfil gate)
  | 'injection-detected' // prompt-injection found in a tool result (raises session posture)
  | 'tool-failed'; //       an executed tool returned an error instead of a result

/** How a held call was resolved (D23). Drives the latency metric (resolved.ts − opened.ts). */
export type HitlResolution = 'approved' | 'rejected' | 'expired';

/**
 * One line in the local audit log — a single observed event (D22/D23). `event`, `ts` (and `reason`
 * for the human-readable "what happened") are always present; the rest are populated per event kind:
 * decision/hitl-* carry the tool-call fields; session-* carry only session identity; resolution and
 * latencyMs are hitl-resolved-only; secretTypes/injectionScore tag the content events.
 */
export interface AuditEntry {
  event: AuditEvent;
  ts: number;
  reason: string;
  sessionId?: string; //    session grouping for the timeline (D24)
  requestId?: string; //    per-/intercept id; links decision ↔ hitl-opened ↔ hitl-resolved (D24)
  tool?: string;
  input?: Record<string, unknown>; // the tool-call args (decision/hitl events) — powers the timeline diff
  category?: ToolCategory;
  action?: FinalAction; //  decision + hitl-resolved
  ruleId?: string | null;
  viaHitl?: boolean;
  signal?: SignalSource;
  risk?: RiskAssessment;
  resolution?: HitlResolution; // hitl-resolved only
  latencyMs?: number; //        hitl-resolved only
  secretTypes?: string[]; //    taint-loaded only
  injectionScore?: number; //   injection-detected only
}

/**
 * A per-session rollup for the investigation view (D22 — derived by PROJECTING the audit log, never
 * stored as its own record). One row per Claude Code session, newest activity first.
 */
export interface SessionSummary {
  sessionId: string;
  firstTs: number;
  lastTs: number;
  startedAt?: number; //  ts of the session-started event, if one was observed
  endedAt?: number; //    ts of the session-ended event, if the session has closed
  verdicts: number; //    decisions + resolved holds (calls that got an ALLOW/BLOCK)
  allowed: number;
  blocked: number;
  held: number; //        calls that were paused for human review (hitl-opened)
  taintLoaded: number; // secrets that entered context
  injections: number; //  prompt-injections detected in tool results
  toolFailures: number;
  peakRiskScore: number;
  peakBand: RiskBand;
  signals: SignalSource[]; // distinct defense lines that fired this session
  drivers: string[]; //      friendly names of the risk factors that drove this session's risk, hottest first
}

/**
 * One row of the correlated timeline. A held call's `hitl-opened` and `hitl-resolved` (same
 * `requestId`) collapse into a single item — `primary` is the opened event, `resolvedBy` the verdict —
 * so the UI shows one row ("held → BLOCK, rejected · 1.2s") instead of two. Every other event is a
 * standalone item (`resolvedBy` undefined).
 */
export interface TimelineItem {
  primary: AuditEntry;
  resolvedBy?: AuditEntry;
}

/** `GET /sessions/:id/timeline` response — the rollup, the raw events, and the correlated items. */
export interface SessionTimeline {
  sessionId: string;
  summary: SessionSummary;
  events: AuditEntry[]; //   ascending by ts — the raw projection
  items: TimelineItem[]; //  correlated (open+resolve folded) — what the UI renders
}

/* ----------------------------- WebSocket contract ----------------------------- */

/** Messages the Engine pushes to the Dashboard. */
export type ServerToDashboard =
  | { type: 'hello'; pending: SecurityViolation[] }
  | { type: 'violation'; violation: SecurityViolation }
  | { type: 'resolved'; violationId: string; action: FinalAction }
  | { type: 'audit'; entry: AuditEntry };

/** Messages the Dashboard sends back to the Engine. */
export type DashboardToServer = {
  type: 'decision';
  violationId: string;
  action: FinalAction;
};

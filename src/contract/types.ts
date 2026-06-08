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

/** The only two outcomes the agent ever sees. HITL always collapses to one of these. */
export type FinalAction = 'ALLOW' | 'BLOCK';

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
}

/** The final, binary verdict returned to the hook (and thus to the agent). */
export interface PipelineResult {
  action: FinalAction;
  reason: string;
  violationId?: string;
}

/** One line in the local audit log. */
export interface AuditEntry {
  ts: number;
  tool: string;
  category: ToolCategory;
  action: FinalAction;
  ruleId: string | null;
  reason: string;
  viaHitl: boolean;
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

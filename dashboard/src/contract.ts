/**
 * AgentGuard data contract — COPIED VERBATIM from `src/contract/types.ts` in the engine.
 *
 * Single source of truth lives in the engine package; this copy keeps the dashboard
 * decoupled at the build level (no workspaces, no shared tsconfig) while preventing
 * drift. If you change the engine contract, copy it here.
 */

export type ToolCategory = 'READ' | 'WRITE' | 'EXECUTE' | 'EGRESS' | 'UNKNOWN';
export type PolicyAction = 'ALLOW' | 'BLOCK' | 'HITL';
export type FinalAction = 'ALLOW' | 'BLOCK';

export interface MCPToolCall {
  tool: string;
  input: Record<string, unknown>;
  sessionId?: string;
  cwd?: string;
}

export interface SecurityViolation {
  id: string;
  toolCall: MCPToolCall;
  category: ToolCategory;
  ruleId: string | null;
  reason: string;
  createdAt: number;
  ttlMs: number;
}

export interface AuditEntry {
  ts: number;
  tool: string;
  category: ToolCategory;
  action: FinalAction;
  ruleId: string | null;
  reason: string;
  viaHitl: boolean;
}

export type ServerToDashboard =
  | { type: 'hello'; pending: SecurityViolation[] }
  | { type: 'violation'; violation: SecurityViolation }
  | { type: 'resolved'; violationId: string; action: FinalAction }
  | { type: 'audit'; entry: AuditEntry };

export type DashboardToServer = {
  type: 'decision';
  violationId: string;
  action: FinalAction;
};

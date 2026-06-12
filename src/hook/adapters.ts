/**
 * Per-agent adapters (M5). The shared hook flow (POST /intercept → ALLOW/BLOCK/ASK, POST /inspect,
 * POST /session) is identical across agents; only two things differ per agent and live here:
 *   1. parse(): the agent's stdin event shape → a normalized ParsedEvent (MCPToolCall + kind).
 *   2. formatPre/Post/Session(): the verdict → the agent's expected stdout JSON.
 * Plus `supportsAsk`: whether the agent has a NATIVE in-tool approval prompt (so the engine returns
 * ASK) or only allow/deny (so we fall back to the dashboard socket-hold).
 *
 * All functions are PURE (no IO) so they're unit-testable without spawning the agent.
 *
 * VERIFICATION STATUS: `claude` is verified end-to-end. `codex`/`cursor`/`cline` formats are built to
 * the published hook specs (late-2025/2026) — field names are pinned here and flagged for live
 * re-verification per agent release (see brainstorms/m5-multi-agent.md).
 */
import type { MCPToolCall } from '../contract/types.js';

export type AgentName = 'claude' | 'codex' | 'cursor' | 'cline';
export type Verdict = 'allow' | 'deny' | 'ask';

export interface ParsedEvent {
  kind: 'pre' | 'post' | 'session-start' | 'session-end' | 'ignore';
  call?: MCPToolCall;
  toolResponse?: string;
  error?: string;
  sessionSource?: string;
}

export interface AgentAdapter {
  name: AgentName;
  /** Native in-tool approval prompt? true ⇒ engine returns ASK; false ⇒ dashboard socket-hold. */
  supportsAsk: boolean;
  parse(e: Record<string, unknown>): ParsedEvent;
  formatPre(verdict: Verdict, reason: string): unknown;
  formatPost(): unknown;
  formatSession(): unknown;
}

const str = (v: unknown): string | undefined => (typeof v === 'string' ? v : undefined);
const rec = (v: unknown): Record<string, unknown> => (v && typeof v === 'object' ? (v as Record<string, unknown>) : {});
const asText = (v: unknown): string => (typeof v === 'string' ? v : JSON.stringify(v ?? ''));

/** Shared pre/post parsing for the Claude-Code-spec agents (Claude, Codex copied the spec). */
function parseClaudeShape(e: Record<string, unknown>): ParsedEvent {
  const name = str(e['hook_event_name']);
  if (name === 'SessionStart') return { kind: 'session-start', sessionSource: str(e['source']) };
  if (name === 'SessionEnd') return { kind: 'session-end' };

  const sessionId = str(e['session_id']) ?? str(e['turn_id']);
  const isPost = name === 'PostToolUse' || e['tool_response'] !== undefined || e['tool_output'] !== undefined || e['error'] !== undefined;
  const call: MCPToolCall = { tool: str(e['tool_name']) ?? 'unknown', input: rec(e['tool_input']), sessionId, cwd: str(e['cwd']) };
  if (isPost) {
    const tr = e['tool_response'] ?? e['tool_output'];
    const err = e['error'];
    return { kind: 'post', call, toolResponse: asText(tr), ...(err != null ? { error: asText(err) } : {}) };
  }
  return { kind: 'pre', call };
}

const claude: AgentAdapter = {
  name: 'claude',
  supportsAsk: true,
  parse: parseClaudeShape,
  formatPre: (v, reason) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: v, permissionDecisionReason: reason } }),
  formatPost: () => ({ hookSpecificOutput: { hookEventName: 'PostToolUse' } }),
  formatSession: () => ({}),
};

const codex: AgentAdapter = {
  name: 'codex',
  supportsAsk: false, // Codex PreToolUse is allow/deny only → dashboard hold
  parse: parseClaudeShape, // Codex copied the Claude hook spec
  // Codex maps ASK (never reached, supportsAsk=false) defensively to deny.
  formatPre: (v, reason) => ({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: v === 'allow' ? 'allow' : 'deny', permissionDecisionReason: reason } }),
  formatPost: () => ({ hookSpecificOutput: { hookEventName: 'PostToolUse' } }),
  formatSession: () => ({}),
};

const cursor: AgentAdapter = {
  name: 'cursor',
  supportsAsk: true, // Cursor's `permission` supports allow|deny|ask (native IDE prompt)
  parse: (e) => {
    const command = str(e['command']); // beforeShellExecution puts the command at top level
    const sessionId = str(e['conversation_id']) ?? str(e['session_id']);
    const cwd = str(e['cwd']);
    if (command !== undefined) return { kind: 'pre', call: { tool: 'Bash', input: { command }, sessionId, cwd } };
    const toolName = str(e['tool_name']);
    if (toolName) return { kind: 'pre', call: { tool: toolName, input: rec(e['tool_input']), sessionId, cwd } };
    return { kind: 'ignore' }; // beforeReadFile / afterFileEdit / stop — not gated in v1
  },
  formatPre: (v, reason) => ({ permission: v, agentMessage: reason }),
  formatPost: () => ({}),
  formatSession: () => ({}),
};

const cline: AgentAdapter = {
  name: 'cline',
  supportsAsk: false, // Cline returns a `cancel` boolean — no native ask → dashboard hold
  parse: (e) => {
    const name = str(e['hook_event_name']) ?? str(e['hookEventName']);
    if (name === 'PostToolUse') {
      const tr = e['tool_response'] ?? e['toolResponse'] ?? e['result'];
      return { kind: 'post', call: clineCall(e), toolResponse: asText(tr) };
    }
    return { kind: 'pre', call: clineCall(e) }; // the PreToolUse hook file is the default
  },
  // cancel=true blocks; on deny we also inject the reason as context for the agent.
  formatPre: (v, reason) => (v === 'deny' ? { cancel: true, contextModification: reason } : { cancel: false }),
  formatPost: () => ({}),
  formatSession: () => ({}),
};

function clineCall(e: Record<string, unknown>): MCPToolCall {
  return {
    tool: str(e['tool_name']) ?? str(e['toolName']) ?? 'unknown',
    input: rec(e['tool_input'] ?? e['toolInput'] ?? e['parameters']),
    sessionId: str(e['task_id']) ?? str(e['taskId']) ?? str(e['session_id']),
    cwd: str(e['cwd']),
  };
}

const ADAPTERS: Record<AgentName, AgentAdapter> = { claude, codex, cursor, cline };

export function getAdapter(name: string | undefined): AgentAdapter {
  return ADAPTERS[(name as AgentName) in ADAPTERS ? (name as AgentName) : 'claude'];
}

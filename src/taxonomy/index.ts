/**
 * Tool taxonomy — maps a tool name to a risk category.
 *
 * GOVERNING PRINCIPLE: Fail-Closed / No-Celebrity-Benefit.
 * A tool we do not recognise with certainty (e.g. a custom `send_to_webhook`
 * from a third-party MCP server) is classified UNKNOWN, and the policy engine
 * treats UNKNOWN as the highest risk tier (human review) — never auto-allowed.
 */
import type { ToolCategory } from '../contract/types.js';

/** Canonical tool name → category. Covers Claude Code built-ins + common MCP/agent names. */
const KNOWN_TOOLS: Readonly<Record<string, ToolCategory>> = {
  // read-only
  Read: 'READ',
  read_file: 'READ',
  Glob: 'READ',
  Grep: 'READ',
  NotebookRead: 'READ',
  // file mutation
  Write: 'WRITE',
  Edit: 'WRITE',
  MultiEdit: 'WRITE',
  write_file: 'WRITE',
  NotebookEdit: 'WRITE',
  apply_patch: 'WRITE', // Codex CLI's file-edit tool
  // execution
  Bash: 'EXECUTE',
  execute_bash: 'EXECUTE',
  shell: 'EXECUTE',
  run_command: 'EXECUTE',
  PowerShell: 'EXECUTE', // Windows: Claude Code routes shell commands through a PowerShell tool
  pwsh: 'EXECUTE',
  cmd: 'EXECUTE',
  // network egress
  WebFetch: 'EGRESS',
  WebSearch: 'EGRESS',
  fetch: 'EGRESS',
  curl: 'EGRESS',
  http_request: 'EGRESS',
  send_to_webhook: 'EGRESS',
};

/**
 * Classify a tool by name. Unknown names (including unrecognised `mcp__*` tools)
 * return UNKNOWN so the engine can fail closed.
 */
export function classify(tool: string): ToolCategory {
  return KNOWN_TOOLS[tool] ?? 'UNKNOWN';
}

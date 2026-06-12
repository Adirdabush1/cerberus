# M5 — Multi-agent support (adapters beyond Claude Code)

**Topic:** Extend AgentGuard past Claude Code to other coding agents. The engine + 4 signals + risk +
dashboard are agent-agnostic; only the **adapter** (intercept tool call → `/intercept` → enforce the
verdict in the agent's mechanism) is agent-specific.

## Established facts (researched 2026-06-12, primary sources)
- **Codex CLI — native `PreToolUse` hook** (+ a separate `PermissionRequest` hook). JSON over stdin
  (`tool_name`, `tool_input.command`, …), returns `permissionDecision: allow|deny` (+ `updatedInput`
  rewrite, exit-2 block). Config: `~/.codex/hooks.json` / `config.toml [hooks]` / repo `.codex/`.
  **Enterprise `requirements.toml` (`allow_managed_hooks_only`) makes hooks non-bypassable** — a real
  security selling point. Built-in `shell`/`apply_patch` are internal (PreToolUse covers them).
- **Cursor — native hooks (v1.7+, Oct 2025)**: `beforeShellExecution`, `beforeMCPExecution`,
  `preToolUse`/`postToolUse`, etc. JSON over stdin, returns `{ permission: allow|deny|ask, user_message,
  agent_message }`. Config: `~/.cursor/hooks.json` or `<proj>/.cursor/hooks.json`. **Default fail-OPEN
  → must set `"failClosed": true`** per hook.
- **Cline — native hooks (v3.36+)**: `PreToolUse`/`PostToolUse` (modeled on the Claude Code spec).
  Script file in `~/Documents/Cline/Rules/Hooks/` or `.clinerules/hooks/`, **filename == hook type, no
  ext, executable**. Returns JSON with **`cancel` boolean** (+ `contextModification`). **macOS/Linux only
  (no Windows) as of v3.36.**
- **Roo Code — NO hooks, archived May 2026.** Do NOT target. (Fork "ZooCode" unverified.)
- **MCP-proxy is a dead end for all four:** shell/file-edit are INTERNAL tools, never traverse MCP, so
  a proxy `tools/call` interceptor misses the highest-risk surface. Native hooks are the correct lever;
  reserve MCP-proxy only for a hookless MCP-only agent.

## What's reusable vs per-agent
- **Reusable (no change):** engine, `/intercept` + `/inspect` + `/session`, signals, risk, dashboard,
  audit/projector. The `MCPToolCall → PipelineResult{ALLOW|BLOCK|ASK}` contract already fits.
- **Per-agent (the adapter):** (1) parse that agent's stdin event shape → `MCPToolCall`; (2) emit that
  agent's output shape from the verdict (Claude/Codex `permissionDecision`; Cursor `permission`; Cline
  `cancel`); (3) `agentguard init` writes the right config file in the right place + sets fail-closed.

## Key decisions
- **D42 — Scope = Codex + Cursor + Cline together** (Roo excluded — archived). One milestone.
- **D43 — One `agentguard hook --agent <claude|codex|cursor|cline>` binary** (default `claude` for
  back-compat; flag set by `init`). Shared core (POST `/intercept` → ALLOW/BLOCK/ASK); a per-agent
  **adapter** does only (1) parse stdin event → `MCPToolCall`, (2) format the verdict in the agent's
  output shape. Pure parse/format funcs ⇒ unit-testable without spawning the agent.
- **D44 — ASK vs HOLD is per-agent capability.** Claude & **Cursor support native "ask"** → terminal
  prompt. **Codex & Cline only do allow/deny** (Codex PreToolUse; Cline `cancel` bool) → fall back to
  the **dashboard socket-hold** flow. The hook tells the engine which via a new `approvalMode:'ask'|'hold'`
  on `/intercept` (derived from adapter capability + `AG_APPROVAL_SURFACE`); engine returns ASK or holds.
- **D45 — Output shapes:** Claude/Codex `permissionDecision` + `permissionDecisionReason`; Cursor
  `{permission, agentMessage}`; Cline `{cancel}` (+contextModification). `init` sets fail-closed where the
  agent defaults open (Cursor `failClosed:true`; Codex enterprise `requirements.toml` for non-bypassable).
- **D46 — Taxonomy:** add Codex's `apply_patch` → WRITE (its edit tool) so edits aren't UNKNOWN.

## Build order
1. Contract: `MCPToolCall.approvalMode?`; taxonomy `apply_patch`→WRITE.
2. Engine: honor `approvalMode` (ask vs hold) on HITL.
3. `src/hook/adapters.ts`: 4 adapters (pure parse + format + `supportsAsk`).
4. Rework `src/hook/index.ts` to select adapter by `--agent`/`AG_AGENT` and drive the shared flow.
5. `agentguard init --agent <name>`: write the per-agent config (path + shape + fail-closed).
6. Tests: `adapters.test.ts` (parse/format per agent); keep Claude byte-identical (back-compat).

## Open flags
- Hook field names are recent/evolving (Codex, Cursor v1.7, Cline v3.36) — pin & re-verify per release.
- Cursor/Codex default fail-OPEN → AgentGuard's init must set failClosed.
- Cline has no Windows support yet.
- Codex hook field details came from a single doc page — re-confirm `updatedInput`/`permissionDecision`
  against the installed CLI.

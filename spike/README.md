# M0 Spike — proving the foundational assumptions

Goal: before building, prove (1) we can intercept & block ANY Claude Code tool call,
and (2) we can hold an action for synchronous human approval. **Both proven below.**

## Files
- `hook.mjs` — a Claude Code **PreToolUse** hook. Classifies a tool call (allow / block /
  HITL), holds HITL requests for approval, audits every decision to `audit.jsonl`.
- `approve.mjs` — the "admin" CLI: list pending requests, approve/deny them.
- `claude-settings.example.json` — example hook wiring for a **test** project.

## Standalone test (no Claude Code needed) — proves the decision logic
```bash
# allow
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la"}}' | node hook.mjs
# block rm -rf
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf src"}}' | node hook.mjs
# block .env read
echo '{"tool_name":"Read","tool_input":{"file_path":"/p/.env"}}' | node hook.mjs
# HITL: in terminal A (holds), then approve in terminal B
echo '{"tool_name":"Write","tool_input":{"file_path":"/p/x.ts"},"session_id":"s1"}' | node hook.mjs   # A
node approve.mjs                 # B — list pending
node approve.mjs <id> approve    # B — release the hold
```

## Live test (real Claude Code) — proves enforcement + the hook-timeout question
> ⚠️ Do this in a SEPARATE throwaway project, not while Claude Code is operating in this repo.
1. Copy `claude-settings.example.json` → `<test-project>/.claude/settings.json`.
2. Run `claude` in that project and ask it to run `rm -rf build` → expect AgentGuard denial.
3. Ask it to `Write` a file → it should HANG (held). In another terminal run
   `node approve.mjs <id> approve` → Claude Code should proceed.
4. **OPEN QUESTION TO MEASURE:** the hook's `timeout` (seconds) is a hard wall — does a
   long hold survive? Tune `timeout` in settings and confirm a 5-min hold isn't killed.

## Results (2026-06-08)
| # | Scenario | Result |
|---|----------|--------|
| 1 | Bash `ls -la` | ✅ allow |
| 2 | Bash `rm -rf src` | ✅ deny (auto-block) |
| 3 | Read `.env` | ✅ deny (auto-block) |
| 4 | Bash `git push` + no approver | ✅ deny (timeout fail-safe) |
| 5 | Write + human approves mid-hold | ✅ allow (synchronous HITL) |

## Findings → feed back into PLAN.md
- ✅ **Assumption 1 (enforcement):** a PreToolUse hook intercepts built-in tools (Bash/Read/
  Write/Edit) — the surface a pure MCP proxy CANNOT see. **Hooks are the primary enforcement
  layer for Claude Code**; MCP proxy is complementary (MCP tools + content/result scanning).
- ✅ **Assumption 2 (synchronous hold):** works via a blocking hook + poll for approval +
  timeout→deny. Production swaps file-poll for Redis pub/sub.
- 🐛 **Bug found:** pending requests aren't cleaned up after a decision/timeout (stale files
  leak). Cleanup is required in the real implementation.
- ❓ **Still to measure live:** the Claude Code **hook timeout** ceiling for long holds, and
  whether `deny` reliably stops execution and returns the reason to the model.

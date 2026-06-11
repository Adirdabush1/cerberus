# AgentGuard

A **local-first security gateway for autonomous AI agents.** AgentGuard sits between an agent
(Claude Code today) and its execution environment, intercepts every **tool call**, scores it across
four signals, and either allows it, holds it for **human approval**, or blocks it — all on your
machine, with **no external API and nothing leaving the box.**

## What it catches
- **Policy** — deterministic rules (block `rm -rf`, hold `git push`, fail-closed on unknown tools).
- **Behavioral** — runaway agents and tight loops (tool-call rate / repetition).
- **Content** — secrets loaded into context, then a **taint → exfil** gate on outbound calls.
- **Injection** — prompt-injection in tool *results* (a poisoned README) raises the session's risk.

These feed a **Risk Engine** that aggregates a weighted score → `ALLOW · AUDIT · HITL · BLOCK`, with
deterministic prohibitions as a hard floor the score can never override.

## Quickstart

```bash
npm install            # (in a clone) install deps
npm run build          # compile the engine + build the dashboard

# wire AgentGuard into Claude Code (merges into .claude/settings.json — backed up, idempotent):
agentguard init                 # project-level   (--global for ~/.claude, --print to just show it)

# start the gateway + dashboard (one process):
agentguard engine               # then open http://127.0.0.1:9000/
```

Use Claude Code as usual — tool calls now route through AgentGuard. A blocked or held call is
announced **in your terminal**; resolve a held call from the terminal or the dashboard:

```bash
agentguard pending              # list calls held for review (with their ids)
agentguard approve <id>         # release a held call …
agentguard deny <id>            # … or deny it
```

The dashboard (`http://127.0.0.1:9000/`) has a **Live** tab (Action Center + stream) and a
**Sessions** tab — a forensic timeline per session with a risk-factor breakdown and a **Replay**
player to step through how a session's risk built up.

## Terminal-first alerts & approvals
AgentGuard runs *inside* the agent's execution loop, so the terminal is the realtime decision point
and the dashboard is the deep dive. Per severity:

| verdict | terminal | web UI |
|---|---|---|
| **BLOCK** | ⛔ alert + session link | optional auto-open |
| **HITL** (held) | ⏸ notice → `agentguard pending` + link | reachable via the link |
| **AUDIT** | — (quiet) | elevated-risk record |
| **ALLOW** | — (silent) | — |

Alerts write to the controlling terminal (`/dev/tty`, falling back to stderr) so the protocol channel
to Claude Code stays clean. Tune via env:

| env | default | effect |
|---|---|---|
| `AG_NOTIFY` | `1` | terminal notifications on/off (`0` to silence) |
| `AG_APPROVAL_SURFACE` | `both` | `terminal` · `dashboard` · `both` |
| `AG_AUTO_OPEN` | `off` | `block` ⇒ auto-open the investigation UI on a BLOCK/EXFIL |

## How it plugs in
- **PreToolUse hook → `/intercept`** is the single hard enforcement point (allow/deny; HITL holds the
  socket open until you decide).
- **PostToolUse hook → `/inspect`** is observe-only: it updates the session's contamination state so
  the *next* action is judged with full context. It never modifies a tool result.
- The engine is **agent-agnostic** at its core; the Claude Code hooks are just the first adapter.

## Architecture
```
PreToolUse  ─▶ /intercept ─▶ Policy + Behavioral + Content/Injection ─▶ RiskEngine ─▶ ALLOW/AUDIT/HITL/BLOCK
PostToolUse ─▶ /inspect   ─▶ secret detection + injection classifier ─▶ session contamination state
                                                                   (audit log + WebSocket → dashboard)
```
Single Node + TypeScript package; the dashboard is a Vite/React app served by the engine. Rules and
risk weights are editable **YAML data**, not code (`rules/`).

## Local-first & licensing
No external API, no API key, nothing leaves the machine. The optional injection model
([`@agentguard/injection-model`](packages/injection-model), ProtectAI DeBERTa, Apache-2.0) upgrades
the built-in heuristic classifier; install it only if you want it. The core is OSS-clean
(Apache/MIT-compatible deps); Meta Prompt-Guard is deliberately kept out of core (Llama license).

## Development
```bash
npm run engine            # run from source via tsx (dev)
npm run typecheck
npm run test:behavioral && npm run test:content && npm run test:injection && npm run test:risk \
  && npm run test:init && npm run test:projector && npm run test:audit && npm run test:notify && npm run test:security
npm run e2e:behavioral && npm run e2e:content && npm run e2e:injection && npm run e2e:risk
```
See `PLAN.md` for milestones and `brainstorms/` for the design records behind each decision.

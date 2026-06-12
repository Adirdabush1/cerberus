# AgentGuard

A **local-first security gateway for autonomous AI coding agents.** AgentGuard sits between the agent
(Claude Code, Codex, Cursor, Cline) and your machine, intercepts **every tool call** before it runs,
risk-scores it across four signals, and either **allows, audits, asks for human approval, or blocks**
it — all on your machine, with **no external API and nothing leaving the box.**

## The problem
Autonomous coding agents run shell commands, edit files, and make network calls on your behalf — at
machine speed, often unattended. One bad step (`rm -rf`, an unwanted `git push`, a leaked `.env`, a
poisoned README that tricks the agent into exfiltrating secrets) and there's no human in the loop to
stop it. AgentGuard puts that checkpoint **on the tool boundary**, where the agent actually acts.

## What it does
```
PreToolUse  ─▶ intercept ─▶ Policy + Behavioral + Content + Injection ─▶ Risk Engine ─▶ ALLOW · AUDIT · HITL · BLOCK
PostToolUse ─▶ inspect   ─▶ secret + injection detection ─▶ session contamination state
```
Four deterministic signals aggregated into one weighted risk score, with a hard floor that absolute
prohibitions can never override.

## What it protects against
- **🟢 Secret exfiltration** — detects secrets loaded into context, then **content-matches the outbound
  payload**: holds the call that actually carries the key (raw or base64/hex/url-encoded), with provenance
  (`source: .env:4 · sha256:… · 97%`) and never logging the secret itself.
- **🟢 Excessive permissions** — every call gated; unknown tools fail-closed; sensitive paths (`~/.ssh`,
  `~/.aws`, credentials, `/etc/passwd`) held; destructive commands (`rm -rf`, `Remove-Item -Recurse`,
  `chmod 777`, `kill -9`) blocked or held.
- **🟢 Dangerous egress** — destination policy: trusted hosts (registries, GitHub, OpenAI/Anthropic)
  auto-allowed; paste sites / webhook catchers / raw-IP destinations held.
- **🟡 Tool abuse** — runaway-loop and tool-call-rate/repetition detection.
- **🟡 Prompt injection** — detects injection in tool *results* and gates the next egress (heuristic
  classifier; optional local DeBERTa model). It sees tool calls, **not the LLM prompt** — so it catches the
  *exploitation* of an injection (the egress), not the injection itself.

## Key features
- **Terminal-first approval** — held calls surface in the agent's native permission prompt (Claude Code /
  Cursor), or via `agentguard approve <id>` / a localhost dashboard.
- **Forensic dashboard** — per-session timeline, risk-factor breakdown, and a **Replay** player that steps
  through how a session's risk built up.
- **Multi-agent** — one adapter layer serves Claude Code, Codex, Cursor, and Cline.
- **Policy as data** — rules and risk weights are editable YAML, not code.
- **Local-first** — binds to `127.0.0.1`, no external API, no telemetry; secret *values* never touch disk or logs.

## Quickstart

```bash
npm i -g agentguard      # or run ad-hoc with: npx agentguard <cmd>

# wire AgentGuard into your agent (merges into the agent's config — backed up, idempotent):
agentguard init                 # Claude Code, project-level   (--agent codex|cursor|cline, --global, --print)

# start the gateway + dashboard (one process):
agentguard engine               # then open http://127.0.0.1:9000/
```

Use your agent as usual — tool calls now route through AgentGuard. By default a held (HITL) call is
**approved right in the terminal**: AgentGuard returns `ask`, so Claude Code shows its native
permission prompt with AgentGuard's reason — approve/deny without leaving your session.

The dashboard (`http://127.0.0.1:9000/`) has a **Live** tab (Action Center + stream) and a
**Sessions** tab — a forensic timeline per session with a risk-factor breakdown and a **Replay**
player to step through how a session's risk built up.

## Terminal-first approvals
AgentGuard runs *inside* the agent's execution loop, so the terminal is the realtime decision point
and the dashboard is the deep dive. Per severity (default `AG_APPROVAL_SURFACE=terminal`):

| verdict | terminal | web UI |
|---|---|---|
| **BLOCK** | ⛔ denied in-terminal (Claude shows the reason) + optional auto-open | forensics |
| **HITL** | ✋ **Claude's native permission prompt**, with AgentGuard's reason | forensics |
| **AUDIT** | — (quiet) | elevated-risk record |
| **ALLOW** | — (silent) | — |

Prefer a central web queue instead? Set **`AG_APPROVAL_SURFACE=dashboard`** — held calls then pause on
the engine's synchronous hold and you Approve/Deny from the dashboard (or the terminal, out-of-band):

```bash
agentguard pending              # list calls held for review (with their ids)
agentguard approve <id>         # release a held call …
agentguard deny <id>            # … or deny it
```

Extra terminal alerts write to the controlling terminal (`/dev/tty`, falling back to stderr) so the
protocol channel to Claude Code stays clean. Tune via env:

| env | default | effect |
|---|---|---|
| `AG_NOTIFY` | `1` | extra terminal alert lines on/off (`0` to silence) |
| `AG_APPROVAL_SURFACE` | `terminal` | `terminal` ⇒ HITL via Claude's native prompt; `dashboard` ⇒ socket hold + dashboard approve |
| `AG_AUTO_OPEN` | `off` | `block` ⇒ auto-open the investigation UI on a BLOCK/EXFIL |

## Agents
The engine + signals + risk + dashboard are agent-agnostic; only a thin **adapter** (parse the agent's
hook event → normalize → emit its verdict shape) is per-agent. Wire one with `agentguard init --agent <name>`:

| agent | `--agent` | HITL approval | notes |
|---|---|---|---|
| **Claude Code** | `claude` (default) | native terminal prompt (`ask`) | verified end-to-end |
| **Codex CLI** | `codex` | dashboard hold (no native ask) — `AG_APPROVAL_SURFACE=dashboard` | enterprise `requirements.toml` makes it non-bypassable |
| **Cursor** | `cursor` | native IDE prompt (`ask`) | init sets `failClosed: true` |
| **Cline** | `cline` | dashboard hold (`cancel` bool) | macOS/Linux only |

`codex`/`cursor`/`cline` adapters follow the published hook specs; verify against your installed version
(`agentguard init --agent <name> --print` shows the exact config). Roo Code is unsupported (archived 2026).

## How it plugs in
- **PreToolUse hook → `/intercept`** is the single hard enforcement point (allow/deny/ask; or HITL holds the
  socket open until you decide).
- **PostToolUse hook → `/inspect`** is observe-only: it updates the session's contamination state so
  the *next* action is judged with full context. It never modifies a tool result.
- The engine is **agent-agnostic** at its core; per-agent adapters (`--agent`) are the only thing that differs.

## Architecture
```
PreToolUse  ─▶ /intercept ─▶ Policy + Behavioral + Content/Injection ─▶ RiskEngine ─▶ ALLOW/AUDIT/HITL/BLOCK
PostToolUse ─▶ /inspect   ─▶ secret detection + injection classifier ─▶ session contamination state
                                                                   (audit log + WebSocket → dashboard)
```
Single Node + TypeScript package; the dashboard is a Vite/React app served by the engine. Rules and
risk weights are editable **YAML data**, not code (`rules/`).

## What it is — and isn't
AgentGuard is a **runtime gateway on the tool boundary**. It's strongest at secret-exfiltration
prevention and as a permission chokepoint. Because it sees tool calls (not the LLM prompt), it catches
the *exploitation* of a prompt injection — not the injection itself — and it does **not** cover
data-pipeline / RAG poisoning. The exfil match is high-confidence but not airtight (novel secret formats,
split-across-calls encoding). Honest defaults over false guarantees.

## Local-first & licensing
No external API, no API key, nothing leaves the machine. The optional injection model
([`@agentguard/injection-model`](packages/injection-model), ProtectAI DeBERTa, Apache-2.0) upgrades
the built-in heuristic classifier; install it only if you want it. The core is OSS-clean
(Apache/MIT-compatible deps); Meta Prompt-Guard is deliberately kept out of core (Llama license).

## Development
```bash
# from a clone: install (root + dashboard are separate npm projects) and build
npm install && npm --prefix dashboard install
npm run build             # compile the engine (tsc → dist) + dashboard (vite → dashboard/dist)

npm run engine            # run from source via tsx (dev)
npm run typecheck
npm run test:behavioral && npm run test:content && npm run test:injection && npm run test:risk \
  && npm run test:init && npm run test:projector && npm run test:audit && npm run test:notify \
  && npm run test:security && npm run test:policy && npm run test:adapters
npm run e2e:behavioral && npm run e2e:content && npm run e2e:injection && npm run e2e:risk
```
See `PLAN.md` for milestones and `brainstorms/` for the design records behind each decision.

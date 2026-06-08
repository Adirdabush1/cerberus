# AgentGuard (APG) — Engineering Plan

> **A Web Application Firewall (WAF) for autonomous AI agents.**
> Local-first MCP gateway that intercepts every tool call, runs three independent
> security signals (Policy + Behavioral + Content), and pauses risky actions for
> real-time human approval. Open-Core distribution.

**Status:** Planning complete (grill phase closed 2026-06-08). No production code yet.
**Owner:** Adir

---

## 1. Locked Decisions

| # | Decision | Choice |
|---|----------|--------|
| 1 | **Interception point** | **Dual-layer (revised after M0 spike).** For **Claude Code**, primary enforcement is **PreToolUse hooks** — they intercept ALL tools incl. built-in `Bash`/`Read`/`Edit`/`Write` that a pure MCP proxy *cannot see*. The **MCP proxy** is complementary (MCP-routed tools + scanning tool *results*) and is the path for non-Claude-Code agents. Both sit on the tool boundary, not the LLM boundary. |
| 2 | **Decision engine** | **Deterministic core (no maintainer LLM cost).** OPA + rules + a small *local* ONNX classifier. A generative BYO-LLM intent layer is optional/off by default. |
| 3 | **Policy engine** | **(Revised) Declarative rules as DATA for V1** — `json-logic-js` over a JSON/YAML rule file the dev edits (0 build, ~0ms). Hidden behind a `PolicyEngine` interface so **OPA/Cedar plug in as Enterprise adapters later**. Rules stay editable data, never hardcoded TS `if`s. |
| 4 | **HITL mechanism** | **Synchronous Hold.** Claude-Code path = the **hook child-process** holds + polls + exits (no long-lived server promise → no leak). MCP-proxy path = single shared Redis subscriber + cleanup in `finally`. **Fail-safe Deny TTL = the configured hook/MCP timeout (minutes, e.g. 300–600s)** — NOT 60s; a human must have time to approve. |
| 5 | **Distribution** | **Local-first** sidecar/CLI (`npx agentguard`). Approval via **localhost dashboard** with **terminal fallback** (`approval_surface: dashboard \| terminal \| both`). Cloud / Slack / multi-seat / log-retention = paid tier. |
| 6 | **MVP depth** | **The Security Trinity** — Policy + Behavioral/Anomaly + Content/Injection+Exfil. This is what makes it a WAF, not a linter. |

---

## 2. Architecture

AgentGuard is an **MCP proxy/aggregator**: to the agent it *is* an MCP server; to the
real tools it is an MCP client. Every `tools/call` (JSON-RPC 2.0 over stdio / Streamable
HTTP) passes through it.

```
                            ┌─────────────────────────────────────────────┐
                            │              AgentGuard Gateway              │
   AI Agent                 │                                              │
 (Claude Code) ──tools/call─┼─► [A] Pre-flight on INPUT                    │
       ▲                    │       • OPA policy decision (allow/block/HITL)│
       │                    │       • Behavioral counters (Redis sliding win)│
       │                    │       • Exfil state check (taint flag)        │
       │                    │            │                                  │
       │                    │   allow ───┤                                  │
       │                    │   block ───┤──► synthetic "Permission Denied" │
       │                    │   HITL  ───┤──► Redis pending + dashboard/Slack│
       │                    │            │      (Synchronous Hold)          │
       │                    │            ▼                                  │
       │                    │       forward to upstream MCP tool ──────────┼──► Real MCP Tool / Runtime
       │                    │            │                                  │      (fs, bash, git, http…)
       │                    │            ▼                                  │
       │  tool result ◄─────┼─── [B] Post-flight on OUTPUT                  │
       └────────────────────┤       • ONNX injection classifier (scan result)│
                            │       • Secret detection → set taint flag     │
                            │       • Audit log (JSONL/SQLite)              │
                            └─────────────────────────────────────────────┘
                                         │
                                  Redis (state) · OPA (policy) · Dashboard (React)
```

**Key architectural precision:** because we are on the *tool* boundary, the injection
classifier scans **tool results** (e.g. the poisoned `README` returned by `read_file`)
*before* they flow back to the agent — not the LLM prompt. We never see LLM
tokens/prompts in the core architecture.

---

## 3. The Security Trinity (MVP)

### Signal 1 — Behavioral / Anomaly (Runaway agents)
- **Where:** Proxy middleware + Redis sliding window.
- **How:** `INCRBY` on `agent:<session>:window` per tool call; 60s sliding window.
  Trip if e.g. >30 `execute_bash`/`read_file` per minute, or repeated-identical-call
  count exceeds threshold → status `PAUSED`, red alert on dashboard.
- **⚠️ Precision:** we count **tool-call rate/volume/repetition**, *not* token-$ spend
  (tokens live on the LLM path we don't proxy). v1 "budget" = tool-call ceiling.
  True $-budget = future optional LLM-proxy or agent-reported usage.

### Signal 2 — Content / Exfiltration (context-aware Zero-Trust)
- **Where:** Redis state machine + outbound block.
- **How (two-step):**
  1. Agent reads a sensitive file (`.env`, keys) → secret detector flags it → set
     `agent:<session>:SENSITIVE_DATA_LOADED = true` (with TTL).
  2. Agent later calls a **network-egress tool** (`fetch`/`curl`/browser MCP) while the
     flag is set → route to **HITL** (not auto-block — avoids false positives on
     legitimate dev API calls). Admin sees: *"read .env 2m ago, now POSTing to
     evil-site.com — approve/block?"*
- **Needs:** a **tool taxonomy** (which tools are network egress) — maintained list + schema inference, governed by the **Fail-Closed / No-Celebrity-Benefit** principle: any tool not identified with certainty (e.g. a custom `send_to_webhook`) is treated as the **highest** risk tier (full policy eval / HITL), never given the benefit of the doubt.
- **v1.1 upgrade:** binary flag → **content-match** (does the outbound payload actually
  contain bytes from the secret?) — turns "suspicion" into "proof."

### Signal 3 — Indirect Prompt Injection (defense in depth)
- **Layer 1 (payload detection):** tool *result* text runs through a small **local ONNX
  classifier** (e.g. Meta **Prompt-Guard-2**, ONNX Runtime on CPU). Returns a risk
  score; if > 0.85 → withhold/flag/sanitize the result *before* returning it to the
  agent. Zero API cost, nothing leaves the machine.
- **Layer 2 (action block):** if injection slips through and the agent emits
  `execute_bash rm -rf src`, **OPA** deterministically blocks it at the gateway —
  word-manipulation can't bypass a hard rule.

---

## 4. Repository Structure (single package — monorepo rejected for MVP)

Workspaces/Turborepo/tsup add build-pipeline friction with zero MVP payoff. One flat
Node package for the engine; the dashboard is a separate app talking REST/WS only.

```
agentguard/
├── src/                 # the single Node.js + TS package (engine + hook + CLI)
│   ├── hook/                # Claude Code PreToolUse/PostToolUse hook entry (primary enforcement)
│   ├── mcp/                 # MCP proxy server+client (complementary / non-Claude-Code agents)
│   ├── pipeline/            # pre-flight / post-flight decision pipeline
│   ├── signals/             # behavioral / exfil / injection
│   ├── policy/              # PolicyEngine interface + json-logic evaluator (default impl)
│   ├── hitl/                # synchronous hold + pending store + fail-safe deny
│   ├── audit/               # JSONL/SQLite audit log
│   ├── taxonomy/            # tool classifier — Fail-Closed (unknown = strictest)
│   └── contract/            # SINGLE source-of-truth WS/REST message types (copied to dashboard)
├── rules/               # default policies as editable DATA (json/yaml), NOT code
├── bin/                 # `npx agentguard` CLI (init, run, config)
├── dashboard/           # separate React+Tailwind app — Live Stream · Action Center (diff) · Policy Editor
│                        #   talks to the engine ONLY via REST/WebSocket (no build coupling)
├── docs/
└── examples/            # Claude Code settings + MCP config (e2e integration)
```

---

## 5. OSS Dependency Map

### ✅ Build on (verified, well-established)
| Tool | Role | License |
|------|------|---------|
| **`json-logic-js`** | V1 policy evaluator over declarative rule data — tiny, 0 build | MIT |
| **Redis** | Sliding-window counters, pending queue, taint state | BSD/RSAL — verify version |
| **ONNX Runtime** | Run local classifier on CPU | MIT |
| **MCP SDK** (`@modelcontextprotocol/sdk`) | MCP server/client plumbing | MIT |
| **Fastify** | HTTP/transport layer | MIT |

### 🔍 Adopt after verification (category is real; pin the exact project + license)
| Candidate | Role | Note |
|-----------|------|------|
| **Meta Prompt-Guard-2** | Injection classifier model | Confirm license + ONNX export path; alternatives: Rebuff, Llama-Prompt-Guard |
| **AgentDojo** (ETH Zurich) | Security-Score benchmark | Post-MVP / investor demo; evaluation harness, not runtime |
| **Langfuse** | Observability (trace view) | Post-MVP |
| **OPA (Rego)** / **Cedar (AWS)** | Enterprise policy adapters behind `PolicyEngine` | Deferred — NOT in V1 core |

### 🟡 Reference only — borrow ideas, do NOT depend on (unverified names)
`AgentShield`, `Helio`, `Arbitus` (Rust gateway), `Canar.ai` (injection honeypot).
Borrow: Approval Queue, Spend Limits, auto security-testing of new MCP servers.

---

## 6. Open-Core Boundary

| Free / OSS (local) | Paid (cloud) |
|---|---|
| MCP gateway + the three signals | Hosted central gateway |
| OPA + default policies + custom Rego | Multi-seat / team management |
| Localhost dashboard + terminal approval | Slack approvals + cloud dashboard |
| Local audit log (JSONL/SQLite) | Long-term log retention (compliance) |
| Single developer | AgentDojo Security Score, BYO-LLM intent layer, Cedar/Enterprise, anomaly $-budget |

Pricing hypothesis: **$49/mo** small team · **$299/mo** mid team (by # agents / volume).

---

## 7. Milestones

- **M0 — Spike (proof of interception + hold): ✅ DONE (2026-06-08).** Built a Claude Code
  PreToolUse hook (`spike/`) that intercepts Bash/Read/Write/Edit, auto-blocks `rm -rf`/`.env`,
  holds state-changers for synchronous human approval (approve→allow, timeout→deny), and
  audits every decision. All 5 scenarios pass standalone. **Revised arch:** hooks are the
  primary Claude Code enforcement surface (built-in tools are invisible to a pure MCP proxy).
  *Still to measure live:* the hook-timeout ceiling for long holds. Found a pending-cleanup bug.
- **M1 — Policy + HITL: �️ CORE DONE (engine), dashboard pending.** Single TS package:
  `PolicyEngine` (json-logic over `rules/default_policy.yaml`) + `IPendingStore`/`InMemoryPendingStore`
  + Engine with **Synchronous HTTP Hold** (open socket = the hold) + WS feed + dumb-client hook +
  fail-closed (timeout, disconnect-cleanup, engine-down) + JSONL audit. **11/11 smoke tests pass.**
  Remaining: the React localhost dashboard (Action Center w/ diff, Approve/Deny) wired over WS.
  *Demo today (CLI): "block `rm -rf`, hold `git push` for approval."*
- **M2 — Behavioral signal:** Redis sliding window + runaway detection + Live Stream feed.
  *Demo: "caught a loop."*
- **M3 — Content signal:** ONNX injection classifier on tool results + secret detection +
  exfil taint state machine → HITL. *Demo: "caught a poisoned README trying to steal .env." → this is the MVP.*
- **M4 — Polish + package:** `npx agentguard` CLI, config (`approval_surface`), Policy
  Editor UI, docs, example Claude Code config. *Goal: install in a minute.*
- **Post-MVP / Paid:** cloud + Slack + multi-seat + retention; AgentDojo Score; Langfuse;
  Cedar adapter; BYO-LLM intent layer; exfil content-match upgrade; $-budget via LLM-proxy.

---

## 8. Implementation Risks (to validate early)

1. **MCP client timeout during Synchronous Hold** — clients may cancel long requests.
   *Mitigation:* MCP **progress notifications** as keepalive; configurable timeout→Deny.
   **Validate in M1.**
2. **ONNX classifier latency** on tool results — must stay low (target single-digit→tens of ms on CPU).
   *Mitigation:* run async/post-flight; only on text results above a size threshold. **Validate in M3.**
3. **Prompt-Guard licensing & ONNX export** — confirm it's usable in an OSS product. **Validate before M3.**
4. **Tool taxonomy coverage** — misclassifying a network-egress tool weakens exfil defense.
   *Mitigation:* explicit allow-list + schema heuristics + "unknown tool → HITL" default.
5. **Bypass surface** — does the target agent let *all* tools route through one MCP server?
   *Validate the Claude Code integration assumption in M0.*

---

## 9. Open Flags / To-Research
- [ ] Pin exact injection model (Prompt-Guard-2 vs Rebuff) + license + ONNX path.
- [ ] Confirm MCP progress-notification keepalive survives Claude Code's client timeout.
- [ ] OPA embedded (WASM/Go sidecar) vs `opa` binary — pick deployment for `npx` simplicity.
- [ ] Redis as hard dependency vs optional (in-memory fallback for single-dev local mode?).
- [ ] Define the v1 default policy set precisely (the Rego rules shipped out of the box).

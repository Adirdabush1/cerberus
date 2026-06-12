# AgentGuard (APG) — Engineering Plan

> **A Web Application Firewall (WAF) for autonomous AI agents.**
> Local-first MCP gateway that intercepts every tool call, runs three independent
> security signals (Policy + Behavioral + Content), and pauses risky actions for
> real-time human approval. Open-Core distribution.

**Status:** M1–M5 shipped (2026-06; on `main`). Engine + 4 signals + risk + investigation UI + replay +
terminal-first approval + multi-agent adapters. Publish-ready v0.1.0 (Apache-2.0); `npm publish` pending.
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
- **M1 — Policy + HITL: ✅ DONE.** Single TS package: `PolicyEngine` (json-logic over
  `rules/default_policy.yaml`) + `IPendingStore`/`InMemoryPendingStore` + Engine with
  **Synchronous HTTP Hold** (open socket = the hold) + WS feed + dumb-client hook + fail-closed
  (timeout, disconnect-cleanup, engine-down) + JSONL audit. **11/11 engine smoke + WS path verified.**
  **Dashboard** (`/dashboard`, Vite+React+TS+Tailwind v4) — Action Center w/ diff + Approve/Deny +
  Live Stream, talks WS only, builds clean. *Demo: "block `rm -rf`, hold `git push`, approve from UI."*
- **M2 — Behavioral signal: ✅ DONE (local tier).** `BehavioralMonitor` interface +
  `InMemoryBehavioralMonitor` — per-session sliding window over tool-call **rate** and
  **repetition** (not token spend), two-tier (soft→escalate ALLOW to HITL, hard ceiling→auto-BLOCK).
  Wired into the intercept pipeline ahead of policy (a behavioral block overrides a permissive
  policy); `signal` provenance (`policy`/`behavioral`/`content`) threaded through audit + WS +
  dashboard (ANOMALY badges). Idle sessions evicted so the monitor can't leak. Env-configurable
  (`AG_WINDOW_MS`/`AG_MAX_RATE`/`AG_MAX_REPEAT`/`AG_HARD_MULT`). **9/9 unit + 8/8 e2e "caught a
  loop" through the real /intercept path** (`npm run test:behavioral`, `npm run e2e:behavioral`).
  *Redis sliding window deferred — see Open Flag #210; the interface is the drop-in seam for the
  multi-instance paid tier.* *Demo: "caught a loop."*
- **M3 — Content signal** (split after design review — see `brainstorms/m3-content-signal.md`):
  - **M3a — Deterministic content signal: ✅ DONE.** Contamination/taint model, fully local, zero ML.
    New PostToolUse hook → `POST /inspect` (observe-only) runs **secret detection** (curated patterns
    + entropy fallback) on tool results and updates a per-session contamination state;
    `InMemoryContaminationMonitor` (Redis-ready interface, mirrors M2). **Enforcement is PreToolUse-only**
    (D2): the three signals now fold via **uniform strictest-wins** (`combine()`, replacing M2's ad-hoc
    combine). Asymmetric decay (D5): content-confirmed taint persists for the session, path-risk decays
    (TTL). Tiered (D4): content-confirmed + egress → **HITL** with a rich exfil reason (`signal:'content'`),
    path-only → audit; auto-BLOCK deferred to v1.1 content-match. `/inspect` is sync-state-commit (D9).
    **8/8 unit + 10/10 e2e ("caught the exfil") + M1 smoke 11/11 + M2 8/8 still green** (`npm run
    test:content`, `npm run e2e:content`). Example Claude Code config in `examples/`. Dashboard shows
    EXFIL badges. *Demo: "loaded an AWS key, then the agent's outbound POST is held as an exfil risk."*
  - **M3b — Injection signal: ✅ DONE (core).** Async posture escalation (`brainstorms/m3b-injection-classifier.md`).
    `/inspect` classifies tool results; a flagged result raises the session's posture so the **next
    egress is held (HITL, `signal:'content'`, ruleId `content-injection`) even with no secret loaded** —
    enforcement stays PreToolUse-only (D2/D12), the flag decays via TTL. **Licensing resolved (D10/D11):**
    Meta Prompt-Guard is Llama-Community-licensed (NOT OSI) → kept out of core; the OSS-clean core uses
    a deterministic **heuristic baseline** always on, with **ProtectAI DeBERTa (Apache-2.0) ONNX as an
    optional companion** `@agentguard/injection-model` (`InjectionClassifier` interface; "recommended
    but optional", D13). Core publishable under MIT/Apache. **9/9 unit + 12/12 e2e ("caught the
    poisoned README") + full regression 67/67 green** (`npm run test:injection`, `npm run e2e:injection`).
    *ONNX adapter is a real scaffold, not yet run on the model — verify live + measure latency (Risk #2).*
  - **M3c — Risk Aggregation Engine: ✅ DONE.** Replaced strictest-wins `combine()` with
    `WeightedRiskEngine` (`src/risk/engine.ts`) — design in `brainstorms/m3c-risk-engine.md` (D14–D18).
    **Per-call score from decaying state** (D14), **hard floor + score** (D15: deterministic BLOCK
    bypasses the sum), **centralized versioned weight config** `rules/risk_weights.yaml` with
    normalization (group-max-sum so `secret+egress` stays HITL, not BLOCK — D4) + golden test vectors
    (D16). **AUDIT** = ALLOW-to-agent + risk annotation (D17; binary agent contract preserved);
    `risk { score, band, version, factors }` added to audit + violations. Calibration **conservative**
    (D18) — every M1/M2/M3a/M3b guarantee preserved; attribution uses signal-priority so `signal:'content'`
    survives. Dashboard shows score/AUDIT. **13/13 golden vectors + 6/6 e2e (four bands) + full
    regression 86/86 green** (`npm run test:risk`, `npm run e2e:risk`).
- **M4 — Packaging: ✅ DONE (core).** Design in `brainstorms/m4-packaging-ux.md` (D19–D21).
  `npm run build` compiles the engine (`tsc`→`dist/`) + dashboard (`vite`→`dashboard/dist`); `bin`
  prefers compiled `dist`, falls back to tsx for dev, exports `AG_HOME` for resource resolution. The
  **engine serves the built dashboard** at `/` (single process, SPA fallback + path-traversal guard;
  API/WS routes take precedence). **`agentguard init`** safely merges the Pre/PostToolUse hooks into
  `.claude/settings.json` (idempotent + backup; `--global`, `--print`). package.json `files` +
  `prepublishOnly`; README rewritten (install → init → run → demo). **13/13 init unit + full
  regression 99/99 green** incl. compiled-engine smoke. *Goal: install in a minute — met. Follow-ups
  since done: Investigation UI (B) → M4-B; `approval_surface` (C) → M4-C. Still open: a Policy Editor UI,
  and the actual `npm publish` (everything is publish-ready — Apache-2.0 + THIRD_PARTY_NOTICES — just not pushed).*
- **M4-B — Investigation UI: ✅ DONE.** `brainstorms/m4b-investigation-ui.md` (D22–D30). Event-sourced
  audit log (closed `event` enum + `requestId`/`sessionId` + runtime validation gate); `/sessions` +
  `/sessions/:id/timeline` read API; shared projector (open→resolve correlation + session "drivers");
  dashboard **Live / Sessions** tabs with a timeline, risk-factor breakdown, filters, and a **Replay**
  player. SessionStart/SessionEnd hooks reset monitors.
- **M4-C — Terminal-first notifications + approval: ✅ DONE.** `brainstorms/m4c-notification-tiers.md`
  (D34–D41). Terminal alerts via `/dev/tty` (stderr fallback); `agentguard pending|approve|deny` CLI;
  engine-side auto-open (`AG_AUTO_OPEN`). **HITL approval is terminal-native by default** via Claude
  Code's `permissionDecision:"ask"` (`AG_APPROVAL_SURFACE=terminal|dashboard`). This was the deferred
  M4 (C) `approval_surface`. Security: Origin allowlist on `/ws` + `/decision` (CSWSH fix). Cross-platform
  (Windows/POSIX). Published-ready: Apache-2.0 + THIRD_PARTY_NOTICES + npm metadata (v0.1.0).
- **M5 — Multi-agent support: ✅ DONE (core).** `brainstorms/m5-multi-agent.md` (D42–D46). One
  `agentguard hook --agent <claude|codex|cursor|cline>` binary over a pure per-agent adapter layer
  (`src/hook/adapters.ts`); engine/signals/risk/dashboard unchanged. ASK-vs-HOLD is a per-agent
  capability (claude/cursor → native prompt; codex/cline → dashboard hold) signaled via
  `MCPToolCall.approvalMode`. `agentguard init --agent <name>` writes each agent's config shape/location
  (+ fail-closed). MCP-proxy rejected (can't see internal shell/edit tools); Roo excluded (archived 2026).
  **adapters 22/22 + init 20/20; full regression unit 146 / e2e 36 green; each agent live-verified
  (ask vs hold, benign, apply_patch→WRITE).** *Codex/Cursor/Cline hook formats follow published specs —
  flagged for live re-verification per agent release.*
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

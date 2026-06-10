# M3 — Content Signal (the MVP milestone)

**Topic:** Injection classifier on tool *results* + secret detection + exfil taint state machine → HITL. Demo: *"caught a poisoned README trying to steal .env."*

Builds on M1 (policy + HITL + audit + dashboard) and M2 (behavioral signal; `SignalSource = 'policy' | 'behavioral' | 'content'` already threaded through contract/audit/WS/dashboard — `'content'` is the reserved slot we now fill).

## Key decisions (D1–D9) — M3a design locked
- **D1** Fully local, no external AI/API/cloud; local ONNX is part of the product; BYO-LLM = future plugin.
- **D2** Content signal = contamination/taint model. PostToolUse only OBSERVES; **enforcement is
  PreToolUse-only** on the next action. No retroactive result modification. Dissolves PostToolUse fail-open.
- **D3** Taint trigger = **content (primary) + path (complementary)**. Content confirms; path warns early.
- **D4** Exfil enforcement tiered: path-only→audit/allow; content-confirmed+egress→**HITL**; auto-BLOCK
  only with v1.1 content-match proof.
- **D5** Asymmetric decay: content-confirmed taint **persists for session**; path-risk **decays (TTL)**.
  Store = in-memory per-session, Redis-ready (M2 pattern).
- **D6** **Split** M3 → M3a (deterministic: secret+path+taint+exfil HITL, ships the demo) + M3b (ONNX).
- **D7** Signals combine via **uniform strictest-wins** (`BLOCK>HITL>ALLOW`); refactors M2's ad-hoc combine.
- **D8** Secret detection = **curated ~12 patterns + high-threshold entropy fallback**, size-capped, in `/inspect`.
- **D9** `/inspect` = **sync-state-commit** (await taint persist, no output touch) to kill the egress race.

### Detail
- **D1 — Fully local, no external AI dependency.** AgentGuard sits in front of *someone else's*
  agent; it never connects an LLM of its own. No external API, no API key, no content ever leaving
  the machine (no OpenAI/Anthropic/cloud). A **local ONNX classifier on CPU is part of the product**
  (a bundled model file, offline inference) — it satisfies "Zero API cost / nothing leaves the
  machine" and is NOT considered an external AI service. Signal 3 = local ONNX (Prompt-Guard) +
  heuristics + secret detection + taint tracking. **BYO-LLM / extra analysis providers = optional
  future plugin, never an MVP requirement to run AgentGuard.**

## Established facts (from codebase, not assumptions)
- Hook is **PreToolUse only** (`src/hook/index.ts`): posts the tool *call* to the engine `/intercept`, holds the socket, emits allow/deny. **The engine never sees tool *results* today.**
- Engine routes: `GET /health`, `GET /pending`, `POST /decision`, `POST /intercept`. HTTP response to the agent is `{action, reason}` only — `signal` lives in audit JSONL + WS.
- Taxonomy already tags EGRESS tools (`WebFetch`, `WebSearch`, `fetch`, `curl`, `http_request`, `send_to_webhook`); unknown → fail-closed strictest.
- Policy already **BLOCKs** `.env` reads outright (M1 rule). → A blocked read never "loads" a secret, so the taint model needs a different trigger than a blocked path-match.
- `signal: 'content'` enum value exists across `src/contract/types.ts` + `dashboard/src/contract.ts` but is never produced yet.

## Q&A log

**Q0 (constraint raised by user) — Does "no external AI" rule out the local ONNX classifier?**
A: No. "No external AI" = no external API, no API key, no content leaving the machine to a cloud
service. A local ONNX model on the user's CPU is part of the product, not an external AI service.
→ locked as **D1**. BYO-LLM = optional future plugin, not MVP.

**Q1 — How does the engine receive tool-result content?**
A: **PostToolUse hook → new `/inspect` endpoint.** A second hook (PostToolUse) posts the tool
result post-flight to an agent-agnostic `/inspect` endpoint, where injection scan + secret scan +
taint-set run. The egress-while-tainted decision stays on the existing `/intercept` (PreToolUse).
Engine `/inspect` logic is agent-agnostic; the PostToolUse hook is just the Claude Code adapter
(MCP proxy can feed the same endpoint later for non-CC agents). Covers built-in Read/WebFetch,
which is the demo's core (MCP-proxy-only would miss them).

## Established facts — PostToolUse (verified via claude-code-guide + docs)
- Fires **after** the tool executes but **before** the result is sent to the model → this is our
  interception point. Receives `tool_name`, `tool_input`, **`tool_response`**, `session_id`, `cwd`.
- **Cannot block** (tool already ran). **Can replace the result** via `updatedToolOutput` and feed
  an explanation to the model via `additionalContext`. → "withhold/redact a poisoned result before
  the model reads it" **is achievable**.
- ⚠️ **Structurally fail-OPEN:** if the hook crashes or exceeds its `timeout` (default 600s), Claude
  Code sends the **original, unmodified** result to the model. We cannot make PostToolUse fail-closed
  the way PreToolUse can. → Injection scanning is **best-effort defense-in-depth**, NOT a hard
  guarantee. The hard backstop remains the **PreToolUse policy** that blocks the *action* the
  injection tries to cause (PLAN Signal 3, Layer 2).
- Implication: set a **tight hook timeout** (single-digit seconds) so a slow/hung scan degrades fast
  rather than stalling the agent for minutes.

**Q2 — Role of PostToolUse/ONNX, and where enforcement happens.**
A: **D2 — Content signal is a CONTAMINATION (taint) model, enforced PRE-FLIGHT on the NEXT action.
No retroactive modification of already-executed results.**
- PostToolUse → `/inspect` is **observe-only**: run secret detection + ONNX injection classification
  on `tool_response`, update the per-session **contamination state**. We deliberately do NOT use
  `updatedToolOutput`/withholding even though Claude Code supports it.
- **PreToolUse → `/intercept` is the SOLE enforcement point.** It now combines
  `policy + behavioral + contamination` to decide allow/review/block on the next call.
- Mental model: **prevention-of-next-action, not retroactive result modification.**
- This **dissolves the PostToolUse fail-open concern** — no guarantee ever rested on PostToolUse;
  the hard, fail-closed guarantee is always PreToolUse.
- **Timing (only remaining sub-point):** taint must be committed before the next `/intercept` reads
  it. Normally fine (LLM round-trip ≫ inspect latency). To eliminate the race entirely, make
  `/inspect` a **fast synchronous state-commit** (hook waits only for state to persist; no output
  modification). → leaning sync-state-commit; confirm in Q3/impl.
- Supersedes the earlier "hybrid withhold" framing — withholding is OFF the table.

**Q3 — What sets the contamination (taint) flag?**
A: **D3 — Combined model: Content is the PRIMARY trigger, Path is a COMPLEMENTARY signal.**
- **Path risk** (`.env`, `~/.aws`, `*.pem`, …) on the tool call = **early warning** (cheap, known
  ahead, but a guess).
- **Content risk** (secret patterns in the tool *result*) = **stronger confirmation** the session is
  contaminated (certain, but only after the tool ran).
- Neither alone — both together. Product framing (locked):
  > "AgentGuard builds a per-session contamination state from a combination of **path risk** and
  > **content risk**, but enforcement itself happens only before the next action."
- Complements (does not duplicate) the existing M1 `.env`-block policy: policy blocks *access* to
  obvious paths; taint tracks what actually *loaded* and what happens *next* (exfil).

**Q4 — Enforcement when an egress call arrives while the session is contaminated.**
A: **D4 — Tiered escalation, enforced at PreToolUse:**
- **path-only warning + egress → audit/allow** (log + dashboard tag, no hard prompt — avoids HITL
  noise on benign `~/.aws` access followed by a legit API call).
- **content-confirmed + egress → HITL** (the canonical "read a secret 2m ago, now POSTing to X —
  approve/block?"). Reuses the M1 HITL machinery verbatim (sync hold, approve→ALLOW, deny/timeout→
  fail-closed BLOCK); `signal: 'content'`. No new infra.
- **auto-BLOCK only with real proof** — deferred to v1.1 **content-match** (outbound payload actually
  contains the secret bytes). Suspicion → HITL; proof → BLOCK.
- `egress` = existing taxonomy `EGRESS` category; unknown tool → fail-closed.

**Rationale / design north-star (user, grounded in OWASP LLM Top 10):**
"Best = a **local-first security engine**: PreToolUse = hard gate, PostToolUse = contamination/taint
engine, session state decides the next calls. Core is local-only (heuristics + local ONNX/Prompt-
Guard + secret detection + taint), no external API. Enforce the *next action*, don't try to 'fix' a
result already sent to the model. Tiered routing by risk. Adapter layer for Claude Code today, other
interfaces tomorrow." Aligns with OWASP: treat all external data as untrusted, filter injection
patterns, and **never rely on the model's own behavior to enforce security**. Relevant OWASP LLM
risks: Prompt Injection, Insecure Output Handling, Sensitive Information Disclosure, Excessive Agency.

**Q5 — Does taint decay (TTL), and where is it stored?**
A: **D5 — Asymmetric contamination model.**
- **Content-confirmed taint = persistent for the entire session lifetime; does NOT decay.** It is
  verified exposure of sensitive data — a TTL here would be a trivial bypass (load secret, wait out
  the timer, exfil freely). Cleared only when the session ends (`reset`, same as M2).
- **Path-based risk = heuristic, decays via a TTL function** to avoid long-lived false positives on
  benign access to sensitive-looking dirs.
- **PreToolUse enforcement on the combined state:** persistent content taint escalates **all** egress
  to HITL; path risk influences routing only when **recent or accumulated**.
- **Store:** in-memory per-session behind an interface (Redis-ready drop-in for the paid tier, same
  pattern as `BehavioralMonitor`). No new infra. State ≈
  `{ contentConfirmed: {secretTypes, ts}, pathRisk: {paths, lastTs}, injectionFlagged: ts }`.
- Strong guarantee for confirmed leaks; usability preserved for legit dev workflows.

**Q6 — Build M3 in one slice or split?**
A: **D6 — Split.**
- **M3a (ship first) — deterministic content signal:** secret detection (regex prefixes + entropy
  fallback) + path risk + asymmetric taint (D5) + exfil→HITL (D4). Fully local, zero ML, zero
  licensing risk, e2e-tested like M2. **Delivers the flagship demo** ("poisoned README → steal .env"
  caught at the exfil step) WITHOUT any model.
- **M3b (layer on after) — ONNX injection classifier:** async Prompt-Guard that raises session
  posture. Gated behind resolving the license + ONNX-export (#207) + latency (#2) unknowns.
- Net: the MVP demo is reachable in M3a without ML risk. ONNX-specific questions (model choice,
  injection async effect) **deferred to M3b planning**.

**Q7 — How do the three signals combine into one PreToolUse decision?**
A: **D7 — Uniform strictest-wins.** Each signal yields an action; `final = strictest(policy,
behavioral, content)` on the order `BLOCK > HITL > ALLOW`. Result `signal` = the one that set the
binding action. Content's contribution on an incoming call: egress + content-confirmed → `HITL`;
egress + path-only(recent) → audit only (still `ALLOW` for blocking); non-egress → `ALLOW`.
So a policy `BLOCK` on egress still wins, but content `HITL` escalates an egress the policy permitted.
**Also refactors away the M2 ad-hoc combination** into this single rule.

**Q8 — Secret-detection source/scope (the primary content-taint trigger in M3a).**
A: **D8 — Curated set + entropy fallback.** ~12 high-value structured patterns (AWS `AKIA`, GitHub
`ghp_`/`gho_`, OpenAI `sk-`, Slack `xoxb-`, Google `AIza`, `-----BEGIN … PRIVATE KEY-----`, JWT,
`api_key=`/`password=` assignments) — may adapt gitleaks' *patterns* (MIT) without depending on the
binary. High-threshold Shannon-entropy fallback only for unprefixed secrets, tuned conservative to
limit FPs. Runs on `tool_response` text in `/inspect` with a **size cap** (scan first N KB) to bound
latency. Lean + low-FP + easy to extend later.

**Q9 — `/inspect` sync-state-commit or pure-async?**
A: **D9 — sync-state-commit.** The PostToolUse hook waits only until `/inspect` has persisted the
taint (regex + entropy = sub-ms), without touching the output (no withhold). Eliminates the race on
the first egress after a secret loads; stays faithful to D2. (In M3b the heavy ONNX scan runs async
*after* the state-commit — cheap signal sync-commits, heavy signal stays async.)

## M3a design — COMPLETE (no remaining design forks; only impl details below)
**Build surface:**
- Extend `src/hook/index.ts` to handle PostToolUse (route by `hook_event_name`) → POST
  `{tool, input, tool_response, sessionId}` to `/inspect`, await state-commit ack.
- New engine `POST /inspect`: secret-detect + path-risk update → commit to contamination store → ack.
- New `src/signals/content.ts`: `ContaminationMonitor` (interface + in-memory impl, mirrors
  `behavioral.ts`/M2; Redis-ready). Secret detector + path-risk submodules.
- Refactor `server.ts` `handleIntercept` to **strictest-wins** across policy/behavioral/content (D7).
- `examples/` Claude Code config: register the PostToolUse hook.
- Tests: `scripts/content.test.ts` (unit) + `scripts/content-e2e.mjs` (load secret via an ALLOWED
  read → egress → HITL with `signal:'content'`).

**Discovered during build — default policy already HITLs all EGRESS** (`hitl-egress-category` rule).
So under the stock policy, content's egress→HITL does NOT change the *action* (it would be HITL
anyway). Content's M3a value is therefore: (1) **attribution + rich exfil reason** the human sees
("AWS key loaded 2m ago, now POSTing to X") — content WINS the HITL tie over the generic egress
rule; (2) the real *escalation* lands once a user **relaxes** the egress policy (e.g. allow-list dev
domains) — then a tainted session re-escalates to HITL. Auto-BLOCK on proof stays v1.1 (D4).

**Impl-detail notes (not forks):** path-risk recorded at `/intercept` when a sensitive-path call is
allowed through (path known from the call); `/inspect` handles content (needs the result). Path-risk
TTL default ~5 min. `signal:'content'` enum already exists in the contract. Dashboard may add a
"session tainted" indicator (signal badge already supported from M2).

## Open flags — remaining
- **(M3a impl)** final path-risk TTL value + secret size-cap KB + curated pattern-list contents.
- **(M3b)** Prompt-Guard-2 license + ONNX export path (PLAN Open Flag #207, Risk #3).
- **(M3b)** ONNX classifier CPU latency target: single→tens of ms (Risk #2).
- **(M3b)** Async injection lane: exact "elevate session risk posture" mechanism — does a prior
  injection-flag make the next egress HITL even with no secret loaded?

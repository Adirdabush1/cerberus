# M3b — ONNX Injection Classifier (defense-in-depth)

**Topic:** Add a local prompt-injection classifier on tool results that raises the session's risk
posture (async, post-state-commit) so the PreToolUse gate gets stricter. Layers on top of M3a's
deterministic contamination model. No external API (D1). Enforcement stays PreToolUse-only (D2).

Builds on M3a (`/inspect`, `ContaminationMonitor`, strictest-wins `combine()`, `signal:'content'`).

## Established facts (verified via web research — resolves PLAN Open Flag #207 + Risk #3)
- 🚨 **Meta Prompt-Guard (v1 86M, v2 86M, v2 22M) = Llama Community License = NOT OSI open source.**
  700M-MAU clause, Acceptable-Use Policy (field-of-use limits), mandatory "Built with Llama"
  attribution, derivative-naming rule. Gated on HF. Community ONNX re-exports inherit `license: llama4`.
  → **Incompatible with a clean OSS (Apache/MIT) product.** This contradicts the PLAN's Prompt-Guard-2
  assumption.
- ✅ **ProtectAI `deberta-v3-base-prompt-injection-v2` = Apache-2.0**, not gated, pre-exported ONNX
  (`onnx/` folder), int8-quantized variant (~180–200MB) for CPU. Base mDeBERTa-v3-base, ~184M params.
  Trade-off: **English-only**, weaker on pure jailbreaks, not for scanning system prompts. Lighter
  Apache options: `protectai/deberta-v3-small-prompt-injection-v2`, `fmops/distilbert-prompt-injection`.
- **Runtime:** `@huggingface/transformers` (Apache-2.0, successor to `@xenova/transformers`) → uses
  `onnxruntime-node` (CPU) and handles DeBERTa SentencePiece tokenization. Offline via
  `env.allowRemoteModels=false` + `env.localModelPath`. Zero network at runtime after the model is present.
- **Distribution:** DON'T bundle weights (too big for npm). Download-on-first-run into a local cache,
  then load offline. Apache-2.0 permits redistribution; Llama license would not.
- **Latency:** no official CPU benchmark; DeBERTa-base int8 ≈ tens of ms for short text (Risk #2 — to
  measure on our hardware). Async lane (D2/D9) means it never blocks the agent anyway.

## Key decisions
- **D10 — Injection-classifier strategy: ProtectAI in core, BYO-model plugin for the rest.**
  - **Core classifier:** ProtectAI `deberta-v3-base-prompt-injection-v2` (Apache-2.0), ONNX Runtime.
  - **Interface:** `InjectionClassifier` — `ProtectAIClassifier` now; `LlamaPromptGuardPlugin` (and
    others) as a **future opt-in plugin the user fetches themselves** (they accept Meta's terms).
  - **Licensing policy:** core product = **Apache-2.0 / MIT only**; plugins = any compatible license.
    Core stays 100% OSS, freely distributable, no Meta/Llama dependency (clean for a future
    commercial sale). Matches D1 (core never depends on a specific model).

- **D11 — License verdict (verified against official sources; not legal advice):**
  Publishing ALL of AgentGuard under **MIT (or Apache-2.0) is OK — conditionally.**
  | Component | License | Source |
  |---|---|---|
  | ProtectAI deberta-v3-base-prompt-injection-v2 (code + ONNX weights) | **Apache-2.0** | HF model-card front-matter `license: apache-2.0`; `onnx/` folder same license |
  | @huggingface/transformers (transformers.js) | **Apache-2.0** | npm + repo LICENSE |
  | onnxruntime-node | **MIT** (Microsoft) | npm + microsoft/onnxruntime LICENSE |
  | Meta Llama-Prompt-Guard-2-86M | **Llama 4 Community License — NOT OSI**, gated | llama.com/llama4/license; OSI statement |
  **Conditions to publish clean:** (1) ship a `THIRD_PARTY_NOTICES` carrying the Apache-2.0 text +
  ProtectAI/transformers.js NOTICE content + onnxruntime MIT notice; (2) retain ProtectAI attribution
  (and the CC-BY/MIT training-data attributions on the card where applicable); (3) **keep Llama
  Prompt Guard strictly OUT of core** — plugin only, user-fetched; plugin glue-code may be MIT but the
  model stays under the Llama license and must NOT be branded OSS. Apache-2.0 ↔ MIT are compatible
  (an MIT project may include Apache-2.0 deps as long as attribution obligations are kept).
  **Pre-release caveat:** confirm ProtectAI's repo root has no separate `NOTICE`/`LICENSE` file beyond
  the tag; carry it if present.

## Q&A log

**Q1 — Model/license for the injection classifier?** → **D10** (ProtectAI core + Llama future plugin).
**License verification** → **D11** (publishable under MIT/Apache, conditions; Llama out of core).

**Q2 — What does the injection classifier DO?**
A: **D12 — Option A: async posture escalation.**
- The ONNX classifier runs async on the tool result (post state-commit, D9/D2). It CANNOT withhold the
  result or warn the model about it — it updates contamination state for the *next* PreToolUse gate.
- Adds a contamination dimension `injectionFlagged` (ts + score + source tool).
- An injection-flagged session escalates the **next EGRESS to HITL even with no secret loaded**
  (poisoned content may try to exfil via instructions); consider also escalating `EXECUTE`.
- Surfaced as `signal:'content'` with an injection reason ("tool result from X flagged as
  prompt-injection, score 0.93").
- **Decays via TTL** (like path-risk, D5) — it's a probabilistic model signal, not a confirmed secret;
  a single false positive must not lock the session for its lifetime.
- Dashboard alert. Threshold ≈ 0.85 (PLAN). Model returns a 0–1 score → store it (forward-compatible
  with the M3c risk score).
- Build A now; it slots into the existing strictest-wins `combine()` (injection-flag contributes HITL).

## Spawned milestone — M3c (Risk Aggregation Engine) — PLAN THE NEXT STEP, don't build yet
User's strategic call (competitive differentiator vs Protect AI / Lakera / HiddenLayer / Prompt
Security): replace the boolean strictest-wins (D7) with a **weighted numeric risk score per session**.
```
sessionRisk = { policy, behavioral, content, injection }   // additive weights, e.g.
  prompt-injection score 0.93  → +40
  sensitive path               → +20
  secret detected              → +80
  repeated attempts            → +30
bands:  0–49 ALLOW · 50–79 AUDIT · 80–119 HITL · 120+ BLOCK
```
M3c generalizes `combine()` (D7) — strictest-wins becomes a special case of the score bands. M3b's
injection signal already emits a numeric score, so it feeds M3c directly. **Get a dedicated grill-me
before building M3c.**

Product roadmap (user): M1 Policy · M2 Behavior · M3a Content/Taint · M3b Injection · **M3c Risk
Aggregation** · M4 Dashboard + Investigation UI · M5 Multi-agent (Claude Code, Codex, Cursor, Roo, Cline).

**Q3 — Is the ONNX classifier a hard or optional dependency?**
A: **D13 — "Recommended but optional", as a separate companion package.**
- `npm install agentguard` → lean core (M1/M2/M3a), **zero native deps**, works immediately. Runs in
  a minute (M4 goal).
- `npm install @agentguard/injection-model` → pulls `@huggingface/transformers` + `onnxruntime-node`
  + the ProtectAI model fetcher, and activates the injection lane.
- The engine **detects** whether the companion package is present; if absent, `/inspect` skips the
  ONNX step (secret detection still runs) — `InjectionClassifier` reports "disabled", no crash.
- Build defaults (accepted): model **download-on-first-run** into a local cache; flag **threshold ≈
  0.85**; MVP escalates **egress only** (not EXECUTE) to limit false positives.
- Matches D1 (core never depends on a specific model) + D10/D11 (core stays Apache/MIT clean).

## Build plan for M3b (proposed — see chat for go/no-go)
- **Build now in core (fully verifiable, zero heavy deps):** `InjectionClassifier` interface; an
  `injectionFlagged` contamination dimension (score + ts, TTL decay); `combine()` extension
  (injection-flag → egress HITL, `signal:'content'`); optionality detection; unit + e2e tests driven
  by a **deterministic heuristic classifier** (regex for obvious injection, e.g. "ignore previous
  instructions") that doubles as the always-on baseline when the model package is absent.
- **Build as the companion adapter (real code, NOT run in this session):** `OnnxInjectionClassifier`
  using `@huggingface/transformers` + ProtectAI weights. Live inference verified manually with the
  model present — the ~180MB model + native binary aren't downloaded/run in the automated suite.

## Open flags (to go find out)
- Measure real CPU latency of the chosen ONNX model on a short tool result (Risk #2).
- Confirm quantized ONNX file size + exact HF path/revision to pin.

# M3c — Risk Aggregation Engine

**Topic:** Replace the boolean strictest-wins `combine()` (D7) with a **weighted per-session risk
score** across all signals (policy / behavioral / content / injection) → mapped to action bands
(ALLOW / AUDIT / HITL / BLOCK). The competitive differentiator vs Protect AI / Lakera / HiddenLayer /
Prompt Security. Strictest-wins becomes a special case of the bands.

## User's sketch (starting point)
```
sessionRisk = { policy, behavioral, content, injection }   // additive weights, e.g.
  prompt-injection score 0.93  → +40
  sensitive path               → +20
  secret detected              → +80
  repeated attempts            → +30
bands:  0–49 ALLOW · 50–79 AUDIT · 80–119 HITL · 120+ BLOCK
```

## Established facts (from the M1–M3b build)
- `combine()` (in `src/engine/server.ts`) currently does strictest-wins: BLOCK > HITL > ALLOW, with
  attribution to the binding signal. M3c replaces it.
- Signal outputs today are **categorical**, not numeric:
  - policy → `PolicyDecision { action: ALLOW|BLOCK|HITL, ruleId, reason, category }`
  - behavioral → `AnomalyVerdict { severity: review|block|null, reason }` (monitor also holds raw rate/repeat counts)
  - content → `ContentVerdict { action: HITL|null, reason, kind }` (monitor holds content/path/injection dims)
  - injection → `InjectionVerdict { score: 0–1, label }` (already numeric — feeds M3c directly)
- `FinalAction = ALLOW | BLOCK`; `PolicyAction` adds `HITL`. **AUDIT is a NEW tier** to define.
- Per D5/D12 the session state ALREADY decays appropriately (content-confirmed persists; path/injection
  decay via TTL; behavioral uses a sliding window). So "session memory" exists and decays.
- Hard guarantees that MUST survive any scoring change: policy `BLOCK` on `rm -rf`/`.env`; fail-closed
  on unknown tools; HITL timeout → BLOCK.

## Key decisions
- **D14 — Per-call score from decaying state (NOT a monotonic accumulator).** The risk score is
  recomputed on each call from (a) the current call's signal weights + (b) the session's already-
  decaying state (content-confirmed persists; path/injection decay via TTL; behavioral sliding
  window). No separate ever-growing ledger — that would make every long session eventually stick at
  BLOCK. "Repeated attempts" is captured by behavioral's decaying window count. Preserves D5's
  asymmetry: a loaded secret keeps the score high all session; stale heuristics fade.

## Q&A log

**Q1 — Per-call score vs accumulator?** → **D14** (per-call from decaying state).

**Q2 — How do hard guarantees coexist with the score?**
A: **D15 — Hard floor + score for the rest.** Deterministic BLOCK signals (policy `BLOCK`, behavioral
hard-block/runaway) are a **hard floor** → BLOCK regardless of score; they bypass the sum. Everything
else (policy HITL/ALLOW, behavioral review, content taint/injection, path-risk) contributes **weights**
→ summed → band. The band can independently reach BLOCK at ≥120 (many soft signals stacking). Two
BLOCK paths: hard guarantee + score≥120. Never let a numeric score un-block a deterministic prohibition
(OWASP: don't rely on a score to enforce an absolute rule).

**Q3 — Where do the weights live / how do signals feed the score?**
A: **D16 — Centralized weight table (config-as-data); signals emit FACTS, not points.**
- Each signal exposes numeric facts (content → active dims + injection score; behavioral → rate/repeat
  magnitude; policy → action + category; injection → score). The RiskEngine maps facts→points via one
  tunable table (a YAML like `rules/default_policy.yaml`). Tuning lives in one place; signals stay
  decoupled from scoring policy. Requires light enrichment of the monitors to expose the facts.
- **Three drift-guards (user, best practice — prevent "weight drift over time"):**
  1. **Normalization layer** — per-factor caps so no single weight can dominate/break the score; the
     summed contribution per category is bounded and documented.
  2. **Config versioning** — `version: m3c-risk-v1.0` stamped in the weights file and in the audit
     entry, so a decision is always traceable to the exact weight set that produced it.
  3. **Fixed golden test vectors** — pinned cases (injection-simple, injection-repeated, benign
     false-positive, secret+egress, multi-signal stack) that lock expected band outputs; any weight
     change must keep them passing. This is what makes it a production-trustworthy scoring engine, not
     a heuristic script.

**Q4 — What does the new AUDIT tier do, and how does it enter the contract?**
A: **D17 — AUDIT = ALLOW to the agent + a risk annotation.** Bands: `0–49 ALLOW · 50–79 AUDIT ·
80–119 HITL · 120+ BLOCK`. The agent only ever sees ALLOW/BLOCK (binary contract preserved —
`FinalAction` unchanged, no third agent-facing value, keeps M5 adapters simple). AUDIT → agent gets
ALLOW, but the record carries `risk: { score, band, version, factors[] }` and the dashboard surfaces
it as "allowed but borderline" — passive surfacing, no human prompt. Generalizes D4's
"path-only egress → audit/allow". **Contract change:** add `risk` block to `AuditEntry` and
`SecurityViolation`; `action` stays ALLOW for AUDIT, the `band` field distinguishes.

**Q5 — Calibration philosophy: preserve existing guarantees, or shift to stack-to-escalate?**
A: **D18 — Conservative: preserve guarantees, add stacking on top.** Strong/high-confidence signals
(secret loaded, policy HITL, content-exfil, injection-on-egress, behavioral review) get weight ≥ the
HITL threshold → each still reaches HITL ALONE, exactly as today. Aggregation ADDS value: weak signals
(path-risk) stack, and several soft signals together can reach BLOCK. No existing guarantee is
relaxed; existing e2e/smoke expectations hold. Shifting to "stack-to-escalate" (B) is later a config
re-tune (versioned), not a code change — when HITL noise justifies it.

- **Calibration constraint (surfaced during Q5):** the default policy already HITLs all EGRESS
  (`policy_hitl`), so egress is always ≥ HITL threshold. Naive summing of `secret(80) + egress(80)`
  would hit the BLOCK band — which would CONTRADICT D4 (exfil → HITL, NOT auto-block; auto-block is
  v1.1). The **normalization layer (D16 guard #1) must prevent this**: cap/normalize so overlapping
  HITL-level signals don't silently escalate exfil to BLOCK. The golden vectors (D16 guard #3) pin it:
  `secret+egress → HITL`, single strong signal → HITL, weak stacks → escalate.

## M3c design — COMPLETE (D14–D18; no remaining forks — calibration is build, guarded by golden vectors)
**Build surface:**
- `src/risk/engine.ts` — `RiskEngine` replacing `combine()`: hard-floor check first (deterministic
  BLOCK → BLOCK), else sum weighted facts (normalized/capped) → band → action. Reads a versioned
  weights config.
- `rules/risk_weights.yaml` (or similar) — `version`, per-factor `weights`, `caps`, `bands`. Config-as-data.
- Light enrichment of behavioral/content monitors to expose numeric facts (rate/repeat magnitude,
  active taint dims) for the scorer.
- Contract: add `risk: { score, band, version, factors[] }` to `AuditEntry` + `SecurityViolation`;
  AUDIT band → agent ALLOW.
- `scripts/risk.test.ts` golden vectors (injection-simple, injection-repeated, benign FP, secret+egress,
  multi-signal stack) + an e2e showing an AUDIT-band allow and a stacked BLOCK.
- Dashboard: AUDIT badge + show score/band on cards & audit rows.

## Status: ✅ BUILT & VERIFIED
Implemented `src/risk/engine.ts` (`WeightedRiskEngine`) + `rules/risk_weights.yaml` (v `m3c-risk-v1.0`);
replaced `combine()` in the engine; added `risk` to the contract (src + dashboard); golden vectors in
`scripts/risk.test.ts`; four-band e2e in `scripts/risk-e2e.mjs` (+ `scripts/fixtures/relaxed-egress.yaml`);
dashboard shows score/AUDIT. **13/13 golden + 6/6 e2e + full regression 86/86 green.**

**Final calibration (v1.0):** groups `egress {policy_egress 75, content_exfil 80, content_injection 50,
path_risk 25}`, `command {policy_hitl 75}`, `behavioral {behavioral_review 75}`; bands audit 40 / hitl
75 / block 150. Score = Σ over groups of max(points). Attribution by signal-priority content >
behavioral > policy (preserves M3a/M3b `signal:'content'`).

## Open flags
- (resolved in build) weight/band numbers locked at v1.0 by the golden vectors.
- (future) graduated weights once monitors expose richer facts (injection score × weight, behavioral
  magnitude); shift to "stack-to-escalate" (Q5 option B) is a versioned config re-tune, not code.

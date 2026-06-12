# M6 — Egress content-match + provenance (real DLP)

**Topic:** Upgrade the exfil gate from coarse session-taint ("read a secret → hold ALL egress") to a
precise content-match: inspect the OUTBOUND payload and block when it actually carries a loaded secret,
with provenance (which secret/source) and a confidence.

## Established facts (current content signal — src/signals/content.ts)
- `inspect()` (PostToolUse) detects secret **types** via `SECRET_PATTERNS` + entropy fallback, and stores
  ONLY `st.content.types` (a Set of type names) — **the secret VALUES are not kept**.
- `evaluate()` (PreToolUse) at an EGRESS call: if `st.content` exists → `content-exfil` HITL (any taint →
  hold any egress). Risk engine weights `content-exfil` into the EGRESS group.
- So today it's binary session taint → HITL. No payload inspection, no value match, no provenance.
- The `/intercept` egress call already has the payload in `call.input` (url + body) — the data is there.

## Key decisions
- **D47 — Confirmed match → strong HITL, not hard BLOCK** (owner choice). The new `content-exfil-match`
  kind weights `egress.content_exfil_match: 120` → HITL alone, BLOCK only if it stacks with another
  concern (consistent with the group-max-sum model). Taint-without-payload-match stays the existing
  `content-exfil` HITL (suspicion).
- **D48 — Store the raw secret in SESSION MEMORY only; never persist it.** `inspect()` keeps a
  `SecretRef{value,type,source,hash,confidence}` in `st.content.secrets` for matching; dropped on
  `reset()`/SessionEnd. Audit/dashboard/verdict-reason carry only `sha256` prefix + type + source —
  NEVER the value (verified by test).
- **D49 — Encoding coverage v1 = raw + base64 + hex + url-encode** of the KNOWN secret, substring-searched
  in the serialized egress payload (`JSON.stringify(call.input)`, capped at scanLimitBytes). Cheap
  (encode the secret, not decode the payload) and catches the obvious encode-then-exfil.
- **Provenance:** reason reports type, `source` (`<tool> <path>:<line>`), `sha256` prefix, confidence
  (pattern 0.85–0.98 / entropy 0.75), and the destination host.

## Build — DONE
- `content.ts`: `detectSecretValues` (captures value+line+confidence), `inspect()` stores SecretRefs
  (memory-only, capped 50), `evaluate()` egress: `matchSecret` over raw+encoded forms → `content-exfil-match`.
- `risk/engine.ts` + `risk_weights.yaml`: new `content_exfil_match` factor (120), version → `m3c-risk-v1.1`.
- `projector.ts`: driver label "secret in outbound payload (confirmed)".
- Tests: content 8→12 (match / no-match / base64 / no-raw-value), version pins bumped. Full regression
  unit 164 / e2e 36 green. **Live-verified** via HTTP: ruleId `content-exfil-match`, reason carries
  sha256 + source + dest, never the raw value.

## Open flags
- base64 padding variance (`=`) and split-across-calls exfil not covered in v1.
- private-key value-match is weak (only the header is captured) — taint still fires, match may not.
- raw secret in engine RAM until session reset/end (by design, D48) — fine for the local single-user tier.

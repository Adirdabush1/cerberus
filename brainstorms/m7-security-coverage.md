# M7 — Expand security coverage (prompt injection & beyond)

**Topic:** Broaden Cerberus's detection — strengthen prompt-injection (the 🟡 area) and add adjacent
security checks.

## Established facts (current state)
- **Injection** (`src/signals/injection.ts`): 6 heuristic regex, **binary** score (0/1), catches obvious
  phrasings only. Gates **EGRESS only** (posture → next egress HITL). Scans **tool RESULTS only** (/inspect).
- **ONNX companion** (ProtectAI DeBERTa) is a **scaffold, never run**; the loader still imports the STALE
  `@agentguard/injection-model` (should be `@cerberussec/injection-model`) — **rename bug, fix regardless**.
- Risk engine weights `content-injection` in the egress group (50).

## Candidate expansions
1. **Activate the ONNX classifier** (DeBERTa) — heuristic → ML. Biggest accuracy jump; bigger lift (deps,
   make `packages/injection-model` real + publish, measure latency, keep core lean/optional).
2. **Expand + score the heuristics** — more injection families (role-injection `system:`, tool-result
   markdown-image exfil, unicode/zero-width tricks, "for the assistant only"), multi-hit → higher score.
   Cheap, immediate, complements ONNX.
3. **Broaden enforcement scope** — raised posture should gate **WRITE/destructive** too, not just egress
   (a poisoned doc → "write this backdoor" / "rm -rf"). Closes a real gap.
4. **MCP tool-poisoning detection** — scan MCP tool *descriptions* for injected instructions ("rug pull")
   — a novel, on-trend agent threat; strong differentiator.
5. **PII detection** — emails / SSN / credit cards (Luhn) in results + egress; broadens DLP beyond secrets.
6. **Encoding-aware scanning** — decode base64/hex before injection + secret detection (anti-obfuscation).

## Key decisions
- **D50 — Build order (owner):** (1) Expanded + scored heuristics → (2) Write/destructive enforcement →
  (3) MCP tool-poisoning detection → (4) ONNX optional engine (last; heavier). Steps 1–3 are core /
  deterministic / no heavy deps; step 4 stays the optional companion package.
- **D51 — Also fix the rename bug:** `injection.ts` `COMPANION_PACKAGE` `@agentguard/injection-model` →
  `@cerberussec/injection-model` (done regardless of which steps land).
- Branch protection is on `main` → all of M7 lands via `feat/m7-security-coverage` → PR → CI → merge.

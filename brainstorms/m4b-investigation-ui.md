# M4-B — Investigation UI / Timeline

**Topic:** A session-centric investigation view (timeline + risk trajectory + HITL/exfil context),
built on a sound event model — decided BEFORE any React.

## Key decisions

- **D22 — Timeline = event-sourced projection over the Audit Log (single source of truth).** The
  audit log (append-only JSONL, already broadcast over WS) is the one record; the timeline is a
  PROJECTION of it. Monitors stay ephemeral/decaying runtime state — never a parallel history. If the
  timeline needs an event the log lacks, add an event TYPE to the log; never a second history store.

- **D23 — Enrich the audit log with a first-class `event` discriminator; EMIT observed facts, DERIVE
  interpretations.**
  - Add `event` to the audit record: `decision | hitl-opened | hitl-resolved | session-started |
    session-ended | taint-loaded | injection-detected | tool-failed`. (Today everything is implicitly
    `decision` + two inspect events.)
  - **EMIT (observed):**
    - `session-started` / `session-ended` — via Claude Code **SessionStart / SessionEnd hooks**
      (confirmed to exist; observability-only). SessionEnd ALSO drives `monitor.reset(sessionId)` —
      which closes the M2/M3 monitor-eviction loose end.
    - `hitl-opened` (on violation register — today we broadcast `violation` over WS but don't audit
      it) and `hitl-resolved` {approved|rejected|expired} **with latency** (resolved.ts − opened.ts).
    - `tool-failed` — observable: a PostToolUse **failure** payload carries `error` instead of the
      result, so `/inspect` can distinguish completed vs failed. (Correction to an earlier assumption.)
  - **DERIVE in the projection (NOT source events):**
    - **risk-band transitions** (ALLOW→AUDIT→HITL→BLOCK) — computed from the sequence; emitting them
      would bake a projection choice ("session band" = max? latest? peak?) into the source. Keep the
      source raw per-call assessments.
    - `tool-called` = the `decision` entry we already log.

- **D24 — Identifier model: sessionId ✓, requestId ✓, traceId ✗ (no Claude-Code id).**
  - `sessionId` = Claude Code `session_id` (top of the hierarchy). ✓ have it.
  - `requestId` = our own UUID generated per `/intercept` (one per tool-call decision). ✓ add it.
  - `traceId` ❌ — **VERIFIED: Claude Code provides NO shared id across PreToolUse and PostToolUse**
    ("correlation is by sequence/tool_name/timestamps"). So we CANNOT reliably stitch a specific
    decision to its result by id. Correlation is **best-effort** (sessionId + tool_name + temporal
    order). The timeline is honest about this: `/inspect` events attach to the session timeline by
    time+tool, not to a specific `requestId`. Don't fake precision.
  - `userId` — deferred to the paid multi-seat tier (local = single user).
  - Hierarchy: **Session → tool-call (requestId) decisions + adjacent inspect events, ordered by ts.**

- **D25 — Hybrid timeline: history via API, live via WS — through ONE shared projector.**
  - History: `GET /sessions` (list) + `GET /sessions/:id/timeline` — the engine reads/queries the
    audit JSONL (engine gains a READ path; today AuditLog is write-only).
  - Live: the existing WS `audit`/`violation`/`resolved` stream (extended with the new event types).
  - **CRITICAL:** both paths run the SAME projection function (file-replay and live), or they drift —
    which would violate D22's whole point.

## Robustness flags surfaced (verify live — part of the Risk #1 / real-Claude-Code loose end)
- ⚠️ **Hook result field name:** our hook reads `event.tool_response`; the docs also reference
  `tool_output` (and `error` on failure). UNVERIFIED against real Claude Code (our e2e POSTs to
  /inspect directly, bypassing the hook). If the real field differs, M3a/M3b silently see no result.
  **Fix:** make the hook tolerant — `tool_response ?? tool_output ?? error` — and validate live.
- SessionEnd hook → wire `behavioral.reset` + `contamination.reset` (also fixes monitor eviction).

## Step 4 — React investigation view (design)
- **D26 — IA = two tabs (Live / Sessions), no router lib.** `App` holds a `view` state. **Live** = the
  current screen verbatim (Action Center + Live Stream), so the real-time approval UX is untouched.
  **Sessions** = a session list (newest first, with rollup chips) → click → full timeline detail.
- **D27 — A timeline decision row expands to the risk-factor breakdown + the tool-call diff.** Surfaces
  the `risk.factors[]` (source/label/points/group) that already stream but were never shown, plus the
  `describe()` tool-call diff (command/path/url + content). Factor breakdown collapsed by default.
  Non-verdict events (session-*, taint-loaded, injection-detected, hitl-opened, tool-failed) render as
  compact marker rows.
- **D28 — Filtering = chips (event kind / signal / band) + free-text search (tool/reason/command).**
  Applied within the timeline; the session list gets a text search by sessionId.
- **Live merge through the shared projector (D25):** the Sessions list hydrates from `GET /sessions`;
  opening a session fetches `GET /sessions/:id/timeline`. Incoming WS `audit` events for the open session
  are appended and re-projected with the SAME `projectTimeline` (copied to `dashboard/src/projector.ts`),
  so live and history never diverge. The list re-fetches (throttled) as new events arrive.

## Build order (foundation before React)
1. Audit record `event` discriminator + `requestId` (contract + engine).
2. Emit hitl-opened/resolved(+latency); SessionStart/SessionEnd hook handling + monitor.reset;
   tool-failed via /inspect.
3. Shared projector + `GET /sessions` / `GET /sessions/:id/timeline` (audit-log read path).
4. THEN the React investigation view.

## Build progress
- ✅ **Step 1 — contract event model.** `AuditEntry` reshaped (D23): required `event` (`decision |
  hitl-opened | hitl-resolved | session-started | session-ended | taint-loaded | injection-detected |
  tool-failed`) + `reason` + `ts`; everything else optional per event kind. Added `sessionId`,
  `requestId` (D24), `resolution`/`latencyMs` (hitl-resolved), `secretTypes`/`injectionScore`.
  `InspectRequest.error?` + new `SessionEvent` type. Mirrored verbatim into `dashboard/src/contract.ts`.
- ✅ **Step 2 — emit observed events.** Engine: `writeAudit` refactored to an object form; `requestId`
  per `/intercept` (also the violation id); `hitl-opened` at register + `hitl-resolved`
  {approved|rejected|expired}+`latencyMs` at resolve (replaces the old viaHitl decision write); the
  two `/inspect` writes became first-class `taint-loaded`/`injection-detected`; `tool-failed` when
  `/inspect` carries `error`. New `POST /session` → session-started/ended **and resets the
  behavioral + contamination monitors on end** (closes the M2/M3 idle-eviction loose end). Hook: tolerant
  result field (`tool_response ?? tool_output ?? error`), failure→`error`, SessionStart/SessionEnd
  dispatch → `/session`. `agentguard init` now wires all four hooks (Session* carry no matcher).
- ✅ **Step 3 — read path + shared projector.** `AuditLog.read()` (tolerant JSONL replay). Pure
  `src/audit/projector.ts` (`summarizeSessions` / `projectTimeline`) — **the ONE projection**, copied
  verbatim to `dashboard/src/projector.ts` (D25, like the contract). `GET /sessions` + `GET
  /sessions/:id/timeline`, matched before the static catch-all.
- **Tests:** init 13→16 (session hooks), behavioral-e2e provenance scoped to verdict-bearing events,
  content/injection e2e assert the new `taint-loaded`/`injection-detected` events. **Full regression
  green:** unit 55 (9+8+9+13+16), e2e 36 (8+10+12+6), ws-verify path, smoke 11 (default TTL), and the
  new `/sessions` + timeline verified live (session-started→decision→tool-failed→session-ended rollup).
- ✅ **Step 4 — React investigation view (D26–D29).** Live/Sessions **tabs** in `App` (no router);
  Live = the original screen verbatim. New `SessionsView.tsx`: session list (rollup chips + id search)
  → per-session **timeline** (vertical rail, per-event marker rows). Decision/hitl-resolved rows
  **expand** to the `risk.factors[]` breakdown + the tool-call diff (`describe`). **Filter bar** = event /
  signal / band chips (only those present) + free-text search. **Live-merge:** the open timeline fetches
  history then dedups+re-projects incoming WS events via the shared `projector` (D25). Shared helpers in
  `format.ts`, REST in `api.ts`. `AuditRow` (Live stream) made event-aware.
  - **D29 — log the tool `input` on intercept events.** Discovered while wiring D27: `AuditEntry` had
    `tool` but not the args, so the timeline couldn't render the diff. Added `input?` to the contract and
    populate it on decision/hitl events (local-only log; commands/paths/urls are exactly what an
    investigation needs; size bounded by the 1 MB request cap).
  - **Tests:** new `scripts/projector.test.ts` (15/15) + `test:projector`. Dashboard `npm run build`
    clean (34 modules). Live e2e on the **compiled** engine: dashboard served at `/`, a real HITL
    approve flow, and a 6-event timeline with correct rollup + latency. **Full regression green:** unit
    70 (9+8+9+13+16+15), e2e 36, build + typecheck clean.
- **M4-B COMPLETE.** All four build-order steps done and verified.

## Post-M4-B hardening + forward roadmap (owner re-plan, 2026-06-11)
Owner laid out a 7-step plan; mapped against what this session already shipped:
- **Step 1 — Event-system hardening: ✅ DONE (D30).** `src/audit/validate.ts` — closed runtime event
  enum (`AUDIT_EVENTS`) + `validateAuditEntry`: every record must have `event` (in enum) / `ts` /
  `sessionId` / `reason`; decision & hitl-* require `requestId`; decision & hitl-resolved require an
  `action`; hitl-resolved requires `resolution`+`latencyMs`. `AuditLog.record()` is now the gate —
  **rejects malformed entries** (stderr + drop, returns false; never throws, never breaks enforcement).
  Engine `writeAudit` coerces `sessionId→'default'` so every record is attributable and only broadcasts
  what was persisted. Tests: `scripts/audit.test.ts` (14/14) + `test:audit`. Full regression still
  green — no legitimate engine event is dropped.
- **Step 2 — Server read API: ✅ already done** (`GET /sessions`, `GET /sessions/:id/timeline`).
- **Step 3 — Smarter projector: ✅ DONE.** `correlateTimeline(events)` folds a `hitl-opened` and its
  `hitl-resolved` (same `requestId`) into one `TimelineItem` (`primary` + `resolvedBy`) → the UI shows
  one "held → BLOCK (rejected · 663ms)" row instead of two. `SessionSummary.drivers` aggregates the
  weighted risk-factor labels across verdicts into a friendly session "why" (`RISK_DRIVERS` map, hottest
  first, held call counted once) — rendered as "why this session is risky: secret exfiltration + prompt
  injection". `projectTimeline` now ships `items` alongside `events`; UI filters operate on items (match
  if open OR resolution matches). Projector synced to dashboard. Tests: projector 15→21. Verified live on
  `dist`: drivers `['outbound egress','prompt injection']`, 4 raw events → 3 correlated items.
- **Step 4 — Investigation UI: ✅ mostly done.** Sessions list, timeline, expandable rows, risk
  breakdown, tool-call diff. **TODO (Event Inspector):** show the tool **output**/result diff —
  blocked on a decision: results are NOT logged today (only `input`), and logging results means writing
  tool output (incl. potential secrets) to disk. Needs an explicit opt-in/redaction decision.
- **Step 5 — Filtering + search: ✅ already done** (event/signal/band chips + free-text over
  tool/reason/payload). Optional: a dedicated tool-name chip.
- **Step 6 — Replay mode: 🔨 in progress** ("YouTube of agent decisions" — replay a session like a movie).
  - **D31 — Pure client-side, a toggle inside the Session timeline.** Reuses the already-fetched
    correlated `items`; no backend, no new endpoint. A "▶ Replay" button flips the timeline into player mode.
  - **D32 — Event-paced playback + scrubber.** Play/pause auto-advances one item at a fixed cadence
    (~900ms at 1×) with a speed control (0.5×/1×/2×/4×), step back/forward, and a scrubber (cursor/total).
    Ignores real-world time gaps so it's watchable. Replay traverses ALL items (filters hidden in replay).
  - **D33 — Cumulative state panel + risk sparkline at the cursor.** The panel reconstructs session
    state up to the cursor by re-running the shared `summarizeSession` over the event prefix (running
    risk peak/score, secrets loaded, injection posture, currently-held count, verdict counts, drivers) —
    so you literally watch the risk build. A small SVG sparkline plots per-item risk score across the
    session with the cursor marked. Timeline dims future events, highlights the current one.
- **Step 7 — M5 multi-agent adapters: ⬜ future** (Cursor / Codex / Roo / Cline over the same engine).

## Open flags
- Policy Editor UI + `approval_surface` (C) deferred to a later round.
- Actual `npm publish` deferred (needs THIRD_PARTY_NOTICES + license sign-off).
- Live validation against real Claude Code still pending (Risk #1): SessionStart/SessionEnd payload
  shape, the tolerant result-field assumption, and the hook-timeout ceiling. (All AgentGuard-internal
  paths verified via curl against the compiled engine; only the Claude-Code→hook edge is unverified.)
- `GET /sessions` re-reads the whole JSONL per request — fine for the local tier; the paid/multi-instance
  tier would index or stream. Logged here so the O(log size) cost isn't a silent surprise at scale.

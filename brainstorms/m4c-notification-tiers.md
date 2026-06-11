# M4-C — Tiered notification / approval-surface architecture (terminal-first)

**Topic:** AgentGuard is a security layer *inside* the agent execution loop, so the realtime decision
point should be the **terminal**, with the web dashboard as post-hoc forensics. Owner's tiering:
Layer 1 terminal alerts (+HITL), Layer 2 auto-open the UI on HIGH/BLOCK/EXFIL, Layer 3 manual dashboard
(replay/timeline). This is the deferred `approval_surface: dashboard | terminal | both` from M4-C.

## Established facts / constraints (verified in code)
- **The Claude Code PreToolUse hook is NON-INTERACTIVE.** `src/hook/index.ts`: stdout = the JSON
  `permissionDecision` (the protocol channel to Claude Code), stdin = the hook event. There is no TTY
  read. ⇒ **an interactive terminal y/n prompt from the hook is impossible** on the Claude Code path.
  HITL approval today = the engine's **synchronous hold** released from the dashboard.
- Feasible terminal output: (a) write to **`/dev/tty`** (reaches the controlling terminal even though
  stdout is captured — UNVERIFIED against real Claude Code), (b) **stderr** (Claude Code may surface it),
  (c) the **`permissionDecisionReason`** string (already surfaced).
- The **engine** knows `action` + `risk.band` at decision time (`handleIntercept`) — the natural place to
  trigger severity-based behavior (auto-open, notifications).
- **No dashboard routing exists** — the UI is tab/React state, no URL router. A deep-link like
  `/session/:id/replay` (Layer 2) does not work yet; it needs routing added.
- Existing surfaces: synchronous hold + WS feed + REST (`/pending`, `/decision`); CLI `engine`/`hook`/`init`.

## Key decisions
- **D34 — HITL stays dashboard/hold-based; add a separate terminal approval CLI.** The hook only
  NOTIFIES in the terminal (the hold is unchanged). Real terminal approval comes from a separate process:
  `agentguard approve <id>` / `deny <id>` (one-shot, talks to the engine REST), with a richer
  `agentguard watch` TUI as a later thin layer on top. The notification must therefore carry the
  violation id so the user can act on it.

## Q&A log
- **Q1 — What is Layer-1 HITL given a non-interactive hook?** → **D34** (notify + separate `approve/deny`
  CLI; hold unchanged; `watch` TUI later).
- **Q2 — How does the hook surface the terminal notification?** → **D35** (write to `/dev/tty`, fall back
  to stderr if unwritable; keeps stdout clean, reaches the terminal for all severities incl. non-blocking
  notices). `/dev/tty` availability in real Claude Code = open flag to live-verify.
- **Q3 — Severity → behavior matrix?** → **D36 (owner's matrix):**
  | band/event | terminal | web UI |
  |---|---|---|
  | **HITL** (held) | ✅ notify (mandatory) + **UI deep link** | reachable via the link |
  | **BLOCK** | ✅ alert + **optional auto-open** (config) | replay via link / auto-open |
  | **AUDIT** | ✗ (quiet) | ✅ UI only |
  | **ALLOW** | ✗ silent | — |
  | **Replay / forensics** | — | ✅ UI only |
  - "terminal HITL (mandatory)" = the hold ALWAYS produces a terminal notification; approval itself
    remains the `approve` CLI / dashboard (D34 — the hook can't prompt). Auto-open on BLOCK is a
    config toggle ("optional"); HITL does NOT auto-open (link only).
- **Q4 — Deep-link routing?** → **D37 — terminal-first; the UI link is optional and minimal. NO routing
  design now.** Use a simple session URL `http://127.0.0.1:9000/?session=<id>`: on load the dashboard
  reads `?session=` and preselects that session in the Sessions tab (no path routing, no pushState, no
  replay deep-link). Replay stays manual (UI only, click ▶ Replay) per D36. ~5 lines in App, no router.
- **Q5 — Where does the config live?** → **D38 — `AG_*` env vars** (consistent with all current engine
  config; zero new mechanism). `AG_APPROVAL_SURFACE=terminal|dashboard|both` (default `both`),
  `AG_AUTO_OPEN=block|off` (default `off`), `AG_NOTIFY=1` (default on). The **hook** reads notify/surface
  for terminal output; the **engine** reads auto-open. (Interpreted from a garbled RTL paste of the
  question — confirm if B/C was intended.)

- **Q6 — Who performs auto-open + how?** → **D39 — engine-side** (knows action+band+sessionId, single
  long-lived process ⇒ central dedup + rate-limit). Cross-platform open (`open`/`xdg-open`/`start`) to
  `/?session=<id>` when `AG_AUTO_OPEN=block` and band ∈ {BLOCK, EXFIL}; dedup per session + a ~30s
  window so a burst doesn't spawn tabs. Add `band` to `PipelineResult` so the hook can format alerts.
  _(Recommendation taken — input channel was garbled; confirm if hook-side B was intended.)_
- **Q7 — Terminal notification format?** → **D40 — concise, ≤2 lines, carries id + link.** Examples:
  - HELD: `⏸ AgentGuard HELD Bash · risk=80 · injection detected` / `   approve: agentguard approve <id> · http://127.0.0.1:9000/?session=<sid>`
  - BLOCK: `⛔ AgentGuard BLOCKED WebFetch · risk=150 · secret exfiltration` / `   investigate: http://127.0.0.1:9000/?session=<sid>`
  - notice (PostToolUse): `⚠ AgentGuard: secret loaded into context via Read` / `⚠ AgentGuard: prompt-injection detected in WebFetch result`

- **D41 — HELD-notification timing (found during build).** The hook BLOCKS on `/intercept` during a
  hold, so it only learns "this was held" when the (delayed) response arrives — it can't pre-announce.
  Resolution: a **slow-response heuristic** — if `/intercept` hasn't answered within ~400ms, the hook
  prints "⏸ HELD <tool> — review in dashboard / `agentguard pending`" to `/dev/tty`, then keeps waiting;
  on resolution it prints the outcome (✓ approved / ⛔ denied). The specific violation id isn't known
  during the hold, so the alert points to **`agentguard pending`** (new subcommand: lists held calls +
  ids) and the dashboard. AUTO BLOCK alerts are immediate (response is instant). Adds `pending` to D34's
  CLI set.

## Design COMPLETE (D34–D41). Build plan
1. **Contract:** add `band: RiskBand` to `PipelineResult` (so the hook can format by severity).
2. **Engine:** return `band` from `/intercept`; engine-side auto-open (D39) — config `AG_AUTO_OPEN`,
   cross-platform open, per-session dedup + rate-limit window, only BLOCK/EXFIL.
3. **Hook:** terminal notifier — write to `/dev/tty` (fallback stderr) per D35/D36/D40, gated by
   `AG_NOTIFY`/`AG_APPROVAL_SURFACE`; on PreToolUse HELD/BLOCK and PostToolUse taint/injection notices.
4. **CLI:** `agentguard approve <id>` / `deny <id>` → POST `/decision` (D34). `watch` TUI deferred.
5. **Dashboard:** read `?session=<id>` on load → select that session in the Sessions tab (D37). ~5 lines.
6. **init:** optionally inject `AG_*` notify env into the hook command (or document them).
7. **Tests:** notifier format unit; auto-open dedup unit (inject an opener fn); `approve/deny` CLI unit
   against a temp engine; `?session=` selection. Full regression stays green.

## Build progress — M4-C core COMPLETE (D34–D41)
- ✅ **Contract:** `PipelineResult` gains `band` + `sessionId` (so the hook can format by severity and
  build the `?session=` link).
- ✅ **Engine:** `/intercept` returns band+sessionId; engine-side **auto-open** (`maybeAutoOpen`) on
  BLOCK with per-session dedup + 30s window, cross-platform opener, injectable for tests; gated by
  `AG_AUTO_OPEN=block` (default off), wired through the CLI + startup banner.
- ✅ **Hook notifier:** `/dev/tty` write with stderr fallback (D35), gated by `AG_NOTIFY`/
  `AG_APPROVAL_SURFACE`. PreToolUse: auto-BLOCK alert (immediate) + slow-response HELD notice (D41) +
  held-outcome line; auto-ALLOW/AUDIT silent (D36). PostToolUse: secret-loaded / injection notices.
  Alerts embed the `?session=` link.
- ✅ **CLI:** `agentguard pending` (lists held calls + ids), `approve <id>` / `deny <id>` → POST
  `/decision` (D34). Shares the hook's host/port env.
- ✅ **Dashboard:** reads `?session=<id>` on load → Sessions tab with that session preselected (D37).
- **Tests:** `scripts/notify.test.ts` (5/5 — band/sessionId in response, auto-open dedup, distinct per
  session, off=never) + `test:notify`. Full regression green (unit 95, e2e 36, build clean). Live-verified:
  hook BLOCK alert (stdout protocol stays clean, alert on the terminal channel) + `pending`/`approve`
  released a real hold.
- **Deferred:** `agentguard watch` TUI; `init` env injection (documented instead); README update for the
  new commands + env vars.

## Open flags
- `/dev/tty` writability + stderr surfacing inside real Claude Code — live-verify (ties to Risk #1).
  (Verified the fallback path works; the `/dev/tty` primary path needs a real Claude Code terminal.)
- `watch` TUI (live terminal approval) deferred to a later layer on top of `approve/deny`.
- Auto-open assumes engine + browser on the same host (local tier) — revisit for the cloud/paid tier.

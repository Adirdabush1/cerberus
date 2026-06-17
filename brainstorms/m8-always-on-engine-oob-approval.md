# M8 — Always-on engine + out-of-band approval

**One-liner:** Make the Cerberus engine run permanently in the background (survive reboot + closed sessions, macOS/launchd), and add an out-of-band escalation path so high-risk held calls can reach the user via email/push instead of silently dying on the hook's ~310s TTL.

## Key decisions so far
- **Q1 — scope = (א)+(ב), not (ג).** Escalate when Cerberus holds a high-risk call and no human is approving via the normal surfaces. Covers: agent running while user is away (א), and non-interactive/background agent runs — cron/CI/deploy (ב). Pure monitoring with no agent (ג) is out of scope (different product).
- **Q1b (proposed, to confirm) — escalation is driven by the existing risk band/HITL decision, NOT a hand-maintained list.** The user's ~100-item "extreme" catalog (secrets/creds, DB destruction, dependency attacks, cloud/infra, fs destruction, network exfil, git history, process, blind arch changes, identity) maps almost entirely onto the four existing signals. The catalog becomes a **coverage/test corpus** ("does each of these score HITL/BLOCK?"), not runtime rules.
- **Q2 — flow = Option C (hybrid).** Default is block-now + notify (safe, fail-closed, works for non-interactive (ב)). PLUS a persisted "approved-fingerprint" decision: when the user approves out-of-band (even late), Cerberus remembers the fingerprint and the call passes on the agent's **next retry** — no socket held open, no stuck agent. Gives real remote approval value without breaking the per-call hook model.
- **Q3 — escalation trigger = Option B (local grace period first).** A held call surfaces locally (dashboard/terminal) as usual; only if no human responds within a grace window does it escalate out-of-band. Zero noise when the user is present; auto-escalates in (א) away-from-desk and (ב) no-terminal cases.
- **Q4 — grace period = 60s. The HITL hold itself is the escalation threshold (no extra risk-band filter).** Only HITL calls hold the socket (ALLOW/AUDIT return immediately, BLOCK denies immediately), so a held call already means "risk engine decided a human is needed." Any held call unanswered for 60s escalates. (Possible later optimization: detect non-interactive/no-TTY runs and skip the 60s wait — defer.)
- **Q5 — approval grant = medium-scope normalized fingerprint, one-shot, 10-min expiry.** Remote approval grants exactly "this specific call, once, if the agent retries within 10 minutes." Fingerprint = hash of (tool kind + normalized command + primary path/target). NOT a broad "approve this category" grant. Deny (or ignored/expired email) → stays **blocked** (fail-closed default preserved).
- **Q6 — channel + return path (locked to recommendation; user said "finish & build").**
  - 6a: **Email via the user's own SMTP** is the default channel; push (ntfy/Pushover) is opt-in later. Notification carries only the fingerprint + human description — **never the payload/secret value** (preserves "secret values never touch disk or logs").
  - 6b: Decision returns via **(i) same-network / Tailscale** — the email link hits `http://<host>:<port>/approve?token=…` on the local engine. **No cloud relay** in v1 (preserves local-first). Cloud relay is a future explicit opt-in only.
  - Token is **signed (HMAC), single-use, bound to the fingerprint + expiry** from Q5. A leaked link cannot approve anything else and cannot be replayed.
- **Q7 — always-on (Part 1), locked.** New `cerberus service` subcommand installs a **macOS launchd LaunchAgent** (`~/Library/LaunchAgents/…plist`) with `RunAtLoad` + `KeepAlive` so the engine survives reboot and closed sessions. `install` / `uninstall` / `status`. Linux (systemd --user) deferred. Bonus: with the engine always up, the hook's fail-closed-on-unreachable path stops firing spuriously.

## Build scope (v1)
1. `cerberus service {install|uninstall|status}` → launchd LaunchAgent.
2. Engine HITL hold path: on hold, arm a **60s grace timer**; if unresolved locally → escalate.
3. Notifier abstraction (email/SMTP default) — sends fingerprint + description + signed one-shot approval link. Never the payload.
4. `GET /approve?token=…` (and `/deny`) endpoint: verify HMAC + expiry + single-use, then register an **approved-fingerprint** (one-shot, 10-min) in the store.
5. `/intercept`: before holding, consult the approved-fingerprint cache → ALLOW once if matched, then burn it.
6. Fingerprint helper: hash(tool kind + normalized command + primary target).
7. Config: SMTP/channel + escalation settings (grace period, expiry) in engine config/rules.

## Build status — DONE (v1)
Implemented on branch `feat/m7-security-coverage`:
- `src/engine/escalation.ts` — `fingerprint()`, HMAC `signToken`/`verifyToken`, `loadSigningKey` (0600 under `.cerberus/`), `ApprovalGrants` (one-shot+expiry), `Notifier` (`CommandNotifier` default-channel, `NoopNotifier`).
- `src/engine/server.ts` — grace-timer escalation in the HITL hold path; one-shot grant consumed on retry (never overrides a hard-floor BLOCK); `GET /approve` + `GET /deny` (token-auth, single-use); HTML response page.
- `src/contract/types.ts` + `src/audit/validate.ts` — new `escalated` audit event.
- `src/cli/index.ts` — `AG_ESCALATE=1` wiring (grace/grant/key/public-url/notify-cmd envs) + banner line.
- `src/cli/service.ts` + `cerberus service install|uninstall|status` — macOS launchd LaunchAgent (RunAtLoad+KeepAlive), bakes in `AG_ESCALATE=1` + `AG_APPROVAL_SURFACE=dashboard`.
- `scripts/escalation.test.ts` (`npm run test:escalation`) — 21 tests, all green (fingerprint, token, grants, notifier, + 4 integration flows: live-approve, late-approve-grants-retry, deny, disabled).

### Deviation from Q6a (recorded honestly)
Grilled decision said "email via own SMTP as default channel." Shipped a **`CommandNotifier`** (user-configured `AG_NOTIFY_CMD`) as the default instead of bundling an SMTP client. Rationale: the codebase is deliberately near-zero-dependency (js-yaml, json-logic, ws only) and local-first; bolting on nodemailer contradicts that. The command notifier delivers BOTH email (pipe to `sendmail`/`mail`) and push (ntfy/Pushover/Slack) with zero deps and nothing leaving the box we don't control. SMTP/push become documented recipes, not a dependency.

### Known out-of-scope issue (pre-existing, not introduced)
`scripts/notify.test.ts` fails 2/4 at clean HEAD — the policy recalibration commits made `rm -rf /tmp/x` resolve to HITL (not BLOCK), and that test still asserts BLOCK+auto-open. Independent of M8.

## Architecture facts (verified from code)
- `cerberus hook` is spawned **per tool call** by the agent (PreToolUse/PostToolUse). Ephemeral.
- `cerberus engine` is the long-running daemon. The hook POSTs to `/intercept` and **holds the HTTP socket open** — that open socket *is* the synchronous hold (`src/engine/server.ts:13`).
- HITL has two surfaces: `terminal` (returns ASK → agent's native prompt, **no hold**) and `dashboard` (holds the socket until a human decides, TTL fires, or socket closes).
- TTL default ~310s (`PRE_TIMEOUT = 310` in `src/cli/init.ts`). Hook fails **closed** if the engine is unreachable (`src/hook/index.ts:130`), unless `AG_FAIL_OPEN=1`.
- **Critical tension:** the engine only ever sees a call while an agent session is actively issuing tool calls. If "no session is open," there is no held socket and nothing to approve.

## Q&A log
_(appended after each answer)_

## Open flags
- ~~Define what "extreme case when no session is open" concretely means~~ → resolved Q1.
- Confirm SMTP config shape + where it lives (engine config vs rules YAML) — decide during build.
- Decide signing-key storage (generate on first `service install`, store under AG_HOME, never in repo).
- Coverage corpus: turn the user's ~100-item catalog into a test that asserts each scores HITL/BLOCK (follow-up milestone, not v1 blocker).

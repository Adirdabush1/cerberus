# M4 — Polish + Package / Dashboard + Investigation UI

**Topic (PLAN):** `npx agentguard` CLI, config (`approval_surface`), Policy Editor UI, docs, example
Claude Code config, Dashboard/Investigation UI. *Goal: install in a minute.* This is a grab-bag of
~5 distinct things — first job is to SCOPE it.

## Established facts (current state)
- `bin/agentguard.mjs` runs the TS CLI via **tsx** (dev launcher); `dist/` is gitignored; `npm run
  build` = `tsc` exists but `bin` does NOT point at compiled output. → not npm-publishable yet.
- No `docs/`; `README.md` is 27 lines (planning notes).
- Dashboard: `App.tsx` (191 lines) = Live Stream + Action Center (Approve/Deny) + ANOMALY/EXFIL/AUDIT
  badges + risk score; `useEngine.ts` WS hook; talks WS only.
- Engine surface: `/health /pending /decision /intercept /inspect`, WS `/ws`. Hooks: Pre + Post.
- `examples/claude-settings.json` already exists (both hooks). Rules + risk weights are YAML data.
- No `agentguard init` / install helper; user wires `.claude/settings.json` by hand.

## Candidate M4 sub-parts
1. **Shippable package** — build→dist, `bin`→compiled, `agentguard init` (auto-wire hooks), README/docs,
   verify `npx agentguard`. "Install in a minute."
2. **Investigation/Dashboard UX** — session timeline, risk-factor breakdown, audit history, filtering.
3. **Config/authoring** — `approval_surface` (terminal vs dashboard vs Slack), Policy Editor UI.

## Key decisions
- **D19 — M4 scope = A (Shippable package).** Make AgentGuard install-and-run in a minute: build→dist,
  `bin`→compiled, `agentguard init` to wire hooks, README/docs, verified `npx agentguard`. B
  (Investigation UI) is the next round if there's room; C (Policy Editor / approval_surface) deferred.

## Q&A log

**Q1 — M4 scope?** → **D19** (A: shippable package).

**Q2 — Does the engine serve the dashboard?**
A: **D20 — Yes, the engine serves the built dashboard (static).** `npm run build` builds the Vite app
to `dashboard/dist`; the engine serves it at `/` (WS stays `/ws`; `/health /pending /decision
/intercept /inspect` unchanged), with SPA `index.html` fallback and careful path precedence so it
never shadows the API routes. One process, zero frontend toolchain for the user. Bundle ships in the
npm package.

**Q3 — `agentguard init` behavior + scope?**
A: **D21 — Auto-merge, safe, with `--print` fallback.** Default writes project-level
`./.claude/settings.json` (`--global` for `~/.claude/settings.json`); MERGES (never overwrites) the
Pre+Post hooks pointing at the resolved absolute bin path, correct timeouts (Pre ≥ TTL, Post short);
**idempotent** (no double-add) + **backs up** the existing file + prints the change; ends with next
steps. `--print` emits the JSON snippet only (no mutation).

## M4-A design — COMPLETE (D19–D21). Build plan:
- **Build:** `npm run build` compiles the engine (`tsc` → `dist/`) AND the dashboard (`vite build` →
  `dashboard/dist`). `bin/agentguard.mjs` prefers compiled `dist/cli/index.js` when present, falls
  back to tsx for dev. (No bundler — PLAN rejected tsup friction.)
- **Engine serves dashboard:** static-serve `dashboard/dist` at `/` with SPA fallback; API/WS routes
  take precedence (D20).
- **`agentguard init`:** new CLI subcommand per D21.
- **Packaging:** package.json `files` = [dist, dashboard/dist, rules, examples, bin]; `prepublishOnly:
  npm run build`. Scope = **publishable + locally installable/runnable**, NOT an actual `npm publish`
  (publish is gated on the THIRD_PARTY_NOTICES / OSS-license loose end + a deliberate decision).
- **Docs:** rewrite README (install → init → run → open dashboard → demo); short docs/.
- **Verify:** build clean; run COMPILED `dist/cli/index.js engine` → `/health` + dashboard served at
  `/`; `agentguard init` merge/idempotent/backup unit test against a temp settings.json; full
  regression still green.

## Build progress
- ✅ **Foundation (dist build + CLI + engine-serves-dashboard, single process):** `tsconfig` rootDir
  `src`→`dist/cli/index.js`; `bin` prefers `dist`, falls back to tsx, exports `AG_HOME`; engine
  static-serves `dashboard/dist` at `/` with SPA fallback + path-traversal guard (encoded `../`→403);
  dashboard WS derives from page origin; `npm run build` builds both; package.json `files` +
  `prepublishOnly`. Verified: compiled engine serves `/health`+`/`+assets; 86 tests still green.
- ✅ **`agentguard init` (D21):** `src/cli/init.ts` — merge/idempotent/backup, `--global`/`--print`,
  resolved absolute bin path + correct timeouts. 13/13 unit (`scripts/init.test.ts`); verified via the
  compiled bin (print + real temp-dir merge).
- ✅ **README** rewritten (install → init → run → dashboard → demo, architecture, licensing).
- **M4 core (A) COMPLETE.** Full regression 99/99 green incl. compiled-engine smoke. B (Investigation
  UI) and C (Policy Editor / approval_surface) deferred; actual `npm publish` gated on THIRD_PARTY_NOTICES.

## Open flags
- Policy Editor UI + `approval_surface` (C) deferred to a later round.
- Actual `npm publish` deferred (needs THIRD_PARTY_NOTICES + license sign-off).

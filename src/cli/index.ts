/**
 * Cerberus CLI — two subcommands:
 *   cerberus engine   start the long-running Engine (HTTP hold + WS dashboard feed)
 *   cerberus hook      run the PreToolUse hook (Claude Code spawns this per tool call)
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { Engine } from '../engine/server.js';
import { DEFAULT_ANOMALY_CONFIG } from '../signals/behavioral.js';
import { DEFAULT_CONTENT_CONFIG } from '../signals/content.js';
import { DEFAULT_INJECTION_CONFIG } from '../signals/injection.js';

const HERE = dirname(fileURLToPath(import.meta.url));
// AG_HOME (set by bin/cerberus.mjs) is the package root, so bundled resources resolve whether the
// CLI runs from src/ (tsx dev) or dist/ (published). Fall back to two-up from this file for direct runs.
const PROJECT_ROOT = process.env.AG_HOME ?? resolve(HERE, '..', '..');

async function runEngine(): Promise<void> {
  const port = Number(process.env.AG_ENGINE_PORT ?? 9000);
  const rulesPath = process.env.AG_RULES ?? join(PROJECT_ROOT, 'rules', 'default_policy.yaml');
  const weightsPath = process.env.AG_RISK_WEIGHTS ?? join(PROJECT_ROOT, 'rules', 'risk_weights.yaml');
  const auditFile = process.env.AG_AUDIT ?? join(PROJECT_ROOT, '.cerberus', 'audit.jsonl');
  const ttlMs = Number(process.env.AG_TTL_MS ?? 300_000); // 5 min default — NOT 60s
  const behavioral = {
    windowMs: Number(process.env.AG_WINDOW_MS ?? DEFAULT_ANOMALY_CONFIG.windowMs),
    maxRate: Number(process.env.AG_MAX_RATE ?? DEFAULT_ANOMALY_CONFIG.maxRate),
    maxRepeat: Number(process.env.AG_MAX_REPEAT ?? DEFAULT_ANOMALY_CONFIG.maxRepeat),
    hardMultiplier: Number(process.env.AG_HARD_MULT ?? DEFAULT_ANOMALY_CONFIG.hardMultiplier),
  };

  const content = {
    pathRiskTtlMs: Number(process.env.AG_PATH_TTL_MS ?? DEFAULT_CONTENT_CONFIG.pathRiskTtlMs),
    scanLimitBytes: Number(process.env.AG_SCAN_BYTES ?? DEFAULT_CONTENT_CONFIG.scanLimitBytes),
    entropyThreshold: Number(process.env.AG_ENTROPY ?? DEFAULT_CONTENT_CONFIG.entropyThreshold),
    entropyMinLen: Number(process.env.AG_ENTROPY_MINLEN ?? DEFAULT_CONTENT_CONFIG.entropyMinLen),
  };

  const injection = {
    enabled: (process.env.AG_INJECTION ?? '1') !== '0',
    threshold: Number(process.env.AG_INJECTION_THRESHOLD ?? DEFAULT_INJECTION_CONFIG.threshold),
  };

  // Serve the built dashboard if it's present (run `npm run build` to produce it).
  const dashboardDist = join(PROJECT_ROOT, 'dashboard', 'dist');
  const staticDir = existsSync(join(dashboardDist, 'index.html')) ? dashboardDist : undefined;

  const autoOpen = process.env.AG_AUTO_OPEN === 'block' ? 'block' : 'off'; // M4-C D39 — default off
  // M4-C: terminal approval (HITL → Claude's native in-terminal prompt) by default; dashboard-hold opt-in.
  const approvalSurface = process.env.AG_APPROVAL_SURFACE === 'dashboard' ? 'dashboard' : 'terminal';

  const engine = new Engine({ port, rulesPath, auditFile, ttlMs, behavioral, content, injection, weightsPath, staticDir, autoOpen, approvalSurface });
  await engine.listen();
  process.stderr.write(
    `Cerberus engine listening on :${port}\n` +
      `  rules: ${rulesPath}\n  audit: ${auditFile}\n  HITL TTL: ${ttlMs}ms\n` +
      `  anomaly: ${behavioral.maxRate} calls / ${behavioral.maxRepeat} repeats per ${behavioral.windowMs}ms (×${behavioral.hardMultiplier} = block)\n` +
      `  content: secret-scan ${content.scanLimitBytes}B/result, path-risk TTL ${content.pathRiskTtlMs}ms → exfil HITL\n` +
      `  injection: classifier=${engine.injectionClassifier} (threshold ${injection.threshold}) → posture HITL on egress\n` +
      `  risk: ${weightsPath} (${engine.riskVersion}) → ALLOW/AUDIT/HITL/BLOCK bands\n` +
      `  approval: ${approvalSurface === 'terminal' ? "terminal — HITL → Claude's native prompt (ASK)" : 'dashboard — socket hold + Approve/Deny'}\n` +
      `  auto-open: ${autoOpen === 'block' ? 'on BLOCK/EXFIL' : 'off (set AG_AUTO_OPEN=block)'}\n` +
      `  dashboard: ${staticDir ? `http://127.0.0.1:${port}/` : '(not built — run `npm run build`)'}  ·  WS ws://127.0.0.1:${port}/ws\n`,
  );
}

/** Fetch against the local engine using the same host/port env the hook uses. */
function engineFetch(path: string, init?: RequestInit): Promise<Response> {
  const host = process.env.AG_ENGINE_HOST ?? '127.0.0.1';
  const port = Number(process.env.AG_ENGINE_PORT ?? process.env.AG_PORT ?? 9000);
  return fetch(`http://${host}:${port}${path}`, { headers: { 'content-type': 'application/json' }, ...init });
}

/** `cerberus approve|deny <id>` — the terminal approval channel (M4-C, D34). */
async function runDecision(action: 'ALLOW' | 'BLOCK', id: string | undefined): Promise<void> {
  if (!id) {
    process.stderr.write(`usage: cerberus ${action === 'ALLOW' ? 'approve' : 'deny'} <violation-id>   (list ids with \`cerberus pending\`)\n`);
    process.exit(1);
  }
  const r = await engineFetch('/decision', { method: 'POST', body: JSON.stringify({ type: 'decision', violationId: id, action }) });
  if (r.ok) process.stdout.write(`${action === 'ALLOW' ? '✓ approved' : '⛔ denied'} ${id}\n`);
  else {
    process.stderr.write(`Cerberus: decision failed (${r.status}). Is the engine running, and is the id still pending?\n`);
    process.exit(1);
  }
}

/** `cerberus pending` — list calls currently held for review, with their ids (M4-C, D41). */
async function runPending(): Promise<void> {
  let r: Response;
  try {
    r = await engineFetch('/pending');
  } catch {
    process.stderr.write('Cerberus: cannot reach the engine. Start it with `cerberus engine`.\n');
    process.exit(1);
  }
  if (!r.ok) { process.stderr.write(`Cerberus: /pending returned ${r.status}.\n`); process.exit(1); }
  const { pending } = (await r.json()) as {
    pending: { id: string; toolCall: { tool: string }; reason: string; risk?: { score: number } }[];
  };
  if (pending.length === 0) { process.stdout.write('No calls awaiting approval.\n'); return; }
  process.stdout.write(`${pending.length} awaiting approval:\n`);
  for (const v of pending) {
    process.stdout.write(
      `  ${v.id}  ${v.toolCall.tool}${v.risk ? ` · risk=${v.risk.score}` : ''}\n    ${v.reason}\n` +
        `    → cerberus approve ${v.id}    ·    cerberus deny ${v.id}\n`,
    );
  }
}

async function main(): Promise<void> {
  const cmd = process.argv[2];
  if (cmd === 'engine') return runEngine();
  if (cmd === 'hook') {
    await import('../hook/index.js');
    return;
  }
  if (cmd === 'init') {
    const { runInit } = await import('./init.js');
    return runInit(process.argv.slice(3));
  }
  if (cmd === 'approve') return runDecision('ALLOW', process.argv[3]);
  if (cmd === 'deny') return runDecision('BLOCK', process.argv[3]);
  if (cmd === 'pending') return runPending();
  process.stderr.write(
    'usage: cerberus <command>\n\n' +
      '  init [--agent claude|codex|cursor|cline] [--global] [--print]   wire the hooks into the agent\n' +
      '  engine                      start the gateway (HTTP hold + WS) and serve the dashboard\n' +
      '  hook                        the Claude Code hook entry (spawned per tool call)\n' +
      '  pending                     list calls held for review (with their ids)\n' +
      '  approve <id> | deny <id>    resolve a held call from the terminal\n',
  );
  process.exit(1);
}

main().catch((err: unknown) => {
  process.stderr.write(`Cerberus: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});

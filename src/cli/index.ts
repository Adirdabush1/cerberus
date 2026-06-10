/**
 * AgentGuard CLI — two subcommands:
 *   agentguard engine   start the long-running Engine (HTTP hold + WS dashboard feed)
 *   agentguard hook      run the PreToolUse hook (Claude Code spawns this per tool call)
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { Engine } from '../engine/server.js';
import { DEFAULT_ANOMALY_CONFIG } from '../signals/behavioral.js';
import { DEFAULT_CONTENT_CONFIG } from '../signals/content.js';
import { DEFAULT_INJECTION_CONFIG } from '../signals/injection.js';

const HERE = dirname(fileURLToPath(import.meta.url));
// AG_HOME (set by bin/agentguard.mjs) is the package root, so bundled resources resolve whether the
// CLI runs from src/ (tsx dev) or dist/ (published). Fall back to two-up from this file for direct runs.
const PROJECT_ROOT = process.env.AG_HOME ?? resolve(HERE, '..', '..');

async function runEngine(): Promise<void> {
  const port = Number(process.env.AG_ENGINE_PORT ?? 9000);
  const rulesPath = process.env.AG_RULES ?? join(PROJECT_ROOT, 'rules', 'default_policy.yaml');
  const weightsPath = process.env.AG_RISK_WEIGHTS ?? join(PROJECT_ROOT, 'rules', 'risk_weights.yaml');
  const auditFile = process.env.AG_AUDIT ?? join(PROJECT_ROOT, '.agentguard', 'audit.jsonl');
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

  const engine = new Engine({ port, rulesPath, auditFile, ttlMs, behavioral, content, injection, weightsPath, staticDir });
  await engine.listen();
  process.stderr.write(
    `AgentGuard engine listening on :${port}\n` +
      `  rules: ${rulesPath}\n  audit: ${auditFile}\n  HITL TTL: ${ttlMs}ms\n` +
      `  anomaly: ${behavioral.maxRate} calls / ${behavioral.maxRepeat} repeats per ${behavioral.windowMs}ms (×${behavioral.hardMultiplier} = block)\n` +
      `  content: secret-scan ${content.scanLimitBytes}B/result, path-risk TTL ${content.pathRiskTtlMs}ms → exfil HITL\n` +
      `  injection: classifier=${engine.injectionClassifier} (threshold ${injection.threshold}) → posture HITL on egress\n` +
      `  risk: ${weightsPath} (${engine.riskVersion}) → ALLOW/AUDIT/HITL/BLOCK bands\n` +
      `  dashboard: ${staticDir ? `http://127.0.0.1:${port}/` : '(not built — run `npm run build`)'}  ·  WS ws://127.0.0.1:${port}/ws\n`,
  );
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
  process.stderr.write(
    'usage: agentguard <command>\n\n' +
      '  init [--global] [--print]   wire the Pre/PostToolUse hooks into .claude/settings.json\n' +
      '  engine                      start the gateway (HTTP hold + WS) and serve the dashboard\n' +
      '  hook                        the Claude Code hook entry (spawned per tool call)\n',
  );
  process.exit(1);
}

void main();

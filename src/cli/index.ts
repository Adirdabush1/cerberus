/**
 * AgentGuard CLI — two subcommands:
 *   agentguard engine   start the long-running Engine (HTTP hold + WS dashboard feed)
 *   agentguard hook      run the PreToolUse hook (Claude Code spawns this per tool call)
 */
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import { Engine } from '../engine/server.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = resolve(HERE, '..', '..');

async function runEngine(): Promise<void> {
  const port = Number(process.env.AG_ENGINE_PORT ?? 9000);
  const rulesPath = process.env.AG_RULES ?? join(PROJECT_ROOT, 'rules', 'default_policy.yaml');
  const auditFile = process.env.AG_AUDIT ?? join(PROJECT_ROOT, '.agentguard', 'audit.jsonl');
  const ttlMs = Number(process.env.AG_TTL_MS ?? 300_000); // 5 min default — NOT 60s

  const engine = new Engine({ port, rulesPath, auditFile, ttlMs });
  await engine.listen();
  process.stderr.write(
    `AgentGuard engine listening on :${port}\n` +
      `  rules: ${rulesPath}\n  audit: ${auditFile}\n  HITL TTL: ${ttlMs}ms\n` +
      `  dashboard WS: ws://127.0.0.1:${port}/ws\n`,
  );
}

async function main(): Promise<void> {
  const cmd = process.argv[2];
  if (cmd === 'engine') return runEngine();
  if (cmd === 'hook') {
    await import('../hook/index.js');
    return;
  }
  process.stderr.write('usage: agentguard <engine|hook>\n');
  process.exit(1);
}

void main();

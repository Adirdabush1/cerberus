#!/usr/bin/env node
/**
 * `agentguard` launcher. Prefers the compiled CLI in `dist/` (published package); falls back to
 * running the TypeScript source via tsx when `dist/` is absent (local dev). Either way it exports
 * AG_HOME = the package root so the CLI can resolve bundled resources (rules/, dashboard/dist/)
 * consistently whether it runs from src/ or dist/.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const distCli = join(root, 'dist', 'cli', 'index.js');
const args = process.argv.slice(2);

const spawnArgs = existsSync(distCli)
  ? [distCli, ...args]
  : ['--import', 'tsx', join(root, 'src', 'cli', 'index.ts'), ...args];

const child = spawn(process.execPath, spawnArgs, {
  stdio: 'inherit',
  env: { ...process.env, AG_HOME: root },
});
child.on('exit', (code) => process.exit(code ?? 0));

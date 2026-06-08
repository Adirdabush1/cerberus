#!/usr/bin/env node
/**
 * Dev launcher: runs the TypeScript CLI via tsx so `agentguard` works without a build
 * step. The published package will point `bin` at the compiled dist/cli/index.js.
 */
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const cli = join(root, 'src', 'cli', 'index.ts');

const child = spawn(process.execPath, ['--import', 'tsx', cli, ...process.argv.slice(2)], {
  stdio: 'inherit',
});
child.on('exit', (code) => process.exit(code ?? 0));

// Unit test for `agentguard init` (run: npx tsx scripts/init.test.ts).
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInit } from '../src/cli/init.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) {
    pass++;
    console.log(`  ✅ ${name}`);
  } else {
    fail++;
    console.log(`  ❌ ${name} — ${detail}`);
  }
}

const origCwd = process.cwd();
const origWrite = process.stdout.write.bind(process.stdout);
function quiet<T>(fn: () => T): { out: string; ret: T } {
  let out = '';
  (process.stdout.write as unknown) = (s: string) => ((out += s), true);
  try {
    const ret = fn(); // run BEFORE reading `out`
    return { out, ret };
  } finally {
    (process.stdout.write as unknown) = origWrite;
  }
}
const read = (p: string) => JSON.parse(readFileSync(p, 'utf8'));

try {
  // ── fresh project: init creates settings.json with both hooks ──
  {
    const dir = mkdtempSync(join(tmpdir(), 'ag-init-'));
    process.chdir(dir);
    quiet(() => runInit([]));
    const sp = join(dir, '.claude', 'settings.json');
    check('creates .claude/settings.json', existsSync(sp));
    const s = read(sp);
    const cmd = s.hooks?.PreToolUse?.[0]?.hooks?.[0]?.command ?? '';
    check('PreToolUse hook wired (node … hook)', /bin\/agentguard\.mjs hook$/.test(cmd), cmd);
    check('PostToolUse hook wired', !!s.hooks?.PostToolUse?.[0]?.hooks?.[0]?.command);
    check('PreToolUse timeout >= 300 (>= engine TTL)', s.hooks.PreToolUse[0].hooks[0].timeout >= 300);
  }

  // ── idempotent: a second init adds nothing, no duplicates ──
  {
    const dir = mkdtempSync(join(tmpdir(), 'ag-init-'));
    process.chdir(dir);
    quiet(() => runInit([]));
    const { out } = quiet(() => runInit([]));
    const s = read(join(dir, '.claude', 'settings.json'));
    check('second init reports nothing to do', /nothing to do/.test(out), out.trim());
    check('no duplicate PreToolUse groups', s.hooks.PreToolUse.length === 1, JSON.stringify(s.hooks.PreToolUse));
  }

  // ── merge: existing keys + foreign hooks are preserved, backup written ──
  {
    const dir = mkdtempSync(join(tmpdir(), 'ag-init-'));
    process.chdir(dir);
    mkdirSync(join(dir, '.claude'));
    const sp = join(dir, '.claude', 'settings.json');
    writeFileSync(sp, JSON.stringify({ model: 'opus', hooks: { PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo existing' }] }] } }));
    quiet(() => runInit([]));
    const s = read(sp);
    check('preserves unrelated keys (model)', s.model === 'opus');
    check('preserves the foreign PreToolUse hook', s.hooks.PreToolUse.some((g: { hooks?: { command?: string }[] }) => g.hooks?.[0]?.command === 'echo existing'));
    check('appends our PreToolUse hook (now 2 groups)', s.hooks.PreToolUse.length === 2, JSON.stringify(s.hooks.PreToolUse.length));
    check('adds PostToolUse', !!s.hooks.PostToolUse);
    check('backup written', existsSync(`${sp}.bak`));
  }

  // ── --print: emits the snippet, writes NOTHING ──
  {
    const dir = mkdtempSync(join(tmpdir(), 'ag-init-'));
    process.chdir(dir);
    const { out } = quiet(() => runInit(['--print']));
    check('--print emits a hooks snippet', /PreToolUse/.test(out) && /PostToolUse/.test(out));
    check('--print writes no file', !existsSync(join(dir, '.claude', 'settings.json')));
  }
} finally {
  process.chdir(origCwd);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

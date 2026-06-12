// Unit test for `cerberus init` (run: npx tsx scripts/init.test.ts).
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
    // path is quoted (Windows spaces) and may use either separator; command tags the agent (M5)
    check('PreToolUse hook wired (node "…/cerberus.mjs" hook --agent claude)', /cerberus\.mjs"? hook --agent claude$/.test(cmd), cmd);
    check('PostToolUse hook wired', !!s.hooks?.PostToolUse?.[0]?.hooks?.[0]?.command);
    check('PreToolUse timeout >= 300 (>= engine TTL)', s.hooks.PreToolUse[0].hooks[0].timeout >= 300);
    check('SessionStart hook wired', !!s.hooks?.SessionStart?.[0]?.hooks?.[0]?.command);
    check('SessionEnd hook wired', !!s.hooks?.SessionEnd?.[0]?.hooks?.[0]?.command);
    check('session hooks carry no matcher (not tool-scoped)', s.hooks.SessionStart[0].matcher === undefined && s.hooks.SessionEnd[0].matcher === undefined);
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
    check('--print emits a hooks snippet', /PreToolUse/.test(out) && /PostToolUse/.test(out) && /SessionStart/.test(out) && /SessionEnd/.test(out));
    check('--print writes no file', !existsSync(join(dir, '.claude', 'settings.json')));
  }

  // ── M5: per-agent wiring (codex / cursor / cline) ──
  {
    const dir = mkdtempSync(join(tmpdir(), 'ag-init-'));
    process.chdir(dir);

    quiet(() => runInit(['--agent', 'codex']));
    const codex = read(join(dir, '.codex', 'hooks.json'));
    check('codex: writes .codex/hooks.json with PreToolUse', /cerberus\.mjs"? hook --agent codex$/.test(codex.hooks?.PreToolUse?.[0]?.hooks?.[0]?.command ?? ''));

    quiet(() => runInit(['--agent', 'cursor']));
    const cursor = read(join(dir, '.cursor', 'hooks.json'));
    const shell = cursor.hooks?.beforeShellExecution?.[0];
    check('cursor: beforeShellExecution wired + failClosed', /--agent cursor$/.test(shell?.command ?? '') && shell?.failClosed === true);

    quiet(() => runInit(['--agent', 'cline']));
    const clinePre = join(dir, '.clinerules', 'hooks', 'PreToolUse');
    check('cline: writes executable PreToolUse script', existsSync(clinePre) && readFileSync(clinePre, 'utf8').includes('--agent cline'));

    const { out } = quiet(() => runInit(['--agent', 'codex']));
    check('codex: second run is idempotent', /nothing to do/.test(out), out.trim());
  }
} finally {
  process.chdir(origCwd);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

/**
 * `agentguard init` — wire the Pre/PostToolUse hooks into Claude Code's settings (D21).
 *
 * Auto-merge, safe by default: MERGES into the existing settings.json (never overwrites), is
 * IDEMPOTENT (won't double-add), and BACKS UP the file before changing it. `--global` targets
 * ~/.claude/settings.json; `--print` emits the snippet without touching any file.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync, copyFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

const PACKAGE_ROOT = process.env.AG_HOME ?? process.cwd();
const BIN = join(PACKAGE_ROOT, 'bin', 'agentguard.mjs');
// Pre ≥ engine TTL (it holds the socket); the others are quick fire-and-acknowledge posts.
const HOOK_TIMEOUTS = { PreToolUse: 310, PostToolUse: 10, SessionStart: 10, SessionEnd: 10 } as const;
// Tool-scoped events match by tool (`*`); session lifecycle events are not tool-scoped (no matcher).
const TOOL_EVENTS = new Set<keyof typeof HOOK_TIMEOUTS>(['PreToolUse', 'PostToolUse']);
const HOOK_EVENTS = Object.keys(HOOK_TIMEOUTS) as (keyof typeof HOOK_TIMEOUTS)[];

interface HookCmd { type: 'command'; command: string; timeout?: number }
interface HookGroup { matcher?: string; hooks?: HookCmd[] }
interface Settings { hooks?: Record<string, HookGroup[]>; [k: string]: unknown }

function hookGroup(event: keyof typeof HOOK_TIMEOUTS): HookGroup {
  const hooks: HookCmd[] = [{ type: 'command', command: `node ${BIN} hook`, timeout: HOOK_TIMEOUTS[event] }];
  return TOOL_EVENTS.has(event) ? { matcher: '*', hooks } : { hooks };
}

/** True if this event already has an AgentGuard hook (idempotency). */
function alreadyWired(groups: HookGroup[]): boolean {
  return groups.some((g) => g.hooks?.some((h) => typeof h.command === 'string' && h.command.includes(BIN) && /\bhook\b/.test(h.command)));
}

export function runInit(argv: string[]): void {
  const global = argv.includes('--global');
  const printOnly = argv.includes('--print');
  const settingsPath = global
    ? join(homedir(), '.claude', 'settings.json')
    : join(process.cwd(), '.claude', 'settings.json');

  if (printOnly) {
    const snippet = { hooks: Object.fromEntries(HOOK_EVENTS.map((e) => [e, [hookGroup(e)]])) };
    process.stdout.write(
      `Add this to ${settingsPath} (merge into any existing "hooks"):\n\n${JSON.stringify(snippet, null, 2)}\n\n` +
        `Then run \`agentguard engine\` and open the dashboard.\n`,
    );
    return;
  }

  const settings: Settings = existsSync(settingsPath)
    ? (JSON.parse(readFileSync(settingsPath, 'utf8')) as Settings)
    : {};
  settings.hooks ??= {};

  let added = 0;
  let unchanged = 0;
  for (const event of HOOK_EVENTS) {
    const groups = (settings.hooks[event] ??= []);
    if (!Array.isArray(groups)) {
      process.stderr.write(`AgentGuard: unexpected ${event} shape in ${settingsPath}; leaving it untouched.\n`);
      continue;
    }
    if (alreadyWired(groups)) {
      unchanged++;
      continue;
    }
    groups.push(hookGroup(event));
    added++;
  }

  if (added === 0) {
    process.stdout.write(`AgentGuard hooks already present in ${settingsPath} — nothing to do.\n`);
    return;
  }

  // back up before writing
  if (existsSync(settingsPath)) copyFileSync(settingsPath, `${settingsPath}.bak`);
  mkdirSync(dirname(settingsPath), { recursive: true });
  writeFileSync(settingsPath, JSON.stringify(settings, null, 2) + '\n');

  process.stdout.write(
    `✅ Wired AgentGuard into ${settingsPath} (${added} hook${added > 1 ? 's' : ''} added, ${unchanged} already present).\n` +
      (existsSync(`${settingsPath}.bak`) ? `   Backup: ${settingsPath}.bak\n` : '') +
      `\nNext:\n  1. agentguard engine        # start the gateway + dashboard\n  2. open http://127.0.0.1:9000/   # the dashboard\n  3. use Claude Code as usual — tool calls now route through AgentGuard.\n`,
  );
}

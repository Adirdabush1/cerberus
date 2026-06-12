// Per-agent adapter unit test (parse + format). Run: npx tsx scripts/adapters.test.ts
import { getAdapter } from '../src/hook/adapters.js';

let pass = 0,
  fail = 0;
function check(name: string, cond: boolean, detail = '') {
  if (cond) (pass++, console.log(`  ✅ ${name}`));
  else (fail++, console.log(`  ❌ ${name} — ${detail}`));
}
const J = (v: unknown) => JSON.stringify(v);

// ── adapter selection ──
check('default agent is claude', getAdapter(undefined).name === 'claude');
check('unknown agent falls back to claude', getAdapter('bogus').name === 'claude');
check('getAdapter resolves each agent', (['claude', 'codex', 'cursor', 'cline'] as const).every((a) => getAdapter(a).name === a));

// ── capabilities (ASK vs HOLD) ──
check('claude/cursor support native ask', getAdapter('claude').supportsAsk && getAdapter('cursor').supportsAsk);
check('codex/cline do NOT support ask (→ hold)', !getAdapter('codex').supportsAsk && !getAdapter('cline').supportsAsk);

// ── Claude parse ──
const claude = getAdapter('claude');
const cPre = claude.parse({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls' }, session_id: 's1', cwd: '/x' });
check('claude parse PreToolUse → pre + call', cPre.kind === 'pre' && cPre.call?.tool === 'Bash' && cPre.call?.input.command === 'ls' && cPre.call?.sessionId === 's1', J(cPre));
const cPost = claude.parse({ hook_event_name: 'PostToolUse', tool_name: 'Read', tool_input: {}, tool_response: 'AKIA-secret', session_id: 's1' });
check('claude parse PostToolUse → post + toolResponse', cPost.kind === 'post' && cPost.toolResponse === 'AKIA-secret', J(cPost));
check('claude parse PostToolUse failure → error', claude.parse({ hook_event_name: 'PostToolUse', tool_name: 'Bash', error: 'boom' }).error === 'boom');
check('claude parse SessionStart → session-start + source', J(claude.parse({ hook_event_name: 'SessionStart', source: 'startup' })) === J({ kind: 'session-start', sessionSource: 'startup' }));
check('claude parse SessionEnd → session-end', claude.parse({ hook_event_name: 'SessionEnd', session_id: 's' }).kind === 'session-end');
check('claude formatPre(ask) → permissionDecision ask', J(claude.formatPre('ask', 'r')) === J({ hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: 'r' } }));

// ── Codex (claude-shape parse, allow/deny only) ──
const codex = getAdapter('codex');
check('codex parse → pre + command', codex.parse({ tool_name: 'shell', tool_input: { command: 'rm x' } }).call?.input.command === 'rm x');
check('codex formatPre(allow) → permissionDecision allow', (codex.formatPre('allow', 'ok') as { hookSpecificOutput: { permissionDecision: string } }).hookSpecificOutput.permissionDecision === 'allow');
check('codex maps ask→deny defensively', (codex.formatPre('ask', 'x') as { hookSpecificOutput: { permissionDecision: string } }).hookSpecificOutput.permissionDecision === 'deny');

// ── Cursor (command top-level; permission field; ask supported) ──
const cursor = getAdapter('cursor');
const curShell = cursor.parse({ command: 'npm publish', conversation_id: 'c1', cwd: '/x' });
check('cursor parse beforeShellExecution → pre Bash', curShell.kind === 'pre' && curShell.call?.tool === 'Bash' && curShell.call?.input.command === 'npm publish' && curShell.call?.sessionId === 'c1', J(curShell));
check('cursor parse MCP tool → pre with tool name', cursor.parse({ tool_name: 'mcp__x__y', tool_input: { a: 1 }, conversation_id: 'c1' }).call?.tool === 'mcp__x__y');
check('cursor ignores non-gated events', cursor.parse({ hook_event_name: 'beforeReadFile' }).kind === 'ignore');
check('cursor formatPre(ask) → permission ask', J(cursor.formatPre('ask', 'r')) === J({ permission: 'ask', agentMessage: 'r' }));

// ── Cline (cancel boolean) ──
const cline = getAdapter('cline');
check('cline parse → pre + tool', cline.parse({ tool_name: 'execute_command', tool_input: { command: 'ls' } }).call?.tool === 'execute_command');
check('cline parse (camelCase fields) → pre', cline.parse({ toolName: 'write_to_file', toolInput: { path: 'a' } }).call?.tool === 'write_to_file');
check('cline formatPre(deny) → cancel:true', J(cline.formatPre('deny', 'blocked')) === J({ cancel: true, contextModification: 'blocked' }));
check('cline formatPre(allow) → cancel:false', J(cline.formatPre('allow', 'ok')) === J({ cancel: false }));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

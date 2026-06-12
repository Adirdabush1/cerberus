/**
 * The agent hook — a DUMB CLIENT shared across agents (M5). The agent is selected by `--agent <name>`
 * (or AG_AGENT; default `claude`); a per-agent adapter (./adapters) parses the stdin event and formats
 * the verdict. The flow is identical everywhere:
 *
 * PreToolUse:  POST the normalized tool call to `/intercept`; the engine answers ALLOW / BLOCK / ASK.
 *              ASK → defer to the agent's NATIVE approval prompt (agents that support it). For agents
 *              without a native prompt, the engine HOLDS the socket and a dashboard/CLI decision resolves
 *              it. Fail-Closed if the engine is unreachable (unless AG_FAIL_OPEN=1).
 * PostToolUse: POST the result to `/inspect` (observe-only contamination update); never modifies it.
 * Session*:    POST to `/session` (timeline bookend + monitor reset). Best-effort.
 */
import { request } from 'node:http';
import { closeSync, openSync, writeSync } from 'node:fs';
import type { InspectRequest, MCPToolCall, PipelineResult, SessionEvent } from '../contract/types.js';
import { getAdapter, type ParsedEvent, type Verdict } from './adapters.js';

const ENGINE_HOST = process.env.AG_ENGINE_HOST ?? '127.0.0.1';
const ENGINE_PORT = Number(process.env.AG_ENGINE_PORT ?? 9000);
const FAIL_OPEN = process.env.AG_FAIL_OPEN === '1';
const TERMINAL_NOTIFY = process.env.AG_NOTIFY !== '0';
const HELD_NOTICE_MS = Number(process.env.AG_HELD_NOTICE_MS ?? 400); // a slower /intercept ⇒ it's held (D41)

// Which agent are we adapting? `--agent <name>` (written by `agentguard init`) or AG_AGENT; default claude.
function selectedAgent(): string | undefined {
  const i = process.argv.indexOf('--agent');
  if (i >= 0 && process.argv[i + 1]) return process.argv[i + 1];
  return process.env.AG_AGENT;
}
const adapter = getAdapter(selectedAgent());

// HITL handling: 'ask' if the agent has a native prompt and the user hasn't forced the dashboard;
// otherwise 'hold' (engine holds the socket, dashboard/CLI resolves).
const APPROVAL_MODE: 'ask' | 'hold' = adapter.supportsAsk && process.env.AG_APPROVAL_SURFACE !== 'dashboard' ? 'ask' : 'hold';

// The controlling-terminal device: `\\.\CON` on Windows, `/dev/tty` on POSIX.
const TTY_DEVICE = process.platform === 'win32' ? '\\\\.\\CON' : '/dev/tty';

/** Notify the human in the terminal, off the stdout protocol channel — `/dev/tty`, falling back to stderr. */
function notify(line: string): void {
  if (!TERMINAL_NOTIFY) return;
  const msg = line.endsWith('\n') ? line : line + '\n';
  try {
    const fd = openSync(TTY_DEVICE, 'a');
    writeSync(fd, msg);
    closeSync(fd);
  } catch {
    process.stderr.write(msg);
  }
}

function sessionLink(sessionId?: string): string {
  return sessionId ? `  ·  http://${ENGINE_HOST}:${ENGINE_PORT}/?session=${encodeURIComponent(sessionId)}` : '';
}

function emit(obj: unknown): never {
  process.stdout.write(JSON.stringify(obj));
  process.exit(0);
}
function emitPre(verdict: Verdict, reason: string): never {
  emit(adapter.formatPre(verdict, reason));
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (data += c));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(data));
  });
}

function post<T>(path: string, body: unknown): Promise<T> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = request(
      {
        host: ENGINE_HOST,
        port: ENGINE_PORT,
        path,
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
      },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (data += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(data) as T);
          } catch {
            reject(new Error('invalid engine response'));
          }
        });
      },
    );
    // Do NOT set a short socket timeout: a hold can last minutes. The outer bound is the agent's hook
    // `timeout` setting (must be >= the engine's TTL).
    req.on('error', reject);
    req.end(payload);
  });
}

async function handlePre(call: MCPToolCall): Promise<never> {
  call.approvalMode = APPROVAL_MODE;

  // If /intercept is slow to answer, the call is being HELD — tell the human so the agent isn't just
  // silently hung (D41). The specific id isn't known yet, so point at `agentguard pending`.
  let held = false;
  const heldTimer = setTimeout(() => {
    held = true;
    notify(`⏸ AgentGuard HELD ${call.tool} — awaiting approval.\n   review: agentguard pending${sessionLink(call.sessionId)}`);
  }, HELD_NOTICE_MS);

  try {
    const result = await post<PipelineResult>('/intercept', call);
    clearTimeout(heldTimer);
    // ASK → the engine wants the agent's native prompt. The adapter formats it (e.g. permissionDecision
    // "ask" for Claude, permission "ask" for Cursor).
    if (result.action === 'ASK') emitPre('ask', result.reason);
    if (held) {
      notify(result.action === 'ALLOW' ? `✓ AgentGuard: approved ${call.tool}` : `⛔ AgentGuard: denied ${call.tool}`);
    } else if (result.action === 'BLOCK') {
      notify(`⛔ AgentGuard BLOCKED ${call.tool} · ${result.reason}${sessionLink(result.sessionId ?? call.sessionId)}`);
    } // auto ALLOW / AUDIT → silent in the terminal (D36)
    emitPre(result.action === 'ALLOW' ? 'allow' : 'deny', result.reason);
  } catch (err) {
    clearTimeout(heldTimer);
    const why = `AgentGuard engine unreachable at ${ENGINE_HOST}:${ENGINE_PORT} (${(err as Error).message}).`;
    if (FAIL_OPEN) emitPre('allow', `${why} AG_FAIL_OPEN=1 → allowing.`);
    emitPre('deny', `${why} Start it with \`agentguard engine\`, or set AG_FAIL_OPEN=1. Failing closed.`);
  }
}

async function handlePost(parsed: ParsedEvent): Promise<never> {
  const call = parsed.call ?? { tool: 'unknown', input: {} };
  const body: InspectRequest = {
    tool: call.tool,
    input: call.input,
    sessionId: call.sessionId,
    toolResponse: parsed.toolResponse ?? '',
    ...(parsed.error != null ? { error: parsed.error } : {}),
  };
  try {
    const resp = await post<{ tainted?: boolean; secretTypes?: string[]; injectionFlagged?: boolean }>('/inspect', body);
    if (resp.tainted) notify(`⚠ AgentGuard: secret loaded into context via ${body.tool}${resp.secretTypes?.length ? ` (${resp.secretTypes.join(', ')})` : ''}${sessionLink(body.sessionId)}`);
    if (resp.injectionFlagged) notify(`⚠ AgentGuard: prompt-injection detected in ${body.tool} result — outbound calls now gated.${sessionLink(body.sessionId)}`);
  } catch {
    /* best-effort: PostToolUse cannot block, so a missing engine just means no taint update. */
  }
  emit(adapter.formatPost());
}

async function handleSession(kind: 'started' | 'ended', parsed: ParsedEvent): Promise<never> {
  const body: SessionEvent = { event: kind, sessionId: parsed.call?.sessionId ?? 'default', source: parsed.sessionSource };
  try {
    await post('/session', body);
  } catch {
    /* best-effort: session bookkeeping never blocks the agent. */
  }
  emit(adapter.formatSession());
}

async function main(): Promise<void> {
  const raw = await readStdin();
  let event: Record<string, unknown> = {};
  try {
    event = JSON.parse(raw || '{}') as Record<string, unknown>;
  } catch {
    /* malformed event */
  }

  const parsed = adapter.parse(event);
  switch (parsed.kind) {
    case 'session-start':
      return void (await handleSession('started', parsed));
    case 'session-end':
      return void (await handleSession('ended', parsed));
    case 'post':
      return void (await handlePost(parsed));
    case 'ignore':
      return emit(adapter.formatPost()); // not a gated event for this agent — acknowledge and proceed
    case 'pre':
    default:
      return void (await handlePre(parsed.call ?? { tool: 'unknown', input: {} }));
  }
}

void main();

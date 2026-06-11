/**
 * The Claude Code hook — a DUMB CLIENT for both hook events.
 *
 * PreToolUse:  reads the event on stdin, POSTs the tool call to the Engine `/intercept`, and keeps
 *              the HTTP connection open until the Engine answers (the open socket IS the synchronous
 *              hold). It then emits the Claude Code permission decision (allow/deny).
 *              Fail-Closed by default: if the Engine is unreachable, deny — unless AG_FAIL_OPEN=1.
 *
 * PostToolUse: POSTs the executed tool's RESULT to the Engine `/inspect` so the engine can update its
 *              per-session contamination state, then waits only for that state-commit (D9) and exits.
 *              It NEVER modifies the result (contamination model — enforcement is pre-flight, D2).
 *              Best-effort: a PostToolUse hook cannot block, so if the engine is unreachable we simply
 *              let the result through (there is nothing to fail closed).
 */
import { request } from 'node:http';
import type { InspectRequest, MCPToolCall, PipelineResult, SessionEvent } from '../contract/types.js';

interface HookEvent {
  hook_event_name?: string;
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  tool_response?: unknown;
  tool_output?: unknown; //  some Claude Code versions/docs name the result field this way
  error?: unknown; //        present when the tool FAILED instead of returning a result
  session_id?: string;
  source?: string; //        SessionStart: startup | resume | clear
  cwd?: string;
}

const ENGINE_HOST = process.env.AG_ENGINE_HOST ?? '127.0.0.1';
const ENGINE_PORT = Number(process.env.AG_ENGINE_PORT ?? 9000);
const FAIL_OPEN = process.env.AG_FAIL_OPEN === '1';

function emitPre(decision: 'allow' | 'deny', reason: string): never {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason },
    }),
  );
  process.exit(0);
}

/** PostToolUse exit — we deliberately do NOT modify the result; just acknowledge the event. */
function emitPost(): never {
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse' } }));
  process.exit(0);
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
    // Do NOT set a short socket timeout: a PreToolUse hold can last minutes. The outer bound is
    // Claude Code's hook `timeout` setting (must be >= the Engine's TTL).
    req.on('error', reject);
    req.end(payload);
  });
}

async function handlePre(event: HookEvent): Promise<never> {
  const call: MCPToolCall = {
    tool: event.tool_name ?? 'unknown',
    input: event.tool_input ?? {},
    sessionId: event.session_id,
    cwd: event.cwd,
  };
  try {
    const result = await post<PipelineResult>('/intercept', call);
    emitPre(result.action === 'ALLOW' ? 'allow' : 'deny', result.reason);
  } catch (err) {
    const why = `AgentGuard engine unreachable at ${ENGINE_HOST}:${ENGINE_PORT} (${(err as Error).message}).`;
    if (FAIL_OPEN) emitPre('allow', `${why} AG_FAIL_OPEN=1 → allowing.`);
    emitPre('deny', `${why} Start it with \`agentguard engine\`, or set AG_FAIL_OPEN=1. Failing closed.`);
  }
}

async function handlePost(event: HookEvent): Promise<never> {
  // Be tolerant of the result field name across Claude Code versions (robustness flag): the result
  // may arrive as tool_response or tool_output, or be absent on a failure that carries `error`.
  const tr = event.tool_response ?? event.tool_output;
  const err = event.error;
  const body: InspectRequest = {
    tool: event.tool_name ?? 'unknown',
    input: event.tool_input ?? {},
    sessionId: event.session_id,
    toolResponse: typeof tr === 'string' ? tr : JSON.stringify(tr ?? ''),
    ...(err !== undefined && err !== null ? { error: typeof err === 'string' ? err : JSON.stringify(err) } : {}),
  };
  try {
    await post('/inspect', body);
  } catch {
    /* best-effort: PostToolUse cannot block, so a missing engine just means no taint update. */
  }
  emitPost();
}

/** SessionStart / SessionEnd — observability-only; bookends the timeline and resets monitors on end. */
async function handleSession(event: HookEvent, kind: 'started' | 'ended'): Promise<never> {
  const body: SessionEvent = { event: kind, sessionId: event.session_id ?? 'default', source: event.source };
  try {
    await post('/session', body);
  } catch {
    /* best-effort: session bookkeeping never blocks the agent. */
  }
  process.stdout.write('{}');
  process.exit(0);
}

async function main(): Promise<void> {
  const raw = await readStdin();
  let event: HookEvent = {};
  try {
    event = JSON.parse(raw || '{}');
  } catch {
    /* malformed event */
  }

  const name = event.hook_event_name;
  if (name === 'SessionStart') return void (await handleSession(event, 'started'));
  if (name === 'SessionEnd') return void (await handleSession(event, 'ended'));

  const isPost =
    name === 'PostToolUse' ||
    event.tool_response !== undefined ||
    event.tool_output !== undefined ||
    event.error !== undefined;
  if (isPost) return void (await handlePost(event));
  return void (await handlePre(event));
}

void main();

/**
 * The Claude Code PreToolUse hook — a DUMB CLIENT.
 *
 * It holds no state. It reads the PreToolUse event on stdin, POSTs the tool call to
 * the Engine, and keeps the HTTP connection open until the Engine answers (the open
 * socket is the synchronous hold). It then emits the Claude Code permission decision.
 *
 * Fail-Closed by default: if the Engine is unreachable, deny — unless AG_FAIL_OPEN=1.
 */
import { request } from 'node:http';
import type { MCPToolCall, PipelineResult } from '../contract/types.js';

interface PreToolUseEvent {
  tool_name?: string;
  tool_input?: Record<string, unknown>;
  session_id?: string;
  cwd?: string;
}

const ENGINE_HOST = process.env.AG_ENGINE_HOST ?? '127.0.0.1';
const ENGINE_PORT = Number(process.env.AG_ENGINE_PORT ?? 9000);
const FAIL_OPEN = process.env.AG_FAIL_OPEN === '1';

function emit(decision: 'allow' | 'deny', reason: string): never {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: decision,
        permissionDecisionReason: reason,
      },
    }),
  );
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

function intercept(call: MCPToolCall): Promise<PipelineResult> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(call);
    const req = request(
      {
        host: ENGINE_HOST,
        port: ENGINE_PORT,
        path: '/intercept',
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) },
      },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(body) as PipelineResult);
          } catch {
            reject(new Error('invalid engine response'));
          }
        });
      },
    );
    // Do NOT set a short socket timeout: the hold can last minutes. The outer bound
    // is Claude Code's hook `timeout` setting (must be >= the Engine's TTL).
    req.on('error', reject);
    req.end(payload);
  });
}

async function main(): Promise<void> {
  const raw = await readStdin();
  let event: PreToolUseEvent = {};
  try {
    event = JSON.parse(raw || '{}');
  } catch {
    /* malformed event */
  }

  const call: MCPToolCall = {
    tool: event.tool_name ?? 'unknown',
    input: event.tool_input ?? {},
    sessionId: event.session_id,
    cwd: event.cwd,
  };

  try {
    const result = await intercept(call);
    emit(result.action === 'ALLOW' ? 'allow' : 'deny', result.reason);
  } catch (err) {
    const why = `AgentGuard engine unreachable at ${ENGINE_HOST}:${ENGINE_PORT} (${(err as Error).message}).`;
    if (FAIL_OPEN) emit('allow', `${why} AG_FAIL_OPEN=1 → allowing.`);
    emit('deny', `${why} Start it with \`agentguard engine\`, or set AG_FAIL_OPEN=1. Failing closed.`);
  }
}

void main();

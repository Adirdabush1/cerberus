#!/usr/bin/env node
// AgentGuard — M0 spike: a Claude Code PreToolUse hook.
// Proves the two foundational assumptions:
//   (1) we can intercept ANY tool call (built-in Bash included), classify it, and BLOCK
//       with a custom denial returned to the model.
//   (2) we can hold an action synchronously for human approval (the HITL "money maker").
//
// Reads the PreToolUse JSON event on stdin, prints a PreToolUse hook decision on stdout.
// Zero dependencies. File-based pending/approval (Redis is the production swap-in).

import { readFileSync, appendFileSync, existsSync, writeFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HERE = dirname(fileURLToPath(import.meta.url));
const AUDIT = join(HERE, 'audit.jsonl');
const PENDING = join(HERE, 'pending');
const HITL_TIMEOUT_MS = Number(process.env.AG_HITL_TIMEOUT_MS ?? 300_000); // 5 min default
const POLL_MS = 200;

// ---- read stdin ----
function readStdin() {
  try { return readFileSync(0, 'utf8'); } catch { return ''; }
}

// ---- the three lines of defense (hardcoded for the spike; OPA replaces this later) ----
function classify(event) {
  const tool = event.tool_name ?? '';
  const input = event.tool_input ?? {};
  const cmd = (input.command ?? '').toString();
  const path = (input.file_path ?? input.path ?? '').toString();

  // Signal: secret read -> still allowed, but caller can taint (exfil state) in prod.
  // 2) AUTO-BLOCK — destructive / secret-exfil
  if (tool === 'Bash') {
    if (/\brm\s+-rf?\b/.test(cmd) || /\brm\s+-[a-z]*r[a-z]*f?\b/.test(cmd)) {
      return { decision: 'deny', reason: 'AgentGuard: destructive command (rm -rf) blocked by policy.' };
    }
    if (/\bgit\s+push\b/.test(cmd) || /\b(npm|yarn|pnpm)\s+publish\b/.test(cmd)) {
      return { decision: 'hitl', reason: `AgentGuard: state-changing command requires human approval: \`${cmd}\`` };
    }
  }
  if (tool === 'Read' && /(^|\/)\.env(\.|$)/.test(path)) {
    return { decision: 'deny', reason: 'AgentGuard: reading .env is blocked by policy.' };
  }
  // 3) HITL — state changers via built-in write tools
  if (tool === 'Write' || tool === 'Edit') {
    return { decision: 'hitl', reason: `AgentGuard: file ${tool.toLowerCase()} to \`${path}\` requires human approval.` };
  }
  // 1) AUTO-APPROVE — everything else (read-only / safe) passes in ms
  return { decision: 'allow', reason: 'AgentGuard: auto-approved.' };
}

// ---- synchronous hold: write a pending request, poll for a decision file ----
function holdForApproval(event, reason) {
  const id = `${(event.session_id ?? 'sess').slice(0, 8)}-${process.pid}-${audit_seq()}`;
  const reqFile = join(PENDING, `${id}.json`);
  const decisionFile = join(PENDING, `${id}.decision`);
  writeFileSync(reqFile, JSON.stringify({
    id, tool: event.tool_name, input: event.tool_input, reason, ts: '(spawn-time)'
  }, null, 2));

  const deadline = nowish() + HITL_TIMEOUT_MS;
  // busy-wait poll (spike only). Production: Redis BLPOP / pub-sub, no spin.
  while (nowish() < deadline) {
    if (existsSync(decisionFile)) {
      const d = readFileSync(decisionFile, 'utf8').trim().toLowerCase();
      return d.startsWith('approve')
        ? { decision: 'allow', reason: `AgentGuard: approved by human (request ${id}).` }
        : { decision: 'deny', reason: `AgentGuard: denied by human (request ${id}).` };
    }
    sleepSync(POLL_MS);
  }
  return { decision: 'deny', reason: `AgentGuard: approval timed out after ${HITL_TIMEOUT_MS}ms (request ${id}) — fail-safe deny.` };
}

// Date.now()/setTimeout-free helpers (env may restrict Date; use hrtime + Atomics.wait)
function nowish() { return Number(process.hrtime.bigint() / 1_000_000n); }
function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }
let _seq = 0;
function audit_seq() { return (++_seq).toString().padStart(3, '0'); }

// ---- main ----
const raw = readStdin();
let event = {};
try { event = JSON.parse(raw || '{}'); } catch { event = {}; }

let { decision, reason } = classify(event);
if (decision === 'hitl') ({ decision, reason } = holdForApproval(event, reason));

// audit every decision
try {
  appendFileSync(AUDIT, JSON.stringify({
    tool: event.tool_name, input: event.tool_input, decision, reason
  }) + '\n');
} catch {}

// Claude Code PreToolUse decision schema
const out = {
  hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: decision === 'allow' ? 'allow' : 'deny',
    permissionDecisionReason: reason,
  },
};
process.stdout.write(JSON.stringify(out));
process.exit(0);

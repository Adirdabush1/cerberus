/**
 * AgentGuard Engine — the long-running process.
 *
 * Responsibilities:
 *   • POST /intercept — the dumb hook posts a tool call and HOLDS the socket open.
 *                       ALLOW/BLOCK return immediately; HITL holds until a human
 *                       decides, the TTL fires, or the socket closes.
 *   • WebSocket /ws   — streams pending violations to the dashboard and receives
 *                       Approve/Deny decisions back.
 *   • GET  /health, GET /pending, POST /decision — REST surface (health, hydration,
 *                       and a dashboard-less fallback used by the smoke test).
 *
 * The open HTTP socket itself is the synchronous hold. No polling, no Redis.
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { WebSocketServer, type WebSocket } from 'ws';
import { JsonLogicPolicyEngine, type PolicyEngine } from '../policy/engine.js';
import { InMemoryPendingStore } from '../policy/store.js';
import { AuditLog } from '../audit/index.js';
import { classify } from '../taxonomy/index.js';
import type {
  AuditEntry,
  DashboardToServer,
  FinalAction,
  MCPToolCall,
  PipelineResult,
  SecurityViolation,
  ServerToDashboard,
} from '../contract/types.js';

export interface EngineOptions {
  port: number;
  rulesPath: string;
  auditFile: string;
  ttlMs: number;
}

export class Engine {
  private readonly policy: PolicyEngine;
  private readonly store = new InMemoryPendingStore();
  private readonly audit: AuditLog;
  private readonly clients = new Set<WebSocket>();
  private readonly http = createServer((req, res) => this.route(req, res));
  private readonly wss = new WebSocketServer({ server: this.http, path: '/ws' });

  constructor(private readonly opts: EngineOptions) {
    this.policy = new JsonLogicPolicyEngine(opts.rulesPath);
    this.audit = new AuditLog(opts.auditFile);

    // fan out store lifecycle to every connected dashboard
    this.store.on('registered', (v: SecurityViolation) => this.broadcast({ type: 'violation', violation: v }));
    this.store.on('resolved', (id: string, action: FinalAction) =>
      this.broadcast({ type: 'resolved', violationId: id, action }),
    );

    this.wss.on('connection', (ws) => this.onDashboardConnect(ws));
  }

  listen(): Promise<void> {
    return new Promise((resolve) => this.http.listen(this.opts.port, () => resolve()));
  }

  close(): Promise<void> {
    return new Promise((resolve) => {
      this.wss.close();
      this.http.close(() => resolve());
    });
  }

  /* ------------------------------- HTTP routing ------------------------------- */

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    try {
      if (req.method === 'GET' && req.url === '/health') {
        return json(res, 200, { ok: true, pending: this.store.pending().length });
      }
      if (req.method === 'GET' && req.url === '/pending') {
        return json(res, 200, { pending: this.store.pending() });
      }
      if (req.method === 'POST' && req.url === '/decision') {
        const body = await readJson<DashboardToServer>(req);
        await this.store.resolveContext(body.violationId, body.action);
        return json(res, 200, { ok: true });
      }
      if (req.method === 'POST' && req.url === '/intercept') {
        return await this.handleIntercept(req, res);
      }
      json(res, 404, { error: 'not found' });
    } catch (err) {
      json(res, 400, { error: (err as Error).message });
    }
  }

  /** The synchronous hold. */
  private async handleIntercept(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const call = await readJson<MCPToolCall>(req);
    const decision = this.policy.evaluate(call);

    // Auto paths: answer immediately.
    if (decision.action === 'ALLOW' || decision.action === 'BLOCK') {
      this.writeAudit(call, decision.action, decision.ruleId, decision.reason, false);
      return json(res, 200, finalResult(decision.action, decision.reason));
    }

    // HITL: build a violation, hold the socket, and wait for a verdict.
    const violation: SecurityViolation = {
      id: randomUUID(),
      toolCall: call,
      category: classify(call.tool),
      ruleId: decision.ruleId,
      reason: decision.reason,
      createdAt: Date.now(),
      ttlMs: this.opts.ttlMs,
    };

    let settled = false;
    // If the agent/hook goes away mid-hold, free the held context instead of leaking it.
    // `res` 'close' fires when the connection closes; guard with `settled` so the normal
    // post-response close is a no-op.
    res.on('close', () => {
      if (!settled) void this.store.cleanup(violation.id);
    });

    const result = await this.store.registerContext(violation, this.opts.ttlMs);
    settled = true;

    this.writeAudit(call, result.action, decision.ruleId, result.reason, true);
    if (!res.writableEnded) json(res, 200, result);
  }

  /* ------------------------------- WebSocket -------------------------------- */

  private onDashboardConnect(ws: WebSocket): void {
    this.clients.add(ws);
    send(ws, { type: 'hello', pending: this.store.pending() });

    ws.on('message', (raw) => {
      try {
        const msg = JSON.parse(raw.toString()) as DashboardToServer;
        if (msg.type === 'decision') void this.store.resolveContext(msg.violationId, msg.action);
      } catch {
        /* ignore malformed dashboard messages */
      }
    });
    ws.on('close', () => this.clients.delete(ws));
  }

  private broadcast(msg: ServerToDashboard): void {
    for (const ws of this.clients) send(ws, msg);
  }

  /* --------------------------------- audit ---------------------------------- */

  private writeAudit(
    call: MCPToolCall,
    action: FinalAction,
    ruleId: string | null,
    reason: string,
    viaHitl: boolean,
  ): void {
    const entry: AuditEntry = {
      ts: Date.now(),
      tool: call.tool,
      category: classify(call.tool),
      action,
      ruleId,
      reason,
      viaHitl,
    };
    this.audit.record(entry);
    this.broadcast({ type: 'audit', entry });
  }
}

/* --------------------------------- helpers --------------------------------- */

function finalResult(action: FinalAction, reason: string): PipelineResult {
  return { action, reason };
}

function json(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(payload);
}

function readJson<T>(req: IncomingMessage): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 1_000_000) reject(new Error('payload too large'));
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(data || '{}') as T);
      } catch {
        reject(new Error('invalid JSON body'));
      }
    });
    req.on('error', reject);
  });
}

function send(ws: WebSocket, msg: ServerToDashboard): void {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(msg));
}

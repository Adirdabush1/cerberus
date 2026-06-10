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
import { existsSync, readFileSync, statSync } from 'node:fs';
import { extname, join, normalize, sep } from 'node:path';
import { WebSocketServer, type WebSocket } from 'ws';
import { JsonLogicPolicyEngine, type PolicyEngine } from '../policy/engine.js';
import { InMemoryPendingStore } from '../policy/store.js';
import { InMemoryBehavioralMonitor, type AnomalyConfig, type BehavioralMonitor } from '../signals/behavioral.js';
import {
  InMemoryContaminationMonitor,
  type ContaminationMonitor,
  type ContentConfig,
} from '../signals/content.js';
import {
  DisabledInjectionClassifier,
  loadInjectionClassifier,
  type InjectionClassifier,
  type InjectionConfig,
} from '../signals/injection.js';
import { WeightedRiskEngine, type RiskEngine } from '../risk/engine.js';
import { AuditLog } from '../audit/index.js';
import { classify } from '../taxonomy/index.js';
import type {
  AuditEntry,
  DashboardToServer,
  FinalAction,
  InspectRequest,
  MCPToolCall,
  PipelineResult,
  RiskAssessment,
  SecurityViolation,
  ServerToDashboard,
  SignalSource,
} from '../contract/types.js';

export interface EngineOptions {
  port: number;
  rulesPath: string;
  auditFile: string;
  ttlMs: number;
  behavioral: AnomalyConfig;
  content: ContentConfig;
  injection: InjectionConfig;
  weightsPath: string;
  /** If set, serve the built dashboard (static files) from this dir at `/` (D20). */
  staticDir?: string;
}

export class Engine {
  private readonly policy: PolicyEngine;
  private readonly behavioral: BehavioralMonitor;
  private readonly contamination: ContaminationMonitor;
  private readonly risk: RiskEngine;
  private injection: InjectionClassifier = new DisabledInjectionClassifier();
  private readonly store = new InMemoryPendingStore();
  private readonly audit: AuditLog;
  private readonly clients = new Set<WebSocket>();
  private readonly http = createServer((req, res) => this.route(req, res));
  private readonly wss = new WebSocketServer({ server: this.http, path: '/ws' });

  constructor(private readonly opts: EngineOptions) {
    this.policy = new JsonLogicPolicyEngine(opts.rulesPath);
    this.behavioral = new InMemoryBehavioralMonitor(opts.behavioral);
    this.contamination = new InMemoryContaminationMonitor(opts.content);
    this.risk = new WeightedRiskEngine(opts.weightsPath);
    this.audit = new AuditLog(opts.auditFile);

    // fan out store lifecycle to every connected dashboard
    this.store.on('registered', (v: SecurityViolation) => this.broadcast({ type: 'violation', violation: v }));
    this.store.on('resolved', (id: string, action: FinalAction) =>
      this.broadcast({ type: 'resolved', violationId: id, action }),
    );

    this.wss.on('connection', (ws) => this.onDashboardConnect(ws));
  }

  async listen(): Promise<void> {
    // Resolve the injection classifier (D13): the ONNX companion package if installed, else the
    // always-on heuristic baseline, else disabled. Done here so a slow model load doesn't block import.
    this.injection = await loadInjectionClassifier(this.opts.injection);
    await new Promise<void>((resolve) => this.http.listen(this.opts.port, () => resolve()));
  }

  /** Name of the resolved injection classifier ('onnx' / 'heuristic' / 'disabled') — for the CLI banner. */
  get injectionClassifier(): string {
    return this.injection.name;
  }

  /** Version of the loaded risk-weights config — for the CLI banner + drift traceability. */
  get riskVersion(): string {
    return this.risk.version;
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
      if (req.method === 'POST' && req.url === '/inspect') {
        return await this.handleInspect(req, res);
      }
      // The dashboard (static) is served LAST, so it never shadows an API route (D20).
      if (req.method === 'GET' && this.opts.staticDir) {
        return this.serveStatic(req, res);
      }
      json(res, 404, { error: 'not found' });
    } catch (err) {
      json(res, 400, { error: (err as Error).message });
    }
  }

  /** The synchronous hold + multi-signal decision pipeline (PreToolUse). */
  private async handleIntercept(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const call = await readJson<MCPToolCall>(req);

    // Run all three signals (each has side effects — behavioral records the call, content records
    // path-risk), then fold them into one decision via strictest-wins (D7).
    const anomaly = this.behavioral.record(call); // Signal 1: runaway / loop
    const policy = this.policy.evaluate(call); //     Signal 2: deterministic rules
    const content = this.contamination.evaluate(call); // Signal 3: contamination / exfil
    // M3c: aggregate the three into one risk-scored decision (hard floor + weighted bands).
    const { action, reason, ruleId, signal, risk } = this.risk.assess(policy, anomaly, content);

    // Auto paths: answer immediately. (AUDIT band collapses to ALLOW for the agent — D17 — but the
    // audit record carries risk.band='AUDIT' so it surfaces as elevated-risk on the dashboard.)
    if (action === 'ALLOW' || action === 'BLOCK') {
      this.writeAudit(call, action, ruleId, reason, false, signal, risk);
      return json(res, 200, finalResult(action, reason));
    }

    // HITL: build a violation, hold the socket, and wait for a verdict.
    const violation: SecurityViolation = {
      id: randomUUID(),
      toolCall: call,
      category: classify(call.tool),
      ruleId,
      reason,
      createdAt: Date.now(),
      ttlMs: this.opts.ttlMs,
      signal,
      risk,
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

    this.writeAudit(call, result.action, ruleId, result.reason, true, signal, risk);
    if (!res.writableEnded) json(res, 200, result);
  }

  /**
   * PostToolUse inspection (D2/D9). Observe-only: update the session's contamination state from the
   * executed tool's result, never modify the result. The hook waits only for this state-commit.
   */
  private async handleInspect(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson<InspectRequest>(req);
    const call: MCPToolCall = { tool: body.tool, input: body.input ?? {}, sessionId: body.sessionId };
    const text = body.toolResponse ?? '';
    const outcome = this.contamination.inspect(call, text);

    // Signal 3b (injection): classify the result; a positive raises the session's posture so the
    // next egress is gated (D12). Async/observe-only — never withholds or blocks the result.
    let injectionFlagged = false;
    let injectionScore = 0;
    if (this.injection.available) {
      const verdict = await this.injection.classify(text);
      injectionScore = verdict.score;
      if (verdict.score >= this.opts.injection.threshold) {
        injectionFlagged = true;
        this.contamination.flagInjection(call.sessionId ?? 'default', verdict.score, call.tool);
        this.writeAudit(
          call,
          'ALLOW',
          'content-injection-detected',
          `Prompt-injection detected in ${call.tool} result (score ${verdict.score.toFixed(2)}, ${this.injection.name}). Session posture raised — outbound calls now require review.`,
          false,
          'content',
        );
      }
    }

    if (outcome.tainted) {
      // Auditable security event: a secret entered the agent's context. Not a block (the read already
      // happened) — it arms the exfil gate for subsequent egress on this session.
      this.writeAudit(
        call,
        'ALLOW',
        'content-secret-loaded',
        `Secret loaded into context via ${call.tool}: ${outcome.secretTypes.join(', ')}. Session tainted — outbound calls now require review.`,
        false,
        'content',
      );
    }
    return json(res, 200, {
      ok: true,
      tainted: outcome.tainted,
      secretTypes: outcome.secretTypes,
      injectionFlagged,
      injectionScore,
      classifier: this.injection.name,
    });
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

  /* ------------------------------ static dashboard ------------------------------ */

  /** Serve the built dashboard from opts.staticDir, with SPA fallback to index.html (D20). */
  private serveStatic(req: IncomingMessage, res: ServerResponse): void {
    const dir = this.opts.staticDir as string;
    const urlPath = decodeURIComponent((req.url ?? '/').split('?')[0] ?? '/');
    const rel = urlPath === '/' || urlPath === '' ? 'index.html' : urlPath.replace(/^\/+/, '');
    let file = normalize(join(dir, rel));

    // path-traversal guard: the resolved file must stay inside the static dir.
    if (file !== dir && !file.startsWith(dir + sep)) return json(res, 403, { error: 'forbidden' });
    if (!existsSync(file) || !statSync(file).isFile()) file = join(dir, 'index.html'); // SPA fallback
    if (!existsSync(file)) return json(res, 404, { error: 'dashboard not built (run `npm run build`)' });

    res.writeHead(200, { 'content-type': contentType(extname(file)) });
    res.end(readFileSync(file));
  }

  /* --------------------------------- audit ---------------------------------- */

  private writeAudit(
    call: MCPToolCall,
    action: FinalAction,
    ruleId: string | null,
    reason: string,
    viaHitl: boolean,
    signal: SignalSource,
    risk?: RiskAssessment,
  ): void {
    const entry: AuditEntry = {
      ts: Date.now(),
      tool: call.tool,
      category: classify(call.tool),
      action,
      ruleId,
      reason,
      viaHitl,
      signal,
      risk,
    };
    this.audit.record(entry);
    this.broadcast({ type: 'audit', entry });
  }
}

/* --------------------------------- helpers --------------------------------- */

function finalResult(action: FinalAction, reason: string): PipelineResult {
  return { action, reason };
}

const CONTENT_TYPES: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
};

function contentType(ext: string): string {
  return CONTENT_TYPES[ext.toLowerCase()] ?? 'application/octet-stream';
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

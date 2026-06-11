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
import { spawn } from 'node:child_process';
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
import { projectTimeline, summarizeSessions } from '../audit/projector.js';
import { classify } from '../taxonomy/index.js';
import type {
  AuditEntry,
  DashboardToServer,
  FinalAction,
  HitlResolution,
  InspectRequest,
  MCPToolCall,
  RiskBand,
  SecurityViolation,
  ServerToDashboard,
  SessionEvent,
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
  /** Auto-open the investigation UI on severe verdicts (M4-C, D39). 'block' ⇒ on BLOCK/EXFIL; 'off' ⇒ never. */
  autoOpen?: 'block' | 'off';
  /** Opener injection seam (tests pass a spy); defaults to the platform browser-opener. */
  opener?: (url: string) => void;
}

const AUTO_OPEN_WINDOW_MS = 30_000; // don't reopen the same session's tab more than once per window

export class Engine {
  private readonly policy: PolicyEngine;
  private readonly behavioral: BehavioralMonitor;
  private readonly contamination: ContaminationMonitor;
  private readonly risk: RiskEngine;
  private injection: InjectionClassifier = new DisabledInjectionClassifier();
  private readonly store = new InMemoryPendingStore();
  private readonly lastOpened = new Map<string, number>(); // session → last auto-open ts (rate-limit)
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
      if (req.method === 'POST' && req.url === '/session') {
        return await this.handleSession(req, res);
      }
      // Investigation history (D25): project the replayed audit log into session rollups / a timeline.
      // O(log size) per request — fine for the local single-engine tier; the paid tier would index.
      if (req.method === 'GET' && req.url === '/sessions') {
        return json(res, 200, { sessions: summarizeSessions(this.audit.read()) });
      }
      if (req.method === 'GET' && req.url?.startsWith('/sessions/')) {
        const m = /^\/sessions\/([^/]+)\/timeline\/?$/.exec(req.url.split('?')[0] ?? '');
        if (m) return json(res, 200, projectTimeline(this.audit.read(), decodeURIComponent(m[1] as string)));
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
    const requestId = randomUUID(); // one id per tool-call decision; links its lifecycle events (D24)
    const category = classify(call.tool);

    // Run all three signals (each has side effects — behavioral records the call, content records
    // path-risk), then fold them into one decision via strictest-wins (D7).
    const anomaly = this.behavioral.record(call); // Signal 1: runaway / loop
    const policy = this.policy.evaluate(call); //     Signal 2: deterministic rules
    const content = this.contamination.evaluate(call); // Signal 3: contamination / exfil
    // M3c: aggregate the three into one risk-scored decision (hard floor + weighted bands).
    const { action, reason, ruleId, signal, risk } = this.risk.assess(policy, anomaly, content);

    const base = { sessionId: call.sessionId, requestId, tool: call.tool, input: call.input, category, ruleId, signal, risk };

    // Auto paths: answer immediately. (AUDIT band collapses to ALLOW for the agent — D17 — but the
    // audit record carries risk.band='AUDIT' so it surfaces as elevated-risk on the dashboard.)
    if (action === 'ALLOW' || action === 'BLOCK') {
      this.writeAudit({ ...base, event: 'decision', action, reason, viaHitl: false });
      if (action === 'BLOCK') this.maybeAutoOpen(call.sessionId, risk.band);
      return json(res, 200, { action, reason, band: risk.band, sessionId: call.sessionId });
    }

    // HITL: build a violation, hold the socket, and wait for a verdict.
    const violation: SecurityViolation = {
      id: requestId,
      toolCall: call,
      category,
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

    this.writeAudit({ ...base, event: 'hitl-opened', reason });
    const result = await this.store.registerContext(violation, this.opts.ttlMs);
    settled = true;

    this.writeAudit({
      ...base,
      event: 'hitl-resolved',
      action: result.action,
      reason: result.reason,
      viaHitl: true,
      resolution: resolutionOf(result.action, result.reason),
      latencyMs: Date.now() - violation.createdAt,
    });
    if (result.action === 'BLOCK') this.maybeAutoOpen(call.sessionId, risk.band);
    if (!res.writableEnded) json(res, 200, { ...result, band: risk.band, sessionId: call.sessionId });
  }

  /**
   * Auto-open the investigation UI on a severe verdict (M4-C, D39). Engine-side so it can dedup/rate-
   * limit centrally — a burst of BLOCKs in one session opens at most one tab per window. Best-effort:
   * a failed opener never affects enforcement.
   */
  private maybeAutoOpen(sessionId: string | undefined, band: RiskBand): void {
    if ((this.opts.autoOpen ?? 'off') !== 'block') return;
    if (band !== 'BLOCK') return; // BLOCK band covers exfil/injection blocks (their score florors here)
    const sid = sessionId ?? 'default';
    const now = Date.now();
    const last = this.lastOpened.get(sid) ?? 0;
    if (now - last < AUTO_OPEN_WINDOW_MS) return;
    this.lastOpened.set(sid, now);
    const url = `http://127.0.0.1:${this.opts.port}/?session=${encodeURIComponent(sid)}`;
    try {
      (this.opts.opener ?? defaultOpener)(url);
    } catch {
      /* best-effort */
    }
  }

  /**
   * PostToolUse inspection (D2/D9). Observe-only: update the session's contamination state from the
   * executed tool's result, never modify the result. The hook waits only for this state-commit.
   */
  private async handleInspect(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson<InspectRequest>(req);
    const call: MCPToolCall = { tool: body.tool, input: body.input ?? {}, sessionId: body.sessionId };

    // A failed tool produced no result to scan — record the failure for the timeline and stop (D23).
    if (body.error) {
      this.writeAudit({
        event: 'tool-failed',
        sessionId: body.sessionId,
        tool: body.tool,
        category: classify(body.tool),
        reason: body.error.slice(0, 500),
      });
      return json(res, 200, { ok: true, failed: true });
    }

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
        this.writeAudit({
          event: 'injection-detected',
          sessionId: call.sessionId,
          tool: call.tool,
          category: classify(call.tool),
          signal: 'content',
          injectionScore: verdict.score,
          reason: `Prompt-injection detected in ${call.tool} result (score ${verdict.score.toFixed(2)}, ${this.injection.name}). Session posture raised — outbound calls now require review.`,
        });
      }
    }

    if (outcome.tainted) {
      // Auditable security event: a secret entered the agent's context. Not a block (the read already
      // happened) — it arms the exfil gate for subsequent egress on this session.
      this.writeAudit({
        event: 'taint-loaded',
        sessionId: call.sessionId,
        tool: call.tool,
        category: classify(call.tool),
        signal: 'content',
        secretTypes: outcome.secretTypes,
        reason: `Secret loaded into context via ${call.tool}: ${outcome.secretTypes.join(', ')}. Session tainted — outbound calls now require review.`,
      });
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

  /**
   * SessionStart / SessionEnd (D23). Observability-only — bookends the session timeline. On 'ended'
   * we also reset the per-session monitor state, which is the deterministic counterpart to the
   * idle-eviction in M2/M3 (a session that ends cleanly shouldn't wait to be swept).
   */
  private async handleSession(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await readJson<SessionEvent>(req);
    const sessionId = body.sessionId || 'default';
    if (body.event === 'ended') {
      this.behavioral.reset(sessionId);
      this.contamination.reset(sessionId);
    }
    this.writeAudit({
      event: body.event === 'started' ? 'session-started' : 'session-ended',
      sessionId,
      reason:
        body.event === 'started'
          ? `Session started${body.source ? ` (${body.source})` : ''}.`
          : 'Session ended — monitor state reset.',
    });
    return json(res, 200, { ok: true });
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

  /**
   * Append one event to the audit log (single source of truth, D22) and stream it live to every
   * dashboard. `sessionId` is coerced to 'default' so every record is attributable (hardening, step 1);
   * a record the log rejects as malformed is NOT broadcast, so live and history stay consistent.
   */
  private writeAudit(entry: Omit<AuditEntry, 'ts'>): void {
    const full: AuditEntry = { ts: Date.now(), ...entry, sessionId: entry.sessionId ?? 'default' };
    if (this.audit.record(full)) this.broadcast({ type: 'audit', entry: full });
  }
}

/* --------------------------------- helpers --------------------------------- */

/** Open a URL in the user's default browser, cross-platform, detached (best-effort). */
function defaultOpener(url: string): void {
  const cmd = process.platform === 'darwin' ? 'open' : process.platform === 'win32' ? 'start' : 'xdg-open';
  const child = spawn(cmd, [url], { stdio: 'ignore', detached: true, shell: process.platform === 'win32' });
  child.unref();
}

/** Classify how a held call ended, from the store's verdict — for the hitl-resolved latency event (D23). */
function resolutionOf(action: FinalAction, reason: string): HitlResolution {
  if (action === 'ALLOW') return 'approved';
  return /timed out|disconnected/i.test(reason) ? 'expired' : 'rejected';
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

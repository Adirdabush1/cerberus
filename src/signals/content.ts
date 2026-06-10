/**
 * Content signal (M3a, deterministic) — the contamination / taint model.
 *
 * Two halves (see brainstorms/m3-content-signal.md):
 *   • inspect()  — PostToolUse: OBSERVE a tool result, never modify it. Detect secrets in the
 *                  returned content and mark the session *content-confirmed* tainted.
 *   • evaluate() — PreToolUse: the ENFORCEMENT read. Records *path-risk* for sensitive-path calls,
 *                  and escalates an EGRESS call to HITL when the session is content-confirmed.
 *
 * Asymmetric decay (D5): content-confirmed taint persists for the whole session (the secret is
 * still in the agent's context — a TTL here would be a trivial "wait it out" bypass); path-risk is
 * a softer heuristic that decays via a TTL.
 *
 * Enforcement is ALWAYS pre-flight (D2): this never withholds or rewrites a result. The hard stop is
 * the PreToolUse decision on the *next* action. In-memory per process; the interface lets a
 * Redis-backed monitor drop in for the multi-instance paid tier.
 */
import { classify } from '../taxonomy/index.js';
import type { MCPToolCall } from '../contract/types.js';

export interface ContentConfig {
  pathRiskTtlMs: number;    // path-risk heuristic decays after this
  scanLimitBytes: number;   // only scan the first N bytes of a tool result (latency cap)
  entropyThreshold: number; // Shannon bits/char above which a long unstructured token is "secret-like"
  entropyMinLen: number;    // minimum token length to bother entropy-checking
}

export const DEFAULT_CONTENT_CONFIG: ContentConfig = {
  pathRiskTtlMs: 300_000, // 5 min
  scanLimitBytes: 65_536, // first 64 KB
  entropyThreshold: 4.0,
  entropyMinLen: 24,
};

/** What evaluate() contributes to the PreToolUse decision. Content only ever escalates to HITL (D4). */
export interface ContentVerdict {
  action: 'HITL' | null; // content's own action hint; the RiskEngine reads `kind` to weight it
  reason: string | null;
  kind: 'content-exfil' | 'content-injection' | 'path-risk' | null;
}

const NO_VERDICT: ContentVerdict = { action: null, reason: null, kind: null };

/** What inspect() found in a tool result. */
export interface InspectOutcome {
  secretTypes: string[];
  tainted: boolean;
}

export interface ContaminationMonitor {
  /** PostToolUse: observe a tool result and update session contamination state. Never mutates the result. */
  inspect(call: MCPToolCall, result: string): InspectOutcome;
  /** PostToolUse: record that a tool result was flagged as prompt-injection (M3b posture escalation, D12). */
  flagInjection(sessionId: string, score: number, tool: string): void;
  /** PreToolUse: record path-risk for sensitive-path calls and return content's contribution to the decision. */
  evaluate(call: MCPToolCall): ContentVerdict;
  /** Forget a session's contamination (e.g. when the session ends). */
  reset(sessionId: string): void;
}

interface SessionState {
  content: { types: Set<string>; ts: number } | null; // persistent for the session (D5)
  path: { paths: Set<string>; lastTs: number } | null; // heuristic, decays via TTL (D5)
  injection: { score: number; ts: number; tool: string } | null; // heuristic, decays via TTL (D12)
}

// ── secret patterns (curated; D8) — structured token shapes first ──
const SECRET_PATTERNS: ReadonlyArray<{ type: string; re: RegExp }> = [
  { type: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/ },
  { type: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { type: 'openai-key', re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/ },
  { type: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/ },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { type: 'private-key', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/ },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  {
    type: 'generic-secret-assignment',
    re: /\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-.]{12,}/i,
  },
];

// Paths that, when read, are an early warning the session may be loading secrets.
const SENSITIVE_PATH =
  /(^|\/)(\.env(\.[^/]*)?|\.aws|\.ssh|id_rsa|id_ed25519|[^/]*\.pem|credentials|secrets?\.(?:ya?ml|json|txt))(\/|$)/i;

export class InMemoryContaminationMonitor implements ContaminationMonitor {
  private readonly sessions = new Map<string, SessionState>();

  constructor(private readonly cfg: ContentConfig = DEFAULT_CONTENT_CONFIG) {}

  inspect(call: MCPToolCall, result: string): InspectOutcome {
    const text = typeof result === 'string' ? result.slice(0, this.cfg.scanLimitBytes) : '';
    const found = detectSecrets(text, this.cfg);
    if (found.size === 0) return { secretTypes: [], tainted: false };

    const st = this.get(call.sessionId ?? 'default');
    const types = st.content?.types ?? new Set<string>();
    for (const t of found) types.add(t);
    st.content = { types, ts: Date.now() };
    return { secretTypes: [...found], tainted: true };
  }

  flagInjection(sessionId: string, score: number, tool: string): void {
    this.get(sessionId).injection = { score, ts: Date.now(), tool };
  }

  evaluate(call: MCPToolCall): ContentVerdict {
    const sessionId = call.sessionId ?? 'default';
    const now = Date.now();
    const st = this.get(sessionId);

    // heuristic signals decay (D5/D12)
    if (st.path && now - st.path.lastTs > this.cfg.pathRiskTtlMs) st.path = null;
    if (st.injection && now - st.injection.ts > this.cfg.pathRiskTtlMs) st.injection = null;

    // record path-risk for sensitive-path access (early-warning, complementary signal — D3)
    const path = pathOf(call);
    if (path && SENSITIVE_PATH.test(path)) {
      const paths = st.path?.paths ?? new Set<string>();
      paths.add(path);
      st.path = { paths, lastTs: now };
    }

    // Enforcement (D4/D12): only EGRESS is gated. Content-confirmed taint (a real secret) is the
    // strongest case; a live injection flag also raises posture. path-only risk stays audit/allow.
    let verdict: ContentVerdict = NO_VERDICT;
    if (classify(call.tool) === 'EGRESS') {
      if (st.content) {
        const types = [...st.content.types].join(', ');
        verdict = {
          action: 'HITL',
          reason: `Potential exfiltration: a secret (${types}) was loaded into this session, and the agent is now making an outbound ${call.tool} call. Approve only if this egress is expected.`,
          kind: 'content-exfil',
        };
      } else if (st.injection) {
        verdict = {
          action: 'HITL',
          reason: `Raised posture: a prior tool result (${st.injection.tool}) was flagged as prompt-injection (score ${st.injection.score.toFixed(2)}); the agent is now making an outbound ${call.tool} call. Approve only if this egress is expected.`,
          kind: 'content-injection',
        };
      } else if (st.path) {
        // path-only risk: a weak early-warning. Action stays null (audit/allow, D4) — the RiskEngine
        // gives it a small weight that only escalates when it stacks with other concerns.
        verdict = {
          action: null,
          reason: `Path-risk: this session accessed a sensitive path (${[...st.path.paths][0]}) and is now making an outbound ${call.tool} call.`,
          kind: 'path-risk',
        };
      }
    }

    this.evictIfClean(sessionId, now);
    return verdict;
  }

  reset(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  private get(sessionId: string): SessionState {
    let st = this.sessions.get(sessionId);
    if (!st) {
      st = { content: null, path: null, injection: null };
      this.sessions.set(sessionId, st);
    }
    return st;
  }

  /**
   * Drop a session that holds nothing actionable — no confirmed taint and no live path-risk — so the
   * map can't grow forever from benign traffic. Content-confirmed sessions persist by design (D5)
   * until `reset`, because the secret is still in the agent's context.
   */
  private evictIfClean(sessionId: string, now: number): void {
    const st = this.sessions.get(sessionId);
    if (!st) return;
    const pathLive = !!st.path && now - st.path.lastTs <= this.cfg.pathRiskTtlMs;
    const injLive = !!st.injection && now - st.injection.ts <= this.cfg.pathRiskTtlMs;
    if (!st.content && !pathLive && !injLive) this.sessions.delete(sessionId);
  }
}

function pathOf(call: MCPToolCall): string {
  const i = call.input ?? {};
  const p = i['file_path'] ?? i['path'];
  return typeof p === 'string' ? p : '';
}

function detectSecrets(text: string, cfg: ContentConfig): Set<string> {
  const found = new Set<string>();
  for (const { type, re } of SECRET_PATTERNS) if (re.test(text)) found.add(type);

  // Entropy fallback (D8) — only when no structured pattern matched, tuned conservative to limit FPs.
  if (found.size === 0) {
    for (const token of text.split(/[\s'"`,;(){}[\]]+/)) {
      if (
        token.length >= cfg.entropyMinLen &&
        /^[A-Za-z0-9+/=_-]+$/.test(token) &&
        shannon(token) >= cfg.entropyThreshold
      ) {
        found.add('high-entropy');
        break;
      }
    }
  }
  return found;
}

/** Shannon entropy in bits/char — a cheap "does this look random/secret-like" measure. */
function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

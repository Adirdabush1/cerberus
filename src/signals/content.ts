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
import { createHash } from 'node:crypto';
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
  kind: 'content-exfil-match' | 'content-exfil' | 'content-injection' | 'path-risk' | null;
}

/**
 * A secret captured from a tool result, kept ONLY in session memory for egress content-matching (M6).
 * `value` is the raw secret — NEVER logged or persisted; only `hash`/`type`/`source` ever leave memory.
 */
interface SecretRef {
  value: string; //   raw, in-memory only (dropped on reset/session-end)
  type: string;
  source: string; //  e.g. "Read /path/.env:4" — for provenance in the verdict reason
  hash: string; //    sha256 prefix — the only form that may appear in audit
  confidence: number;
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
  content: { types: Set<string>; secrets: SecretRef[]; ts: number } | null; // persistent for the session (D5)
  path: { paths: Set<string>; lastTs: number } | null; // heuristic, decays via TTL (D5)
  injection: { score: number; ts: number; tool: string } | null; // heuristic, decays via TTL (D12)
}

// ── secret patterns (curated; D8) — structured token shapes first. `valueGroup` is the capture group
// holding the secret VALUE to match against egress (default: the whole match); `confidence` 0–1. ──
const SECRET_PATTERNS: ReadonlyArray<{ type: string; re: RegExp; confidence: number; valueGroup?: number }> = [
  { type: 'aws-access-key', re: /\bAKIA[0-9A-Z]{16}\b/, confidence: 0.98 },
  { type: 'github-token', re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/, confidence: 0.98 },
  { type: 'openai-key', re: /\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b/, confidence: 0.97 },
  { type: 'slack-token', re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, confidence: 0.95 },
  { type: 'google-api-key', re: /\bAIza[0-9A-Za-z\-_]{35}\b/, confidence: 0.95 },
  { type: 'private-key', re: /-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----/, confidence: 0.9 },
  { type: 'jwt', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, confidence: 0.9 },
  {
    type: 'generic-secret-assignment',
    re: /\b(?:api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['"]?([A-Za-z0-9_\-.]{12,})/i,
    confidence: 0.85,
    valueGroup: 1,
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
    const found = detectSecretValues(text, this.cfg);
    if (found.length === 0) return { secretTypes: [], tainted: false };

    const st = this.get(call.sessionId ?? 'default');
    const types = st.content?.types ?? new Set<string>();
    const secrets = st.content?.secrets ?? [];
    const base = `${call.tool}${pathOf(call) ? ` ${pathOf(call)}` : ''}`;
    for (const f of found) {
      types.add(f.type);
      // Keep the raw value in memory for egress matching; store provenance + hash only (M6).
      if (!secrets.some((s) => s.value === f.value)) {
        secrets.push({ value: f.value, type: f.type, source: `${base}:${f.line}`, hash: hash12(f.value), confidence: f.confidence });
      }
    }
    if (secrets.length > 50) secrets.splice(0, secrets.length - 50); // bound memory
    st.content = { types, secrets, ts: Date.now() };
    return { secretTypes: [...new Set(found.map((f) => f.type))], tainted: true };
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

    // Enforcement (D4/D12): EGRESS is gated for exfil/injection/path-risk. Under a live injection
    // posture (M7) a WRITE is ALSO gated — a poisoned instruction's classic payload is the agent
    // writing a backdoor; the file write is already HITL, but attributing it to the injection (and
    // letting it stack in the risk score) surfaces "this write may be attacker-driven".
    let verdict: ContentVerdict = NO_VERDICT;
    const cat = classify(call.tool);
    if (cat === 'EGRESS') {
      // M6: precise content-match — does the OUTBOUND payload actually carry a loaded secret?
      // This is the strongest exfil evidence; reported with provenance + confidence, never the value.
      const hit = st.content?.secrets?.length ? matchSecret(st.content.secrets, payloadOf(call, this.cfg.scanLimitBytes)) : null;
      if (hit) {
        const dest = destOf(call);
        verdict = {
          action: 'HITL',
          reason: `Confirmed exfiltration: a ${hit.type} secret (source: ${hit.source}, sha256:${hit.hash}, confidence ${Math.round(hit.confidence * 100)}%) appears in the outbound ${call.tool} payload${dest ? ` to ${dest}` : ''}. Approve only if this is intended.`,
          kind: 'content-exfil-match',
        };
      } else if (st.content) {
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
    } else if (cat === 'WRITE' && st.injection) {
      verdict = {
        action: 'HITL',
        reason: `Raised posture: a prior tool result (${st.injection.tool}) was flagged as prompt-injection (score ${st.injection.score.toFixed(2)}); the agent is now WRITING via ${call.tool}. A poisoned instruction may be driving this write — approve only if expected.`,
        kind: 'content-injection',
      };
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

interface FoundSecret {
  value: string;
  type: string;
  confidence: number;
  line: number;
}

/** Detect secrets in a tool result, capturing the matched VALUE + provenance line for egress matching. */
function detectSecretValues(text: string, cfg: ContentConfig): FoundSecret[] {
  const out: FoundSecret[] = [];
  for (const { type, re, confidence, valueGroup } of SECRET_PATTERNS) {
    const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
    let m: RegExpExecArray | null;
    while ((m = g.exec(text)) !== null) {
      const value = (valueGroup != null ? m[valueGroup] : m[0]) ?? m[0];
      if (value && value.length >= 8) out.push({ value, type, confidence, line: lineOf(text, m.index) });
      if (m.index === g.lastIndex) g.lastIndex++; // never loop on a zero-width match
    }
  }

  // Entropy fallback (D8) — only when no structured pattern matched, tuned conservative to limit FPs.
  if (out.length === 0) {
    for (const token of text.split(/[\s'"`,;(){}[\]]+/)) {
      if (token.length >= cfg.entropyMinLen && /^[A-Za-z0-9+/=_-]+$/.test(token) && shannon(token) >= cfg.entropyThreshold) {
        out.push({ value: token, type: 'high-entropy', confidence: 0.75, line: lineOf(text, text.indexOf(token)) });
        break;
      }
    }
  }
  return out;
}

const lineOf = (text: string, idx: number): number => (idx < 0 ? 1 : text.slice(0, idx).split('\n').length);

const hash12 = (v: string): string => createHash('sha256').update(v).digest('hex').slice(0, 12);

/** The encoded forms an exfil might use — we encode the KNOWN secret and search the payload for any. */
function encodedForms(v: string): string[] {
  const forms = [v];
  try {
    forms.push(Buffer.from(v).toString('base64'), Buffer.from(v).toString('hex'), encodeURIComponent(v));
  } catch {
    /* non-encodable — raw only */
  }
  return forms.filter((f) => f.length >= 8);
}

/** Does the egress payload contain any loaded secret (raw or commonly-encoded)? Returns the match. */
function matchSecret(secrets: readonly SecretRef[], payload: string): SecretRef | null {
  for (const s of secrets) for (const form of encodedForms(s.value)) if (payload.includes(form)) return s;
  return null;
}

/** Serialize the outbound call's args (url + body + headers…) for content scanning, capped for latency. */
function payloadOf(call: MCPToolCall, limit: number): string {
  try {
    return JSON.stringify(call.input ?? {}).slice(0, limit);
  } catch {
    return '';
  }
}

/** Best-effort destination host from the egress call, for the provenance reason. */
function destOf(call: MCPToolCall): string {
  const u = call.input?.['url'];
  if (typeof u !== 'string') return '';
  try {
    return new URL(u).host;
  } catch {
    return '';
  }
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

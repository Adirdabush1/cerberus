/**
 * Behavioral signal — catches runaway agents that a per-call policy can never see:
 * tight loops, the same command fired N times, or a flood of tool calls per minute.
 *
 * We measure TOOL-CALL rate/volume/repetition — NOT token spend (tokens live on the
 * LLM path the gateway does not proxy). Two tiers:
 *   • review — over the soft threshold ⇒ escalate an otherwise-ALLOW call to HITL.
 *   • block  — over the hard ceiling   ⇒ cut it off immediately (definitely runaway).
 *
 * In-memory per process (single local Engine). The interface lets a Redis-backed
 * monitor drop in for the multi-instance paid tier.
 */
import type { MCPToolCall } from '../contract/types.js';

export interface AnomalyConfig {
  windowMs: number;        // sliding window size
  maxRate: number;         // soft cap on total calls per window per session
  maxRepeat: number;       // soft cap on identical calls per window per session
  hardMultiplier: number;  // ceiling = soft cap × this ⇒ auto-block
}

export const DEFAULT_ANOMALY_CONFIG: AnomalyConfig = {
  windowMs: 60_000,
  maxRate: 30,
  maxRepeat: 10,
  hardMultiplier: 2,
};

export interface AnomalyVerdict {
  severity: 'review' | 'block' | null;
  reason: string | null;
}

const OK: AnomalyVerdict = { severity: null, reason: null };

export interface BehavioralMonitor {
  /** Record an attempted tool call and report whether it looks anomalous. */
  record(call: MCPToolCall): AnomalyVerdict;
  /** Forget a session's history (e.g. when it ends). */
  reset(sessionId: string): void;
}

interface SessionWindow {
  calls: number[];                  // timestamps of all calls in the window
  bySignature: Map<string, number[]>; // timestamps per identical call signature
}

export class InMemoryBehavioralMonitor implements BehavioralMonitor {
  private readonly sessions = new Map<string, SessionWindow>();

  constructor(private readonly cfg: AnomalyConfig = DEFAULT_ANOMALY_CONFIG) {}

  record(call: MCPToolCall): AnomalyVerdict {
    const sessionId = call.sessionId ?? 'default';
    const now = Date.now();
    const cutoff = now - this.cfg.windowMs;

    // Evict sessions whose entire window has expired, so a long-running engine
    // doesn't accumulate one dead SessionWindow per sessionId forever.
    // O(active sessions) per call — negligible for the local single-engine tier;
    // the Redis-backed monitor would lean on key TTLs instead.
    this.evictIdle(cutoff);

    const win: SessionWindow = this.sessions.get(sessionId) ?? { calls: [], bySignature: new Map() };
    this.sessions.set(sessionId, win);

    // total rate
    win.calls.push(now);
    win.calls = prune(win.calls, cutoff);

    // per-signature repetition
    const sig = signature(call);
    const sigTimes = prune(win.bySignature.get(sig) ?? [], cutoff);
    sigTimes.push(now);
    win.bySignature.set(sig, sigTimes);
    this.sweepSignatures(win, cutoff);

    const rate = win.calls.length;
    const repeat = sigTimes.length;
    const { maxRate, maxRepeat, hardMultiplier } = this.cfg;
    const secs = Math.round(this.cfg.windowMs / 1000);

    if (rate > maxRate * hardMultiplier) {
      return { severity: 'block', reason: `Runaway agent: ${rate} tool calls in ${secs}s (hard ceiling ${maxRate * hardMultiplier}). Execution cut off.` };
    }
    if (repeat > maxRepeat * hardMultiplier) {
      return { severity: 'block', reason: `Stuck loop: identical call repeated ${repeat}× in ${secs}s (hard ceiling ${maxRepeat * hardMultiplier}). Execution cut off.` };
    }
    if (rate > maxRate) {
      return { severity: 'review', reason: `High activity: ${rate} tool calls in ${secs}s (limit ${maxRate}). Paused for review.` };
    }
    if (repeat > maxRepeat) {
      return { severity: 'review', reason: `Possible loop: identical call repeated ${repeat}× in ${secs}s (limit ${maxRepeat}). Paused for review.` };
    }
    return OK;
  }

  reset(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  /**
   * Drop any session whose most recent call is older than the window.
   * `calls` is append-only in timestamp order, so the last element is the
   * newest; if even that has expired the whole window is dead.
   */
  private evictIdle(cutoff: number): void {
    for (const [sid, win] of this.sessions) {
      const last = win.calls[win.calls.length - 1];
      if (last === undefined || last < cutoff) this.sessions.delete(sid);
    }
  }

  /** Drop signatures whose timestamps have all expired, so the map can't grow forever. */
  private sweepSignatures(win: SessionWindow, cutoff: number): void {
    for (const [sig, times] of win.bySignature) {
      const kept = prune(times, cutoff);
      if (kept.length === 0) win.bySignature.delete(sig);
      else win.bySignature.set(sig, kept);
    }
  }
}

function prune(times: number[], cutoff: number): number[] {
  return times.filter((t) => t >= cutoff);
}

function signature(call: MCPToolCall): string {
  const i = call.input ?? {};
  const detail = (i['command'] ?? i['file_path'] ?? i['path'] ?? i['url'] ?? '') as unknown;
  return `${call.tool}::${typeof detail === 'string' ? detail : JSON.stringify(i)}`;
}

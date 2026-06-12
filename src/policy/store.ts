/**
 * PendingStore — Ports & Adapters.
 *
 * The store lives ONLY inside the long-running Engine process. The hook is a dumb
 * client holding an open HTTP request; the open socket IS the synchronous hold.
 *
 * `registerContext` returns a Promise that stays unresolved until exactly one of:
 *   • a human decision arrives via the dashboard  → `resolveContext`
 *   • the TTL elapses                              → fail-closed BLOCK
 *   • the client disconnects                       → `cleanup` (fail-closed BLOCK)
 * In every path the entry (and its timer) is removed, so nothing leaks.
 */
import { EventEmitter } from 'node:events';
import type { FinalAction, PipelineResult, SecurityViolation } from '../contract/types.js';

export interface IPendingStore {
  /** Hold a request until a human acts, the TTL fires, or the client disconnects. */
  registerContext(violation: SecurityViolation, ttlMs: number): Promise<PipelineResult>;
  /** Release a held request with a human decision. No-op if already resolved. */
  resolveContext(violationId: string, action: FinalAction): Promise<void>;
  /** Discard a held request because the client went away. No-op if already resolved. */
  cleanup(violationId: string): Promise<void>;
  /** Snapshot of currently-held requests (e.g. to hydrate a freshly-connected dashboard). */
  pending(): SecurityViolation[];
}

interface Entry {
  violation: SecurityViolation;
  resolve: (result: PipelineResult) => void;
  timer: NodeJS.Timeout;
}

/**
 * Emits:
 *   'registered' (violation)                 — a new request is now pending
 *   'resolved'   (violationId, action)        — a request left the pending set
 */
export class InMemoryPendingStore extends EventEmitter implements IPendingStore {
  private readonly entries = new Map<string, Entry>();

  registerContext(violation: SecurityViolation, ttlMs: number): Promise<PipelineResult> {
    return new Promise<PipelineResult>((resolve) => {
      const timer = setTimeout(() => {
        if (!this.entries.delete(violation.id)) return;
        this.emit('resolved', violation.id, 'BLOCK' satisfies FinalAction);
        resolve({
          action: 'BLOCK',
          reason: `Cerberus: approval timed out after ${ttlMs}ms — fail-closed deny.`,
          violationId: violation.id,
        });
      }, ttlMs);
      timer.unref?.(); // never keep the event loop alive just for a pending hold

      this.entries.set(violation.id, { violation, resolve, timer });
      this.emit('registered', violation);
    });
  }

  async resolveContext(violationId: string, action: FinalAction): Promise<void> {
    const entry = this.entries.get(violationId);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.entries.delete(violationId);
    this.emit('resolved', violationId, action);
    entry.resolve({
      action,
      reason: action === 'ALLOW' ? 'Cerberus: approved by human.' : 'Cerberus: denied by human.',
      violationId,
    });
  }

  async cleanup(violationId: string): Promise<void> {
    const entry = this.entries.get(violationId);
    if (!entry) return;
    clearTimeout(entry.timer);
    this.entries.delete(violationId);
    this.emit('resolved', violationId, 'BLOCK' satisfies FinalAction);
    // Release the (now-orphaned) awaiter fail-closed; the client already left, so
    // nobody reads this, but resolving prevents a dangling promise.
    entry.resolve({
      action: 'BLOCK',
      reason: 'Cerberus: client disconnected before approval — context cleaned up (fail-closed).',
      violationId,
    });
  }

  pending(): SecurityViolation[] {
    return [...this.entries.values()].map((e) => e.violation);
  }
}

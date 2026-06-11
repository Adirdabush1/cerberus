/**
 * Audit-entry validation (M4-B step 1 — event-system hardening).
 *
 * The audit log is the single source of truth (D22) and the investigation UI is a pure projection
 * over it — so a malformed line corrupts everything downstream. This is the runtime gate that keeps
 * the log clean: a closed event enum, the per-event-kind required fields, and the invariant that
 * every record carries `sessionId` + `ts` + `reason`. It NEVER throws (auditing must not break
 * enforcement); the caller drops + warns on a non-empty problem list.
 */
import type { AuditEntry, AuditEvent } from '../contract/types.js';

/** The closed set of valid event kinds — the single runtime source mirroring the `AuditEvent` union. */
export const AUDIT_EVENTS: ReadonlySet<AuditEvent> = new Set<AuditEvent>([
  'decision',
  'hitl-opened',
  'hitl-resolved',
  'session-started',
  'session-ended',
  'taint-loaded',
  'injection-detected',
  'tool-failed',
]);

/** Events that describe a specific intercepted tool call, and so MUST carry a requestId (D24). */
const NEEDS_REQUEST_ID: ReadonlySet<AuditEvent> = new Set<AuditEvent>(['decision', 'hitl-opened', 'hitl-resolved']);
/** Events that carry a final verdict, and so MUST carry an ALLOW/BLOCK action. */
const NEEDS_ACTION: ReadonlySet<AuditEvent> = new Set<AuditEvent>(['decision', 'hitl-resolved']);
const RESOLUTIONS = new Set(['approved', 'rejected', 'expired']);

/**
 * Returns the list of problems with an entry; empty ⇒ well-formed. Pure and total — safe to call on
 * arbitrary input (an entry that arrived over the wire), so it guards against `any`-typed junk too.
 */
export function validateAuditEntry(e: AuditEntry): string[] {
  const p: string[] = [];
  if (!e || typeof e !== 'object') return ['entry is not an object'];

  if (!AUDIT_EVENTS.has(e.event)) p.push(`unknown event "${String(e.event)}"`);
  if (typeof e.ts !== 'number' || !Number.isFinite(e.ts) || e.ts <= 0) p.push('missing/invalid ts');
  if (typeof e.sessionId !== 'string' || e.sessionId.length === 0) p.push('missing sessionId');
  if (typeof e.reason !== 'string' || e.reason.length === 0) p.push('missing reason');

  if (NEEDS_REQUEST_ID.has(e.event) && (typeof e.requestId !== 'string' || e.requestId.length === 0)) {
    p.push(`${e.event} requires requestId`);
  }
  if (NEEDS_ACTION.has(e.event) && e.action !== 'ALLOW' && e.action !== 'BLOCK') {
    p.push(`${e.event} requires action ALLOW|BLOCK (got ${String(e.action)})`);
  }
  if (e.event === 'hitl-resolved') {
    if (!e.resolution || !RESOLUTIONS.has(e.resolution)) p.push('hitl-resolved requires resolution approved|rejected|expired');
    if (typeof e.latencyMs !== 'number' || e.latencyMs < 0) p.push('hitl-resolved requires a non-negative latencyMs');
  }
  return p;
}

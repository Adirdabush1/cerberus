/**
 * Audit log — append-only JSONL. Every decision (allow/block, auto or via HITL)
 * is recorded. This is the compliance backbone; the paid tier adds retention.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import type { AuditEntry } from '../contract/types.js';
import { validateAuditEntry } from './validate.js';

export class AuditLog {
  constructor(private readonly file: string) {
    mkdirSync(dirname(file), { recursive: true });
  }

  /**
   * Append one event. The log is the single source of truth (D22), so a malformed entry is REJECTED
   * (logged to stderr, not written) rather than corrupting the projection downstream. Returns whether
   * the entry was actually persisted, so callers can avoid broadcasting a dropped event.
   */
  record(entry: AuditEntry): boolean {
    const problems = validateAuditEntry(entry);
    if (problems.length > 0) {
      process.stderr.write(`AgentGuard: dropping malformed audit entry [${String(entry?.event)}]: ${problems.join('; ')}\n`);
      return false;
    }
    try {
      appendFileSync(this.file, JSON.stringify(entry) + '\n');
      return true;
    } catch {
      // auditing must never break enforcement; surface but do not throw
      process.stderr.write(`AgentGuard: failed to write audit entry\n`);
      return false;
    }
  }

  /**
   * Replay the whole log (the investigation history hydrates from here — D22/D25). Tolerant of a
   * torn final line (a crash mid-append) and of any non-JSON line, which is skipped rather than thrown.
   */
  read(): AuditEntry[] {
    if (!existsSync(this.file)) return [];
    const out: AuditEntry[] = [];
    for (const line of readFileSync(this.file, 'utf8').split('\n')) {
      if (!line) continue;
      try {
        out.push(JSON.parse(line) as AuditEntry);
      } catch {
        /* skip a torn/partial line */
      }
    }
    return out;
  }
}

/**
 * Audit log — append-only JSONL. Every decision (allow/block, auto or via HITL)
 * is recorded. This is the compliance backbone; the paid tier adds retention.
 */
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { AuditEntry } from '../contract/types.js';

export class AuditLog {
  constructor(private readonly file: string) {
    mkdirSync(dirname(file), { recursive: true });
  }

  record(entry: AuditEntry): void {
    try {
      appendFileSync(this.file, JSON.stringify(entry) + '\n');
    } catch {
      // auditing must never break enforcement; surface but do not throw
      process.stderr.write(`AgentGuard: failed to write audit entry\n`);
    }
  }
}

#!/usr/bin/env node
// AgentGuard spike — the "admin" side. Lists pending HITL requests and approves/denies.
// Usage:
//   node approve.mjs                 # list pending
//   node approve.mjs <id> approve    # approve a request
//   node approve.mjs <id> deny       # deny a request
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const PENDING = join(dirname(fileURLToPath(import.meta.url)), 'pending');
const [, , id, action] = process.argv;

if (!id) {
  const reqs = readdirSync(PENDING).filter(f => f.endsWith('.json'));
  if (!reqs.length) { console.log('No pending requests.'); process.exit(0); }
  for (const f of reqs) {
    const r = JSON.parse(readFileSync(join(PENDING, f), 'utf8'));
    console.log(`[${r.id}] ${r.tool}  ${JSON.stringify(r.input)}\n   ${r.reason}\n`);
  }
  console.log('Approve with:  node approve.mjs <id> approve');
  process.exit(0);
}

const verb = (action ?? 'approve').toLowerCase();
writeFileSync(join(PENDING, `${id}.decision`), verb);
console.log(`Wrote decision for ${id}: ${verb}`);

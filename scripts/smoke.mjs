// End-to-end smoke test for the Cerberus Engine. Assumes an engine is running
// on AG_ENGINE_PORT (default 9000) with a short AG_TTL_MS so the timeout path is fast.
import { request } from 'node:http';

const PORT = Number(process.env.AG_ENGINE_PORT ?? 9000);
let pass = 0, fail = 0;

function http(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null;
    const req = request({ host: '127.0.0.1', port: PORT, path, method,
      headers: payload ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } : {} },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve({ status: res.statusCode, json: d ? JSON.parse(d) : null })); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
    return req;
  });
}
const intercept = (call) => http('POST', '/intercept', call);
const sleep = (ms) => new Promise(r => setTimeout(r, ms));
function check(name, cond, detail) {
  if (cond) { pass++; console.log(`  ✅ ${name}`); }
  else { fail++; console.log(`  ❌ ${name} — ${detail}`); }
}

console.log('Cerberus engine smoke test\n');

// A) auto-allow
let r = await intercept({ tool: 'Bash', input: { command: 'ls -la' } });
check('ALLOW: Bash `ls -la`', r.json.action === 'ALLOW', JSON.stringify(r.json));

// B) auto-block rm -rf
r = await intercept({ tool: 'Bash', input: { command: 'rm -rf src' } });
check('BLOCK: Bash `rm -rf src`', r.json.action === 'BLOCK', JSON.stringify(r.json));

// C) auto-block .env read
r = await intercept({ tool: 'Read', input: { file_path: '/proj/.env' } });
check('BLOCK: Read `.env`', r.json.action === 'BLOCK', JSON.stringify(r.json));

// D) unknown tool -> fail-closed HITL (resolve via /decision to keep test fast)
{
  const p = intercept({ tool: 'mcp__weird__doThing', input: {} });
  await sleep(100);
  const pend = (await http('GET', '/pending')).json.pending;
  const v = pend.find(x => x.toolCall.tool === 'mcp__weird__doThing');
  check('Fail-Closed: unknown tool held for review', !!v && v.category === 'UNKNOWN', JSON.stringify(pend));
  if (v) await http('POST', '/decision', { type: 'decision', violationId: v.id, action: 'BLOCK' });
  const res = await p;
  check('Fail-Closed: unknown tool denied after review', res.json.action === 'BLOCK', JSON.stringify(res.json));
}

// E) HITL approve -> ALLOW
{
  const p = intercept({ tool: 'Bash', input: { command: 'git push origin main' }, sessionId: 's1' });
  await sleep(100);
  const pend = (await http('GET', '/pending')).json.pending;
  const v = pend.find(x => x.toolCall.input.command === 'git push origin main');
  check('HITL: git push is held', !!v, JSON.stringify(pend));
  await http('POST', '/decision', { type: 'decision', violationId: v.id, action: 'ALLOW' });
  const res = await p;
  check('HITL: approve -> ALLOW (socket released)', res.json.action === 'ALLOW', JSON.stringify(res.json));
}

// F) HITL timeout -> fail-closed BLOCK
{
  const t0 = Date.now();
  r = await intercept({ tool: 'Write', input: { file_path: '/proj/x.ts' } });
  const waited = Date.now() - t0;
  check('HITL: timeout -> BLOCK (fail-closed)', r.json.action === 'BLOCK' && /timed out/.test(r.json.reason), JSON.stringify(r.json));
  check('HITL: timeout respected TTL window', waited >= 1000, `waited ${waited}ms`);
}

// G) client disconnect -> cleanup (no leak)
{
  const req = request({ host: '127.0.0.1', port: PORT, path: '/intercept', method: 'POST',
    headers: { 'content-type': 'application/json' } });
  req.on('error', () => {});
  req.write(JSON.stringify({ tool: 'Write', input: { file_path: '/proj/y.ts' } }));
  req.end();
  await sleep(150);
  let pend = (await http('GET', '/pending')).json.pending;
  check('Disconnect: request is pending before abort', pend.length >= 1, `pending=${pend.length}`);
  req.destroy();
  await sleep(200);
  pend = (await http('GET', '/pending')).json.pending;
  check('Disconnect: cleanup removed the orphaned hold', pend.length === 0, `pending=${pend.length}`);
}

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);

// Verifies the exact WebSocket path the React dashboard uses.
import { WebSocket } from 'ws';
import { request } from 'node:http';

const PORT = Number(process.env.AG_ENGINE_PORT ?? 9000);
const got = { hello: false, violation: false, resolved: false, audit: false };
let interceptResult = null;

function intercept(call) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(call);
    const req = request({ host: '127.0.0.1', port: PORT, path: '/intercept', method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload) } },
      (res) => { let d = ''; res.on('data', c => d += c); res.on('end', () => resolve(JSON.parse(d))); });
    req.on('error', reject); req.end(payload);
  });
}

const ws = new WebSocket(`ws://127.0.0.1:${PORT}/ws`);

ws.on('open', () => {
  const p = intercept({ tool: 'Bash', input: { command: 'git push origin main' }, sessionId: 'ws-test' });
  p.then((r) => { interceptResult = r; });
});

ws.on('message', (raw) => {
  const msg = JSON.parse(raw.toString());
  got[msg.type] = true;
  if (msg.type === 'violation') {
    ws.send(JSON.stringify({ type: 'decision', violationId: msg.violation.id, action: 'ALLOW' }));
  }
});

setTimeout(() => {
  const ok = got.hello && got.violation && got.resolved && got.audit && interceptResult?.action === 'ALLOW';
  console.log('  hello   received:', got.hello);
  console.log('  violation pushed:', got.violation);
  console.log('  resolved broadcast:', got.resolved);
  console.log('  audit broadcast:', got.audit);
  console.log('  hold released as:', interceptResult?.action);
  console.log(ok ? '\n✅ WS dashboard path verified end-to-end' : '\n❌ WS path incomplete');
  ws.close();
  process.exit(ok ? 0 : 1);
}, 1500);

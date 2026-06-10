import { useEffect, useState } from 'react';
import { useEngine } from './useEngine';
import type { AuditEntry, MCPToolCall, SecurityViolation, ToolCategory } from './contract';

const CATEGORY_STYLE: Record<ToolCategory, string> = {
  READ: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
  WRITE: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  EXECUTE: 'bg-fuchsia-500/15 text-fuchsia-300 ring-fuchsia-500/30',
  EGRESS: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  UNKNOWN: 'bg-red-500/15 text-red-300 ring-red-500/30',
};

/** Turn a raw tool call into a human-readable "what the agent wants to do". */
function describe(call: MCPToolCall): { title: string; body: string | null } {
  const i = call.input ?? {};
  if (typeof i['command'] === 'string') return { title: `$ ${i['command']}`, body: null };
  const path = (i['file_path'] ?? i['path']) as string | undefined;
  if (typeof path === 'string') {
    const content = (i['content'] ?? i['new_string'] ?? '') as unknown;
    return { title: `${call.tool} → ${path}`, body: typeof content === 'string' && content ? content : null };
  }
  if (typeof i['url'] === 'string') return { title: `${call.tool} → ${i['url']}`, body: null };
  const keys = Object.keys(i);
  return { title: call.tool, body: keys.length ? JSON.stringify(i, null, 2) : null };
}

function ago(ts: number, now: number): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  return `${Math.floor(s / 60)}m ${s % 60}s ago`;
}

function ViolationCard({
  v,
  now,
  onDecide,
}: {
  v: SecurityViolation;
  now: number;
  onDecide: (id: string, action: 'ALLOW' | 'BLOCK') => void;
}) {
  const { title, body } = describe(v.toolCall);
  const remaining = Math.max(0, Math.round((v.createdAt + v.ttlMs - now) / 1000));
  const anomaly = v.signal === 'behavioral';
  const exfil = v.signal === 'content';
  return (
    <div
      className={`rounded-xl border bg-slate-900/80 shadow-lg shadow-black/30 overflow-hidden animate-[pulse_2s_ease-in-out_1] ${
        anomaly || exfil ? 'border-red-500/50' : 'border-amber-500/30'
      }`}
    >
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-white/5">
        <span className={`text-[11px] font-semibold px-2 py-0.5 rounded ring-1 ${CATEGORY_STYLE[v.category]}`}>
          {v.category}
        </span>
        {anomaly && (
          <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-red-500/20 text-red-300 ring-1 ring-red-500/40">
            ⚠ ANOMALY
          </span>
        )}
        {exfil && (
          <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-red-500/20 text-red-300 ring-1 ring-red-500/40">
            🛡 EXFIL RISK
          </span>
        )}
        <span className="text-xs text-slate-400">{v.toolCall.tool}</span>
        {v.risk && (
          <span className="text-[11px] font-semibold px-2 py-0.5 rounded bg-slate-700/60 text-slate-200 ring-1 ring-white/10" title={`band ${v.risk.band} · ${v.risk.version}`}>
            ⚖ {v.risk.score}
          </span>
        )}
        <span className="ml-auto text-xs tabular-nums text-amber-300/80">⏳ {remaining}s</span>
      </div>
      <div className="px-4 py-3">
        <pre className="text-sm font-mono text-amber-100 whitespace-pre-wrap break-words">{title}</pre>
        {body && (
          <pre className="mt-2 max-h-40 overflow-auto rounded-lg bg-black/40 p-3 text-xs font-mono text-slate-300 ring-1 ring-white/5">
            {body}
          </pre>
        )}
        <p className="mt-2 text-xs text-slate-400">{v.reason}</p>
      </div>
      <div className="flex gap-2 px-4 py-3 border-t border-white/5 bg-black/20">
        <button
          onClick={() => onDecide(v.id, 'ALLOW')}
          className="flex-1 rounded-lg bg-emerald-500/90 hover:bg-emerald-400 text-emerald-950 font-semibold text-sm py-2 transition"
        >
          ✓ Approve
        </button>
        <button
          onClick={() => onDecide(v.id, 'BLOCK')}
          className="flex-1 rounded-lg bg-red-500/90 hover:bg-red-400 text-red-950 font-semibold text-sm py-2 transition"
        >
          ✕ Deny
        </button>
      </div>
    </div>
  );
}

function AuditRow({ e, now }: { e: AuditEntry; now: number }) {
  const allow = e.action === 'ALLOW';
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 text-xs border-b border-white/5">
      <span className={`font-mono font-semibold ${allow ? 'text-emerald-400' : 'text-red-400'}`}>
        {allow ? 'ALLOW' : 'BLOCK'}
      </span>
      {e.viaHitl && <span className="text-[10px] px-1 rounded bg-amber-500/15 text-amber-300">HITL</span>}
      {e.signal === 'behavioral' && (
        <span className="text-[10px] px-1 rounded bg-red-500/15 text-red-300">ANOMALY</span>
      )}
      {e.signal === 'content' && (
        <span className="text-[10px] px-1 rounded bg-red-500/15 text-red-300">EXFIL</span>
      )}
      {e.risk?.band === 'AUDIT' && (
        <span className="text-[10px] px-1 rounded bg-amber-500/15 text-amber-300">AUDIT</span>
      )}
      {e.risk && e.risk.score > 0 && (
        <span className="text-[10px] tabular-nums text-slate-500" title={`band ${e.risk.band} · ${e.risk.version}`}>⚖{e.risk.score}</span>
      )}
      <span className="text-slate-300 truncate">{e.tool}</span>
      <span className="text-slate-500 truncate flex-1">{e.ruleId ?? e.reason}</span>
      <span className="text-slate-600 tabular-nums shrink-0">{ago(e.ts, now)}</span>
    </div>
  );
}

export default function App() {
  const { connected, pending, audit, decide } = useEngine();
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="flex items-center gap-3 px-6 py-4 border-b border-white/10 bg-slate-900/50 backdrop-blur sticky top-0 z-10">
        <div className="text-lg font-bold tracking-tight">
          🛡️ Agent<span className="text-emerald-400">Guard</span>
        </div>
        <span className="text-xs text-slate-500">Agent Permission Gateway</span>
        <div className="ml-auto flex items-center gap-2 text-xs">
          <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400' : 'bg-red-500 animate-pulse'}`} />
          <span className="text-slate-400">{connected ? 'Engine connected' : 'Engine offline'}</span>
        </div>
      </header>

      <main className="grid grid-cols-1 lg:grid-cols-[1fr_24rem] gap-6 p-6 max-w-7xl mx-auto">
        {/* Action Center */}
        <section>
          <div className="flex items-center gap-2 mb-3">
            <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Action Center</h2>
            {pending.length > 0 && (
              <span className="text-[11px] px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-semibold animate-pulse">
                {pending.length} awaiting approval
              </span>
            )}
          </div>
          {pending.length === 0 ? (
            <div className="rounded-xl border border-dashed border-white/10 p-10 text-center text-slate-500 text-sm">
              No actions awaiting approval. The agent is running freely within policy.
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2">
              {pending.map((v) => (
                <ViolationCard key={v.id} v={v} now={now} onDecide={decide} />
              ))}
            </div>
          )}
        </section>

        {/* Live Stream */}
        <section>
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-3">Live Stream</h2>
          <div className="rounded-xl border border-white/10 bg-slate-900/50 overflow-hidden">
            {audit.length === 0 ? (
              <div className="p-6 text-center text-slate-600 text-sm">Decisions will stream here in real time.</div>
            ) : (
              <div className="max-h-[70vh] overflow-auto">
                {audit.map((e, idx) => (
                  <AuditRow key={`${e.ts}-${idx}`} e={e} now={now} />
                ))}
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

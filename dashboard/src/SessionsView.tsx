/**
 * Sessions / investigation view (M4-B, D26–D28). A session list (history via GET /sessions) → a
 * per-session timeline (GET /sessions/:id/timeline), live-merged with incoming WS audit events through
 * the SAME shared projector (D25) so history and live never diverge.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { AuditEntry, AuditEvent, RiskBand, SessionSummary, SignalSource, TimelineItem } from './contract';
import { fetchSessions, fetchTimeline } from './api';
import { correlateTimeline, summarizeSession } from './projector';
import { CATEGORY_STYLE, EVENT_META, ago, clockTime, describe, fmtDuration } from './format';

const BAND_STYLE: Record<RiskBand, string> = {
  ALLOW: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/30',
  AUDIT: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  HITL: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  BLOCK: 'bg-red-500/15 text-red-300 ring-red-500/30',
};

/** Stable-enough identity for an event, to dedup the fetched history against the live WS buffer. */
function eventKey(e: AuditEntry): string {
  return `${e.ts}|${e.event}|${e.requestId ?? ''}|${e.tool ?? ''}|${e.action ?? ''}`;
}

export function SessionsView({ audit, now, initialSession }: { audit: AuditEntry[]; now: number; initialSession?: string }) {
  const [sessions, setSessions] = useState<SessionSummary[]>([]);
  const [selected, setSelected] = useState<string | null>(initialSession ?? null);
  const [history, setHistory] = useState<AuditEntry[]>([]);
  const [listQuery, setListQuery] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(() => {
    fetchSessions()
      .then((s) => { setSessions(s); setError(null); })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  // Initial load + throttled re-fetch as new audit events stream in (so the list stays current).
  useEffect(() => { refresh(); }, [refresh]);
  const lastFetch = useRef(0);
  useEffect(() => {
    const since = Date.now() - lastFetch.current;
    if (since >= 1500) { lastFetch.current = Date.now(); refresh(); return; }
    const id = setTimeout(() => { lastFetch.current = Date.now(); refresh(); }, 1500 - since);
    return () => clearTimeout(id);
  }, [audit.length, refresh]);

  // Open a session → fetch its full timeline from history.
  useEffect(() => {
    if (!selected) { setHistory([]); return; }
    let live = true;
    fetchTimeline(selected).then((t) => { if (live) setHistory(t.events); }).catch(() => { if (live) setHistory([]); });
    return () => { live = false; };
  }, [selected]);

  // Live-merge: combine fetched history with live-buffer events for this session, dedup, re-project.
  const timeline = useMemo(() => {
    if (!selected) return null;
    const liveForSession = audit.filter((e) => (e.sessionId ?? 'default') === selected);
    const seen = new Set<string>();
    const events: AuditEntry[] = [];
    for (const e of [...history, ...liveForSession]) {
      const k = eventKey(e);
      if (!seen.has(k)) { seen.add(k); events.push(e); }
    }
    events.sort((a, b) => a.ts - b.ts);
    return { events, items: correlateTimeline(events), summary: summarizeSession(selected, events) };
  }, [selected, history, audit]);

  const filteredSessions = useMemo(() => {
    const q = listQuery.trim().toLowerCase();
    return q ? sessions.filter((s) => s.sessionId.toLowerCase().includes(q)) : sessions;
  }, [sessions, listQuery]);

  return (
    <div className="grid grid-cols-1 lg:grid-cols-[22rem_1fr] gap-6">
      <aside>
        <div className="flex items-center gap-2 mb-3">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-400">Sessions</h2>
          <span className="text-[11px] text-slate-500">{sessions.length}</span>
          <button onClick={refresh} className="ml-auto text-xs text-slate-400 hover:text-slate-200" title="Refresh">↻</button>
        </div>
        <input
          value={listQuery}
          onChange={(e) => setListQuery(e.target.value)}
          placeholder="Filter by session id…"
          className="w-full mb-3 rounded-lg bg-slate-900/70 border border-white/10 px-3 py-1.5 text-sm text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
        />
        {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300">Couldn’t load sessions: {error}</div>}
        {loading ? (
          <div className="text-sm text-slate-600 p-4">Loading…</div>
        ) : filteredSessions.length === 0 ? (
          <div className="rounded-xl border border-dashed border-white/10 p-6 text-center text-slate-600 text-sm">No sessions yet.</div>
        ) : (
          <div className="space-y-2">
            {filteredSessions.map((s) => (
              <SessionRow key={s.sessionId} s={s} now={now} active={s.sessionId === selected} onClick={() => setSelected(s.sessionId)} />
            ))}
          </div>
        )}
      </aside>

      <section>
        {!selected ? (
          <div className="rounded-xl border border-dashed border-white/10 p-10 text-center text-slate-500 text-sm">
            Select a session to inspect its timeline.
          </div>
        ) : timeline ? (
          <TimelineDetail sessionId={selected} events={timeline.events} items={timeline.items} summary={timeline.summary} now={now} />
        ) : null}
      </section>
    </div>
  );
}

function SessionRow({ s, now, active, onClick }: { s: SessionSummary; now: number; active: boolean; onClick: () => void }) {
  const live = s.endedAt === undefined;
  return (
    <button
      onClick={onClick}
      className={`w-full text-left rounded-xl border p-3 transition ${
        active ? 'border-emerald-500/50 bg-emerald-500/5' : 'border-white/10 bg-slate-900/50 hover:border-white/20'
      }`}
    >
      <div className="flex items-center gap-2">
        <span className="font-mono text-xs text-slate-200 truncate">{s.sessionId}</span>
        {live && <span className="text-[10px] px-1.5 rounded-full bg-emerald-500/15 text-emerald-300 ring-1 ring-emerald-500/30">live</span>}
        <span className={`ml-auto text-[10px] font-semibold px-1.5 py-0.5 rounded ring-1 ${BAND_STYLE[s.peakBand]}`}>{s.peakBand}</span>
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-slate-400">
        <span>{s.verdicts} verdict{s.verdicts === 1 ? '' : 's'}</span>
        {s.blocked > 0 && <span className="text-red-400">{s.blocked} blocked</span>}
        {s.held > 0 && <span className="text-amber-400">{s.held} held</span>}
        {s.taintLoaded > 0 && <span className="text-orange-400">{s.taintLoaded} secret</span>}
        {s.injections > 0 && <span className="text-red-400">{s.injections} injection</span>}
        {s.toolFailures > 0 && <span className="text-rose-400">{s.toolFailures} failed</span>}
      </div>
      <div className="mt-1 text-[10px] text-slate-600">last activity {ago(s.lastTs, now)}</div>
    </button>
  );
}

const ALL_EVENTS = Object.keys(EVENT_META) as AuditEvent[];

function entryMatches(
  e: AuditEntry,
  f: { eventFilter: Set<AuditEvent>; signalFilter: Set<SignalSource>; bandFilter: Set<RiskBand>; q: string },
): boolean {
  if (f.eventFilter.size && !f.eventFilter.has(e.event)) return false;
  if (f.signalFilter.size && !(e.signal && f.signalFilter.has(e.signal))) return false;
  if (f.bandFilter.size && !(e.risk && f.bandFilter.has(e.risk.band))) return false;
  if (f.q) {
    const hay = `${e.tool ?? ''} ${e.reason} ${JSON.stringify(e.input ?? '')}`.toLowerCase();
    if (!hay.includes(f.q)) return false;
  }
  return true;
}

function TimelineDetail({ sessionId, events, items, summary, now }: { sessionId: string; events: AuditEntry[]; items: TimelineItem[]; summary: SessionSummary; now: number }) {
  const [eventFilter, setEventFilter] = useState<Set<AuditEvent>>(new Set());
  const [signalFilter, setSignalFilter] = useState<Set<SignalSource>>(new Set());
  const [bandFilter, setBandFilter] = useState<Set<RiskBand>>(new Set());
  const [text, setText] = useState('');
  const [replay, setReplay] = useState(false);

  // Only offer chips for values that actually occur in this timeline (keeps the bar uncluttered).
  const present = useMemo(() => {
    const ev = new Set<AuditEvent>(), sig = new Set<SignalSource>(), bd = new Set<RiskBand>();
    for (const e of events) { ev.add(e.event); if (e.signal) sig.add(e.signal); if (e.risk) bd.add(e.risk.band); }
    return { ev: ALL_EVENTS.filter((x) => ev.has(x)), sig: [...sig], bd: [...bd] as RiskBand[] };
  }, [events]);

  const shown = useMemo(() => {
    const f = { eventFilter, signalFilter, bandFilter, q: text.trim().toLowerCase() };
    // A correlated item passes if EITHER of its events (the open or its resolution) matches.
    return items.filter((it) => entryMatches(it.primary, f) || (it.resolvedBy != null && entryMatches(it.resolvedBy, f)));
  }, [items, eventFilter, signalFilter, bandFilter, text]);

  const dur = summary.lastTs - summary.firstTs;

  return (
    <div>
      <div className="rounded-xl border border-white/10 bg-slate-900/50 p-4 mb-4">
        <div className="flex items-center gap-2 flex-wrap">
          <h2 className="font-mono text-sm text-slate-100 truncate">{sessionId}</h2>
          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ring-1 ${BAND_STYLE[summary.peakBand]}`}>peak {summary.peakBand} · {summary.peakRiskScore}</span>
          <span className="ml-auto text-[11px] text-slate-500">{summary.endedAt ? `ended ${ago(summary.endedAt, now)}` : 'active'} · spanned {fmtDuration(dur)}</span>
        </div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-400">
          <span>{summary.verdicts} verdicts</span>
          <span className="text-emerald-400">{summary.allowed} allowed</span>
          <span className="text-red-400">{summary.blocked} blocked</span>
          <span className="text-amber-400">{summary.held} held</span>
          {summary.taintLoaded > 0 && <span className="text-orange-400">{summary.taintLoaded} secrets loaded</span>}
          {summary.injections > 0 && <span className="text-red-400">{summary.injections} injections</span>}
          {summary.toolFailures > 0 && <span className="text-rose-400">{summary.toolFailures} tool failures</span>}
        </div>
        {summary.drivers.length > 0 && (
          <div className="mt-2.5 text-xs">
            <span className="text-slate-500">why this session is risky: </span>
            <span className="text-slate-200">{summary.drivers.join(' + ')}</span>
          </div>
        )}
      </div>

      <div className="flex items-center gap-2 mb-3">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">{replay ? 'Replay' : 'Timeline'}</h3>
        <button
          onClick={() => setReplay((r) => !r)}
          className={`ml-auto text-xs font-semibold px-2.5 py-1 rounded-lg ring-1 transition ${
            replay ? 'bg-emerald-500/20 text-emerald-200 ring-emerald-500/40' : 'bg-slate-800/60 text-slate-300 ring-white/10 hover:text-slate-100'
          }`}
        >
          {replay ? '✕ Exit replay' : '▶ Replay'}
        </button>
      </div>

      {replay ? (
        <Replay sessionId={sessionId} items={items} />
      ) : (
        <>
          <FilterBar
            present={present}
            eventFilter={eventFilter} setEventFilter={setEventFilter}
            signalFilter={signalFilter} setSignalFilter={setSignalFilter}
            bandFilter={bandFilter} setBandFilter={setBandFilter}
            text={text} setText={setText}
          />
          <div className="mt-4 relative pl-6">
            <div className="absolute left-[7px] top-1 bottom-1 w-px bg-white/10" aria-hidden />
            {shown.length === 0 ? (
              <div className="text-sm text-slate-600 py-6">No events match the filters.</div>
            ) : (
              shown.map((it, i) => <TimelineRow key={`${eventKey(it.primary)}-${i}`} item={it} />)
            )}
          </div>
        </>
      )}
    </div>
  );
}

const SPEEDS = [0.5, 1, 2, 4];
const BASE_MS = 900; // cadence at 1× — divided by speed

/** The raw events covered by items[0..cursor] (a held item contributes both its open and resolve). */
function eventsUpTo(items: TimelineItem[], cursor: number): AuditEntry[] {
  const out: AuditEntry[] = [];
  for (let i = 0; i <= cursor && i < items.length; i++) {
    const it = items[i];
    if (!it) continue;
    out.push(it.primary);
    if (it.resolvedBy) out.push(it.resolvedBy);
  }
  return out;
}

/** Count calls held but not yet resolved within a prefix — the "currently awaiting approval" gauge. */
function heldOpenCount(events: AuditEntry[]): number {
  const open = new Set<string>();
  for (const e of events) {
    if (e.event === 'hitl-opened' && e.requestId) open.add(e.requestId);
    if (e.event === 'hitl-resolved' && e.requestId) open.delete(e.requestId);
  }
  return open.size;
}

function Replay({ sessionId, items }: { sessionId: string; items: TimelineItem[] }) {
  const [cursor, setCursor] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);
  const last = Math.max(0, items.length - 1);

  // Event-paced auto-advance (D32): one item per tick; stop at the end.
  useEffect(() => {
    if (!playing) return;
    if (cursor >= last) { setPlaying(false); return; }
    const id = setTimeout(() => setCursor((c) => Math.min(last, c + 1)), BASE_MS / speed);
    return () => clearTimeout(id);
  }, [playing, cursor, speed, last]);

  const prefix = useMemo(() => eventsUpTo(items, cursor), [items, cursor]);
  const state = useMemo(() => summarizeSession(sessionId, prefix), [sessionId, prefix]);
  const held = useMemo(() => heldOpenCount(prefix), [prefix]);
  const scores = useMemo(() => items.map((it) => (it.resolvedBy?.risk ?? it.primary.risk)?.score ?? 0), [items]);
  const maxScore = Math.max(1, ...scores);

  const play = () => { if (cursor >= last) setCursor(0); setPlaying(true); };
  const current = items[cursor];
  const currentLabel = current ? EVENT_META[current.resolvedBy ? 'hitl-resolved' : current.primary.event].label : '';

  return (
    <div>
      {/* transport */}
      <div className="rounded-xl border border-white/10 bg-slate-900/50 p-3 flex items-center gap-2 flex-wrap">
        <button onClick={() => setCursor((c) => Math.max(0, c - 1))} className="text-slate-300 hover:text-white px-1" title="Step back">⏮</button>
        <button onClick={() => (playing ? setPlaying(false) : play())} className="rounded-lg bg-emerald-500/90 hover:bg-emerald-400 text-emerald-950 font-bold text-sm w-9 h-7" title={playing ? 'Pause' : 'Play'}>
          {playing ? '⏸' : '⏵'}
        </button>
        <button onClick={() => setCursor((c) => Math.min(last, c + 1))} className="text-slate-300 hover:text-white px-1" title="Step forward">⏭</button>
        <input
          type="range" min={0} max={last} value={cursor}
          onChange={(e) => { setPlaying(false); setCursor(Number(e.target.value)); }}
          className="flex-1 min-w-[8rem] accent-emerald-400"
        />
        <span className="text-[11px] tabular-nums text-slate-400 shrink-0">{cursor + 1}/{items.length}</span>
        <div className="flex items-center gap-1 ml-1">
          {SPEEDS.map((s) => (
            <button key={s} onClick={() => setSpeed(s)} className={`text-[10px] px-1.5 py-0.5 rounded ${speed === s ? 'bg-white/15 text-slate-100' : 'text-slate-500 hover:text-slate-300'}`}>{s}×</button>
          ))}
        </div>
      </div>

      {/* cumulative state @ cursor + risk sparkline (D33) */}
      <div className="mt-3 rounded-xl border border-white/10 bg-slate-900/50 p-3">
        <div className="flex items-center gap-2 flex-wrap text-xs">
          <span className="text-slate-500">state @ {clockTime(current?.primary.ts ?? 0)} —</span>
          <span className="text-slate-300">{currentLabel}</span>
          <span className={`ml-auto text-[10px] font-semibold px-1.5 py-0.5 rounded ring-1 ${BAND_STYLE[state.peakBand]}`}>risk {state.peakBand} · {state.peakRiskScore}</span>
        </div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-400">
          <span className="text-emerald-400">{state.allowed} allowed</span>
          <span className="text-red-400">{state.blocked} blocked</span>
          <span className="text-amber-400">{held} awaiting</span>
          <span className="text-orange-400">{state.taintLoaded} secrets</span>
          <span className="text-red-400">{state.injections} injections</span>
          {state.toolFailures > 0 && <span className="text-rose-400">{state.toolFailures} failed</span>}
        </div>
        {state.drivers.length > 0 && (
          <div className="mt-1.5 text-[11px]"><span className="text-slate-500">drivers so far: </span><span className="text-slate-300">{state.drivers.join(' + ')}</span></div>
        )}
        <svg viewBox={`0 0 ${Math.max(1, last)} 24`} preserveAspectRatio="none" className="mt-2 w-full h-8 overflow-visible">
          <polyline
            points={scores.map((s, i) => `${i},${24 - (s / maxScore) * 22}`).join(' ')}
            fill="none" stroke="rgb(251 146 60 / 0.7)" strokeWidth={0.4}
          />
          <line x1={cursor} x2={cursor} y1={0} y2={24} stroke="rgb(52 211 153)" strokeWidth={0.5} />
        </svg>
      </div>

      {/* the timeline, dimming the future and ringing the current item */}
      <div className="mt-4 relative pl-6">
        <div className="absolute left-[7px] top-1 bottom-1 w-px bg-white/10" aria-hidden />
        {items.map((it, i) => (
          <div key={`${eventKey(it.primary)}-${i}`} className={`transition ${i > cursor ? 'opacity-30' : ''} ${i === cursor ? 'ring-2 ring-emerald-500/50 rounded-lg' : ''}`}>
            <TimelineRow item={it} />
          </div>
        ))}
      </div>
    </div>
  );
}

function toggle<T>(set: Set<T>, v: T): Set<T> {
  const next = new Set(set);
  next.has(v) ? next.delete(v) : next.add(v);
  return next;
}

function FilterBar(props: {
  present: { ev: AuditEvent[]; sig: SignalSource[]; bd: RiskBand[] };
  eventFilter: Set<AuditEvent>; setEventFilter: (s: Set<AuditEvent>) => void;
  signalFilter: Set<SignalSource>; setSignalFilter: (s: Set<SignalSource>) => void;
  bandFilter: Set<RiskBand>; setBandFilter: (s: Set<RiskBand>) => void;
  text: string; setText: (s: string) => void;
}) {
  const chip = (on: boolean, label: string, onClick: () => void, extra = '') => (
    <button
      key={label}
      onClick={onClick}
      className={`text-[11px] px-2 py-0.5 rounded-full ring-1 transition ${
        on ? `bg-emerald-500/20 text-emerald-200 ring-emerald-500/40 ${extra}` : 'bg-slate-800/60 text-slate-400 ring-white/10 hover:text-slate-200'
      }`}
    >
      {label}
    </button>
  );
  return (
    <div className="flex flex-wrap items-center gap-1.5">
      {props.present.ev.map((ev) => chip(props.eventFilter.has(ev), `${EVENT_META[ev].icon} ${EVENT_META[ev].label}`, () => props.setEventFilter(toggle(props.eventFilter, ev))))}
      {props.present.sig.length > 0 && <span className="mx-1 h-3 w-px bg-white/10" />}
      {props.present.sig.map((s) => chip(props.signalFilter.has(s), s, () => props.setSignalFilter(toggle(props.signalFilter, s))))}
      {props.present.bd.length > 0 && <span className="mx-1 h-3 w-px bg-white/10" />}
      {props.present.bd.map((b) => chip(props.bandFilter.has(b), b, () => props.setBandFilter(toggle(props.bandFilter, b))))}
      <input
        value={props.text}
        onChange={(e) => props.setText(e.target.value)}
        placeholder="search…"
        className="ml-auto rounded-lg bg-slate-900/70 border border-white/10 px-2.5 py-1 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:ring-1 focus:ring-emerald-500/40"
      />
    </div>
  );
}

function TimelineRow({ item }: { item: TimelineItem }) {
  const [open, setOpen] = useState(false);
  const e = item.primary;
  const r = item.resolvedBy; // present ⇒ this is a held call folded with its verdict
  const held = !!r;
  // For a held item, the row's identity is "held" but the verdict/risk come from the resolution.
  const meta = EVENT_META[held ? 'hitl-resolved' : e.event];
  const action = r?.action ?? e.action;
  const risk = r?.risk ?? e.risk;
  const verdictReason = r?.reason;
  const resolution = r?.resolution;
  const latencyMs = r?.latencyMs;
  const expandable = !!risk?.factors?.length || !!e.input;
  const diff = e.input ? describe({ tool: e.tool ?? '', input: e.input }) : null;
  const allow = action === 'ALLOW';

  return (
    <div className="relative mb-2.5">
      <span className={`absolute -left-[18px] top-2 h-2.5 w-2.5 rounded-full ring-2 ring-slate-950 ${meta.dot}`} aria-hidden />
      <div className="rounded-lg border border-white/10 bg-slate-900/50 overflow-hidden">
        <button
          onClick={() => expandable && setOpen((o) => !o)}
          className={`w-full flex items-center gap-2 px-3 py-2 text-left ${expandable ? 'hover:bg-white/[0.03]' : 'cursor-default'}`}
        >
          <span className="text-xs">{meta.icon}</span>
          {held && <span className="text-[10px] px-1 rounded bg-amber-500/15 text-amber-300">HELD</span>}
          {action && <span className={`text-[10px] font-bold ${allow ? 'text-emerald-400' : 'text-red-400'}`}>{action}</span>}
          {e.category && <span className={`text-[10px] px-1.5 py-0.5 rounded ring-1 ${CATEGORY_STYLE[e.category]}`}>{e.category}</span>}
          {e.tool && <span className="text-xs font-mono text-slate-300 truncate">{e.tool}</span>}
          {resolution && <span className="text-[10px] text-slate-500">({resolution}{latencyMs !== undefined ? ` · ${fmtDuration(latencyMs)}` : ''})</span>}
          {risk && risk.score > 0 && (
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ring-1 ${BAND_STYLE[risk.band]}`} title={risk.version}>⚖ {risk.score}</span>
          )}
          <span className="ml-auto text-[10px] tabular-nums text-slate-600 shrink-0">{clockTime(e.ts)}</span>
          {expandable && <span className={`text-slate-600 text-[10px] transition ${open ? 'rotate-90' : ''}`}>▸</span>}
        </button>
        <div className="px-3 pb-2 -mt-1">
          <p className="text-[11px] text-slate-500">{e.reason}</p>
          {held && verdictReason && <p className="text-[11px] text-slate-400 mt-0.5">→ {verdictReason}</p>}
        </div>
        {open && (
          <div className="border-t border-white/5 bg-black/20 px-3 py-2.5 space-y-3">
            {diff && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Tool call</div>
                <pre className="text-xs font-mono text-amber-100 whitespace-pre-wrap break-words">{diff.title}</pre>
                {diff.body && <pre className="mt-1 max-h-40 overflow-auto rounded bg-black/40 p-2 text-[11px] font-mono text-slate-300">{diff.body}</pre>}
              </div>
            )}
            {!!risk?.factors?.length && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1">Risk breakdown — score {risk.score} ({risk.band})</div>
                <div className="space-y-1">
                  {risk.factors.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-[11px]">
                      <span className="text-slate-400 w-20 shrink-0">{f.source}</span>
                      <span className="text-slate-300 flex-1 truncate">{f.label} <span className="text-slate-600">· {f.group}</span></span>
                      <span className="tabular-nums text-slate-200">+{f.points}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

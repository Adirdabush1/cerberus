/** Shared formatting helpers + event presentation metadata, used by the Live stream and the timeline. */
import type { AuditEvent, MCPToolCall, ToolCategory } from './contract';

export const CATEGORY_STYLE: Record<ToolCategory, string> = {
  READ: 'bg-sky-500/15 text-sky-300 ring-sky-500/30',
  WRITE: 'bg-amber-500/15 text-amber-300 ring-amber-500/30',
  EXECUTE: 'bg-fuchsia-500/15 text-fuchsia-300 ring-fuchsia-500/30',
  EGRESS: 'bg-orange-500/15 text-orange-300 ring-orange-500/30',
  UNKNOWN: 'bg-red-500/15 text-red-300 ring-red-500/30',
};

/** Per-event-kind presentation: a glyph, a short label, and a dot color for the timeline rail. */
export const EVENT_META: Record<AuditEvent, { icon: string; label: string; dot: string }> = {
  'decision': { icon: '⚖', label: 'Decision', dot: 'bg-slate-400' },
  'hitl-opened': { icon: '⏸', label: 'Held for review', dot: 'bg-amber-400' },
  'hitl-resolved': { icon: '✓', label: 'Review resolved', dot: 'bg-emerald-400' },
  'session-started': { icon: '▶', label: 'Session started', dot: 'bg-sky-400' },
  'session-ended': { icon: '■', label: 'Session ended', dot: 'bg-slate-500' },
  'taint-loaded': { icon: '🔑', label: 'Secret loaded', dot: 'bg-orange-400' },
  'injection-detected': { icon: '🧪', label: 'Injection detected', dot: 'bg-red-400' },
  'tool-failed': { icon: '✕', label: 'Tool failed', dot: 'bg-rose-500' },
};

/** Turn a raw tool call into a human-readable "what the agent wants to do" (title + optional body). */
export function describe(call: MCPToolCall): { title: string; body: string | null } {
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

export function ago(ts: number, now: number): string {
  const s = Math.max(0, Math.round((now - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  return `${Math.floor(s / 60)}m ${s % 60}s ago`;
}

/** Wall-clock time of day, for the timeline (where absolute order matters more than "Ns ago"). */
export function clockTime(ts: number): string {
  const d = new Date(ts);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  return `${Math.floor(s / 60)}m ${Math.round(s % 60)}s`;
}

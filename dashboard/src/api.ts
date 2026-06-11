/**
 * REST helpers for the investigation history (D25). When the dashboard is served BY the engine the
 * base is the page origin; for standalone `vite dev` set VITE_AG_API to the engine's URL.
 */
import type { SessionSummary, SessionTimeline } from './contract';

function apiBase(): string {
  if (import.meta.env.VITE_AG_API) return String(import.meta.env.VITE_AG_API).replace(/\/$/, '');
  if (typeof window !== 'undefined' && window.location.protocol.startsWith('http')) {
    return window.location.origin;
  }
  return 'http://127.0.0.1:9000';
}

export async function fetchSessions(): Promise<SessionSummary[]> {
  const res = await fetch(`${apiBase()}/sessions`);
  if (!res.ok) throw new Error(`/sessions ${res.status}`);
  const data = (await res.json()) as { sessions: SessionSummary[] };
  return data.sessions ?? [];
}

export async function fetchTimeline(sessionId: string): Promise<SessionTimeline> {
  const res = await fetch(`${apiBase()}/sessions/${encodeURIComponent(sessionId)}/timeline`);
  if (!res.ok) throw new Error(`/sessions/${sessionId}/timeline ${res.status}`);
  return (await res.json()) as SessionTimeline;
}

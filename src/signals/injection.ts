/**
 * Injection signal (M3b) — classify a tool RESULT as prompt-injection or benign.
 *
 * This module owns ONLY the "is this text an injection attempt?" question and returns a 0–1 score
 * (forward-compatible with the M3c risk engine). What to DO with a positive — raising the session's
 * contamination posture so the next egress is gated — lives in the ContaminationMonitor + the
 * PreToolUse pipeline (D2/D12). This classifier never sees a decision and never blocks.
 *
 * Two implementations behind one interface (D10/D13):
 *   • HeuristicInjectionClassifier — always-on baseline, zero deps, deterministic regex. Ships in core.
 *   • (companion) OnnxInjectionClassifier — ProtectAI DeBERTa via @huggingface/transformers, loaded
 *     from the optional `@cerberussec/injection-model` package when installed. Better coverage.
 * If neither is enabled, a DisabledInjectionClassifier no-ops (available=false).
 */

export interface InjectionVerdict {
  score: number; // 0–1; higher = more likely prompt-injection
  label: string; // 'injection' | 'benign' (or the model's label)
}

export interface InjectionClassifier {
  readonly available: boolean;
  readonly name: string;
  classify(text: string): Promise<InjectionVerdict>;
}

export interface InjectionConfig {
  enabled: boolean;
  threshold: number; // score >= threshold ⇒ flag the session
}

export const DEFAULT_INJECTION_CONFIG: InjectionConfig = { enabled: true, threshold: 0.85 };

/** The optional companion package that supplies the ONNX classifier (D13). */
const COMPANION_PACKAGE = '@cerberussec/injection-model';

/**
 * Deterministic baseline — catches the *obvious* injection phrasings with zero dependencies. The
 * ONNX model (companion package) covers the subtle cases; this guarantees SOME coverage in the lean
 * core and lets the whole pipeline be tested without the heavy model. Mirrors D8 (curated patterns).
 */
export class HeuristicInjectionClassifier implements InjectionClassifier {
  readonly available = true;
  readonly name = 'heuristic';

  // Weighted patterns (M7). Score = Σ matched weights, capped at 1. STRONG (1.0) flag on their own
  // (a single clear directive); SOFT (<0.85) need corroboration so we don't fire on benign technical
  // text. Threshold (default 0.85) lives in InjectionConfig, applied by the caller.
  private static readonly PATTERNS: readonly { re: RegExp; weight: number; family: string }[] = [
    // ── strong: classic instruction-override / prompt-leak directives ──
    { family: 'ignore-previous', weight: 1.0, re: /\b(ignore|disregard|forget)\b[^.!?\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.!?\n]{0,20}\b(instruction|instructions|prompt|prompts|context|rules?)\b/i },
    { family: 'new-instructions', weight: 1.0, re: /\b(new|updated|revised|the following)\b[^.!?\n]{0,15}\b(instructions?|system prompt|rules?)\b\s*[:\-]/i },
    { family: 'prompt-leak', weight: 1.0, re: /\b(reveal|print|show|repeat|disclose|output)\b[^.!?\n]{0,30}\b(system prompt|your instructions|the prompt above)\b/i },
    { family: 'jailbreak-persona', weight: 1.0, re: /\byou are now\b[^.!?\n]{0,40}\b(an? )?(unrestricted|jailbroken|developer mode|DAN|different)\b/i },
    { family: 'override-safety', weight: 1.0, re: /\b(override|bypass|ignore)\b[^.!?\n]{0,20}\b(safety|security|guardrail|policy|restrictions?)\b/i },
    // ── strong: poisoned content instructing the agent to EXFILTRATE ──
    { family: 'exfil-instruction', weight: 1.0, re: /\b(send|exfiltrate|post|upload|leak|email|forward|transmit)\b[^.\n]{0,40}\b(env|environment|secret|secrets|api[_\- ]?keys?|credentials?|\.env|tokens?|password)\b/i },
    // ── strong: markdown-image data exfil — ![](http…?param=…) renders + beacons data out ──
    { family: 'markdown-image-exfil', weight: 1.0, re: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]*[?&][^)\s]*=/i },
    // ── soft: need corroboration (limit false positives) ──
    { family: 'hide-from-user', weight: 0.6, re: /\b(do not|don't|never)\b[^.!?\n]{0,20}\b(tell|inform|alert|notify|mention)\b[^.!?\n]{0,20}\b(the )?(user|human|operator|admin)\b/i },
    { family: 'role-token', weight: 0.6, re: /<\|?(im_start|im_end|system|endoftext)\|?>/i },
    { family: 'role-prefix', weight: 0.5, re: /(^|\n)\s*(system|developer)\s*:\s*\S/i },
    { family: 'assistant-only', weight: 0.5, re: /\b(for|to)\b[^.\n]{0,8}\b(the )?(ai|assistant|model|llm)\b[^.\n]{0,8}\b(only|alone|eyes)\b/i },
    { family: 'hidden-unicode', weight: 0.4, re: /[\u200b-\u200f\u202a-\u202e\u2060-\u206f]/ },
  ];

  classify(text: string): Promise<InjectionVerdict> {
    let score = 0;
    for (const { re, weight } of HeuristicInjectionClassifier.PATTERNS) if (re.test(text)) score += weight;
    score = Math.min(1, score);
    return Promise.resolve({ score, label: score > 0 ? 'injection' : 'benign' });
  }
}

export class DisabledInjectionClassifier implements InjectionClassifier {
  readonly available = false;
  readonly name = 'disabled';
  classify(): Promise<InjectionVerdict> {
    return Promise.resolve({ score: 0, label: 'disabled' });
  }
}

/**
 * Resolve the active classifier (D13). Prefers the optional ONNX companion package if installed,
 * else falls back to the always-on heuristic baseline, else disabled. The dynamic specifier is built
 * at runtime so the (optional, possibly-absent) companion is not a hard compile/resolve dependency.
 */
export async function loadInjectionClassifier(cfg: InjectionConfig): Promise<InjectionClassifier> {
  if (!cfg.enabled) return new DisabledInjectionClassifier();
  try {
    const spec = COMPANION_PACKAGE;
    const mod: { createClassifier?: (c: InjectionConfig) => InjectionClassifier | Promise<InjectionClassifier> } =
      await import(spec);
    if (mod?.createClassifier) return await mod.createClassifier(cfg);
  } catch {
    /* companion not installed — fall back to the heuristic baseline */
  }
  return new HeuristicInjectionClassifier();
}

/**
 * @cerberussec/injection-model — the optional ONNX injection classifier (D10/D13).
 *
 * ⚠️ STATUS: companion-package scaffold. The adapter code is real, but it is NOT exercised by
 * Cerberus's automated test suite — running it requires downloading the ~180MB ProtectAI ONNX model
 * and the native `onnxruntime-node` binary. Verify live, on the target hardware, before relying on it
 * (and measure CPU latency — Risk #2).
 *
 * Contract: Cerberus's core calls `loadInjectionClassifier()`, which dynamically imports this
 * package and calls `createClassifier(cfg)`. We return a structurally-compatible `InjectionClassifier`:
 *   { available: boolean; name: string; classify(text): Promise<{ score, label }> }
 *
 * Model: ProtectAI `deberta-v3-base-prompt-injection-v2` — Apache-2.0, pre-exported ONNX. Runs fully
 * local on CPU via @huggingface/transformers (onnxruntime-node backend). No external API (D1).
 *
 * Attribution (Apache-2.0, D11): ship the model's LICENSE/NOTICE in your distribution's
 * THIRD_PARTY_NOTICES. This package and its glue code are Apache-2.0; the model weights are ProtectAI's
 * Apache-2.0 artifacts.
 */
// @ts-expect-error — optional dependency; types resolve only once @huggingface/transformers is installed.
import { pipeline, env } from '@huggingface/transformers';

const MODEL_ID = 'protectai/deberta-v3-base-prompt-injection-v2';

export interface InjectionConfig {
  enabled: boolean;
  threshold: number;
}

interface Verdict {
  score: number;
  label: string;
}

/**
 * Build the classifier. `download-on-first-run` (D13): on first use the model is fetched into the
 * local cache, then loaded offline thereafter. To run fully air-gapped, pre-place the model under
 * `cacheDir` and set `AG_INJECTION_OFFLINE=1`.
 */
export async function createClassifier(_cfg: InjectionConfig) {
  if (process.env.AG_INJECTION_OFFLINE === '1') {
    env.allowRemoteModels = false;
  }
  if (process.env.AG_MODEL_CACHE) {
    env.cacheDir = process.env.AG_MODEL_CACHE;
  }

  // text-classification pipeline; quantized ONNX keeps CPU latency in the tens-of-ms range for short text.
  const classifier = await pipeline('text-classification', MODEL_ID, { dtype: 'q8' });

  return {
    available: true,
    name: 'onnx:protectai-deberta-v3',
    async classify(text: string): Promise<Verdict> {
      if (!text) return { score: 0, label: 'benign' };
      // DeBERTa max sequence ~512 tokens; truncate generously by characters to bound latency.
      const out = await classifier(text.slice(0, 4000), { topk: 1 });
      const top = Array.isArray(out) ? out[0] : out;
      const label = String(top?.label ?? 'benign').toUpperCase();
      const raw = Number(top?.score ?? 0);
      // ProtectAI labels: INJECTION (positive) vs SAFE. Normalize so `score` is P(injection).
      const isInjection = label.includes('INJECT') || label === 'LABEL_1';
      return { score: isInjection ? raw : 1 - raw, label: isInjection ? 'injection' : 'benign' };
    },
  };
}

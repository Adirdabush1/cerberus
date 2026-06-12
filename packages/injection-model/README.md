# @cerberussec/injection-model

Optional ONNX prompt-injection classifier for [Cerberus](../../). Installing it upgrades the
injection signal (M3b) from Cerberus's built-in **heuristic baseline** to a local **ONNX model**
([ProtectAI `deberta-v3-base-prompt-injection-v2`](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2),
Apache-2.0) for broader coverage.

```bash
npm install agentguard            # lean core — heuristic injection baseline, zero native deps
npm install @cerberussec/injection-model   # opt-in ONNX upgrade
```

Cerberus auto-detects this package on startup and uses it instead of the heuristic (the engine
banner shows `classifier=onnx:protectai-deberta-v3`). If it isn't installed, the heuristic baseline
keeps working — nothing breaks.

## Local-first / offline

The model is **downloaded on first run** into a local cache, then loaded offline thereafter
(`@huggingface/transformers` over `onnxruntime-node`, CPU). No external API, no API key, nothing
leaves the machine at runtime.

- `AG_MODEL_CACHE=/path` — where to cache/load the model.
- `AG_INJECTION_OFFLINE=1` — never reach the network; the model must already be in the cache.

## Status

⚠️ **Scaffold — not exercised by Cerberus's automated tests.** The adapter code is real, but live
inference needs the ~180MB model + the native `onnxruntime-node` binary. Verify on your target
hardware and measure CPU latency before relying on it.

## Licensing

- This package + its glue code: **Apache-2.0**.
- The model weights: **Apache-2.0** (ProtectAI). Carry the model's `LICENSE`/`NOTICE` in your
  distribution's `THIRD_PARTY_NOTICES`.
- This is the OSS-clean path. Llama Prompt Guard (multilingual, stronger) is **deliberately not used**
  here — its Llama Community License is not OSI open source. A future, separate, user-fetched plugin
  may offer it; that is the user's choice and their acceptance of Meta's terms.

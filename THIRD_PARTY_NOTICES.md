# Third-Party Notices

Cerberus (Apache-2.0) redistributes and depends on the third-party software below. Each remains
under its own license. This file satisfies the attribution requirements of those licenses.

## Bundled in the shipped package (`dashboard/dist/`)
The dashboard is a compiled Vite/React bundle; the following runtimes are compiled into it:

| Package | Version | License | Copyright |
|---|---|---|---|
| react | ^19 | MIT | Copyright (c) Meta Platforms, Inc. and affiliates |
| react-dom | ^19 | MIT | Copyright (c) Meta Platforms, Inc. and affiliates |

## Declared runtime dependencies (installed by npm alongside the package)
| Package | Version | License | Copyright |
|---|---|---|---|
| js-yaml | ^4.1.0 | MIT | Copyright (c) 2011-2015 Vitaly Puzrin |
| json-logic-js | ^2.0.5 | MIT | Copyright (c) 2013 jwadhams |
| ws | ^8.18.0 | MIT | Copyright (c) 2011 Einar Otto Stangvik and contributors |

Build-time-only tooling (TypeScript, Vite, Tailwind CSS, tsx, type stubs) is **not** redistributed in
the published package and is therefore not listed here.

## Optional companion (NOT part of this package)
- **`@cerberussec/injection-model`** — ProtectAI `deberta-v3-base-prompt-injection` ONNX weights,
  **Apache-2.0**. Installed separately and only if the user opts in; it upgrades the built-in heuristic
  injection classifier. Its own NOTICE/LICENSE ships with that package.

## Deliberately excluded
- **Meta Prompt-Guard** is **not** used or shipped. Its weights are under the Llama Community License
  (not an OSI-approved open-source license), so it is kept out of the OSS-clean core by design.

---

## The MIT License (applies to react, react-dom, js-yaml, json-logic-js, ws)

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

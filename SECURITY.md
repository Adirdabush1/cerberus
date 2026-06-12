# Security Policy

Cerberus is a security tool, so we hold its own supply chain and disclosure process to a high bar.

## Reporting a vulnerability

**Please report security issues privately — do not open a public issue.**

Use GitHub's private vulnerability reporting:
**[Report a vulnerability →](https://github.com/Adirdabush1/cerberus/security/advisories/new)**

We aim to acknowledge a report within **72 hours** and to ship a fix or mitigation for confirmed,
high-severity issues as quickly as is responsible. We'll credit reporters who want it.

## Supported versions

Security fixes target the **latest published** `@cerberussec/core` release on npm.

## Supply-chain assurances

- Releases are published from CI via **OIDC trusted publishing** (no long-lived npm token) with
  **build provenance** (`npm publish --provenance`) — you can verify a release was built from this repo.
- `main` is protected: changes land only via pull request with CI (tests + build) passing.
- **Secret scanning + push protection** are enabled on this repository.
- The CI token is **read-only** by default; fork-PR workflows require maintainer approval.

## Scope note

Cerberus is a **runtime gateway on the tool boundary**. It is strongest at secret-exfiltration
prevention and as a permission chokepoint. It inspects tool calls, **not the LLM prompt**, so it
catches the *exploitation* of a prompt injection (the egress) — not the injection itself — and it does
not cover data-pipeline / RAG poisoning. The exfil content-match is high-confidence but not airtight
(novel secret formats, split-across-calls encoding). Treat it as defense-in-depth, not a guarantee.

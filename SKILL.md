---
name: webapp-audit
description: Use when asked to audit, review or grade a site, app or codebase — security, headers/CSP, accessibility, performance, SEO and code health in one graded report.
version: 1.0.0
license: MIT
---

# Web / App Audit

One command audits a live URL or a local codebase and produces a graded report with evidence
behind every finding. Use it for "audit my site", "check this app", "is this production-ready",
"review the security", "why is it slow", "pre-launch check", or before shipping a client deliverable.

## Run it

```bash
# live site / web app (real Chrome, axe-core, headers, links, SEO)
python3 ~/.config/ai-agents/skills/webapp-audit/scripts/audit.py https://example.com

# codebase
python3 ~/.config/ai-agents/skills/webapp-audit/scripts/audit.py ~/Projects/my-app --deep

# CI / no display
python3 .../audit.py https://example.com --no-browser --json
```

Outputs `audit-report.md` in the current directory (or `--out`), prints the same report, and exits
non-zero when the overall grade is below C. Add `--json` for machine-readable findings.

## What it checks

| area | checks |
|------|--------|
| security | HTTPS + TLS version/expiry, HSTS, CSP quality (`unsafe-inline`/`unsafe-eval`/missing directives), X-Content-Type-Options, clickjacking, referrer + permissions policy, cookie flags, server/tech leaks, mixed content, `target=_blank` without `noopener`, password field over HTTP |
| privacy | CORS wildcard, COOP/CORP, third-party tracker hosts, consent-relevant loads |
| accessibility | axe-core (WCAG 2.1 A/AA + best-practice) in real Chrome, `lang`, viewport, image alt, landmarks, heading structure |
| performance | FCP, LCP, CLS, DOM size, transfer weight and request count, heaviest resources, compression, cache validators, image dimensions |
| SEO | title/meta description length, canonical, Open Graph, JSON-LD, robots.txt, sitemap.xml, broken internal links (sampled) |
| code | static security gate, lockfile, npm/pip audits, missing test/lint/typecheck scripts, .gitignore coverage, console errors and failed requests at runtime |

Grades: **A+ ≥ 95 · A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60**. Security carries 34 % of the
weight, so one critical security finding drags the whole grade down — that is intentional.

## How to use the result

1. **Report the grade table first**, then only the findings that matter (critical/high), each with
   its evidence line — never summarise away the evidence.
2. **Fix in severity order.** Critical security → high security/a11y → performance → the rest.
3. **Re-run after fixing.** A finding is closed when the re-run no longer lists it, not when the code
   "looks fixed".
4. Categories that could not run are reported as *skipped* with a reason — treat them as unknown,
   never as passing.

## Escalate to the deep security skill

`~/.config/ai-agents/skills/security-audit/` (vendored from Cloudflare, MIT) is the companion for
source-level vulnerability work: trust boundaries, auth/session design, injection, SSRF, IDOR,
crypto misuse, supply chain, cloud/IaC, AI/LLM surfaces. Load it when:

- the target handles authentication, payments, PII or multi-tenant data;
- this audit reports critical/high security findings and someone asks *why* or *how exploitable*;
- a pen-test-grade report with reproduction steps is required.

This skill answers "how healthy is it?"; the security-audit skill answers "how would it be broken?".

## Rules

- Read-only: never mutate the target, never submit forms, never authenticate.
- No secrets in reports: quote header **names** and shapes, redact token values.
- One page per run by default. For multi-page apps run it per route and report the worst grade.
- Local repos: run against the working tree; a dirty tree means the findings may not match `HEAD`.

## Dependencies

`node` (for the Chrome/axe pass; degrades to HTTP-only without it), `python3` ≥ 3.9, and a local
Chrome/Chromium. Everything else — axe-core, the CDP driver — is vendored in `vendor/` and `scripts/`.

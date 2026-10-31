# webapp-audit

**One command audits any site, app or codebase — security, accessibility, performance, SEO and code
health — and returns a graded report with evidence behind every finding.**

```bash
curl -sL https://audit.jrispace.com/install.sh | bash   # or just clone and run
audit https://your-site.com
audit ~/Projects/your-app --deep
```

Built for humans who ship and for AI coding agents that need a hard gate before saying "done".

---

## What it produces

```
## Overall: B (89.2/100)

| area          | score | grade | critical | high | medium | low |
|---------------|-------|-------|----------|------|--------|-----|
| security      |  90.0 |   A   |    0     |  0   |   0    |  5  |
| privacy       |  98.0 |  A+   |    0     |  0   |   0    |  1  |
| accessibility |  64.0 |   D   |    0     |  2   |   2    |  0  |
| performance   | 100.0 |  A+   |    0     |  0   |   0    |  0  |
| seo           |  94.0 |   A   |    0     |  0   |   0    |  3  |
| code          | 100.0 |  A+   |    0     |  0   |   0    |  0  |

### [accessibility] axe:color-contrast — Elements must meet minimum color contrast ratio thresholds (18 element(s))
- evidence: `.card-head > h2, #typeBadge — insufficient color contrast of 4.43 (fg #6c7891)`
- fix: See https://dequeuniversity.com/rules/axe/4.10/color-contrast
```

Every finding carries **evidence** — a measured number, a header value, an axe CSS target, a file
path. No finding is a guess, and a check that cannot run is reported as *skipped*, never as passing.

Grades: **A+ ≥ 95 · A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60**. Security is weighted 34 %, and a
critical security finding caps the overall grade — no amount of SEO rescues a plain-HTTP login form.

## What it checks

| area | checks |
|---|---|
| **security** | HTTPS + TLS version/expiry · HSTS · CSP quality (`unsafe-inline`, `unsafe-eval`, missing directives) · `X-Content-Type-Options` · clickjacking · referrer + permissions policy · cookie flags · server/tech disclosure · mixed content · `target=_blank` without `noopener` · password field over HTTP |
| **privacy** | CORS wildcard · COOP/CORP · third-party tracker hosts · consent-relevant loads |
| **accessibility** | axe-core WCAG 2.1 A/AA + best practice in a real browser · `lang` · viewport · image alt · landmarks · headings |
| **performance** | FCP · LCP · CLS · DOM size · transfer weight and request count · heaviest resources · compression · cache validators · image dimensions |
| **SEO** | title/description length · canonical · Open Graph · JSON-LD · `robots.txt` · `sitemap.xml` · sampled broken internal links |
| **code** | static security gate · lockfile · npm/pip audits · missing test/lint/typecheck scripts · `.gitignore` coverage · runtime console errors and failed requests |

## Install

### As a standalone CLI

```bash
git clone https://github.com/jrispace/webapp-audit.git ~/.config/ai-agents/skills/webapp-audit
ln -sf ~/.config/ai-agents/skills/webapp-audit/audit.sh /usr/local/bin/audit
audit https://example.com
```

Requirements: `python3` ≥ 3.9, `node` (for the browser pass), and a local Chrome/Chromium.
Everything else — axe-core and the CDP driver — is vendored. No pip install, no npm install.

### As an agent skill

The repo **is** an [Agent Skill](https://github.com/anthropics/skills): `SKILL.md` plus scripts.
Drop or symlink it wherever your agent looks for skills:

```bash
# Claude Code
ln -s "$PWD" ~/.claude/skills/webapp-audit
# Hermes Agent
ln -s "$PWD" ~/.hermes/skills/quality/webapp-audit
# Codex CLI — copy the prompt into ~/.codex/prompts/audit.md (see install.sh)
# Cursor — copy the rule into ~/.cursor/rules/audit.mdc (see install.sh)
```

Then just ask: *"audit my site"*, *"is this production-ready?"*, *"check this app before I ship"* —
the agent runs the tool, reads `audit-report.md`, and reports the grade table with the blocking
findings.

## Usage

```bash
audit <url|path> [--deep] [--no-browser] [--json] [--out FILE] [--timeout MS]
```

| flag | effect |
|---|---|
| `--deep` | also run `npm audit` / `pip-audit` on a codebase |
| `--no-browser` | HTTP-only pass — for CI or machines without Chrome |
| `--json` | machine-readable findings (same data as the markdown) |
| `--out FILE` | where to write the report (default `./audit-report.md`) |
| `--timeout MS` | browser wait budget (default 30 000) |

Exit codes: `0` ok · `3` overall grade below C — so it drops straight into CI as a gate.

## Design notes

- **Two browser passes.** The first pays DNS/TLS/CDN cold start; the second measures the warm
  experience. If the *runner's* own TTFB is above 2.5 s the audit reports performance without
  grading it — a slow network must never be reported as a slow site.
- **Read-only.** It never submits a form, never logs in, never mutates the target.
- **No secrets in reports.** Header names and shapes are quoted; token values are not.
- **Honest skips.** No Chrome or no `node`? The areas that need them are marked skipped with the
  reason, and their weight is redistributed — not silently passed.

## Going deeper on security

This tool answers *"how healthy is it?"*. For *"how would it be broken?"* — trust boundaries, auth
and session design, injection, SSRF, IDOR, crypto misuse, multi-tenant isolation, cloud/IaC — pair it
with the vendored [`security-audit`](https://github.com/cloudflare/security-audit-skill) skill
(Cloudflare, MIT). `SKILL.md` explains when to escalate.

## Licence

MIT — see [LICENSE](LICENSE).
Vendored: [axe-core](https://github.com/dequelabs/axe-core) 4.10.2, Mozilla Public License 2.0.

---

JRiSpace · **Sylvenson Richard** · [audit.jrispace.com](https://audit.jrispace.com)

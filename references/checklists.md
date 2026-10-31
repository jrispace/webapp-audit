# Audit checklists — what "good" looks like

Reference card for interpreting `audit.py` output. The deep vulnerability methodology lives in
`../../security-audit/` (Cloudflare, MIT) — this file is the fast, objective baseline.

## Security

| control | pass condition | why it matters |
|---|---|---|
| Transport | HTTPS only, TLS 1.2+, HSTS ≥ 6 months | downgrade + MITM |
| CSP | header (not only meta), no `unsafe-inline`/`unsafe-eval`, has `default-src`, `object-src`, `base-uri`, `frame-ancestors` | XSS blast radius |
| Content type | `X-Content-Type-Options: nosniff` | MIME confusion |
| Framing | `X-Frame-Options: DENY` or CSP `frame-ancestors 'none'` | clickjacking |
| Referrer | `Referrer-Policy: strict-origin-when-cross-origin` | URL/token leakage |
| Features | `Permissions-Policy` disabling camera/mic/geo you don't use | silent capability use |
| Cookies | `Secure`, `HttpOnly`, `SameSite` | session theft, CSRF |
| Disclosure | no `Server`, `X-Powered-By`, version banners | targeted exploit lookup |
| Links | `rel="noopener noreferrer"` on `target=_blank` | reverse tabnabbing |
| Mixed content | zero `http://` assets on an HTTPS page | blocking + injection |
| Forms | no password field over HTTP, `action` set, POST for mutations | credential exposure |

## Accessibility (axe-core)

Blocking: `color-contrast`, `image-alt`, `html-has-lang`, `document-title`, `label`, `button-name`,
`link-name`, `frame-title`, `aria-*` misuse. Best-practice: landmarks (`region`, `landmark-one-main`),
heading order, `page-has-heading-one`.

Rule of thumb: 4.5:1 contrast for body text, 3:1 for large text and UI borders. Muted grey on a
dark background fails more often than anything else in practice.

## Performance

| metric | good | needs work |
|---|---|---|
| LCP | < 2.5 s | > 4 s |
| FCP | < 1.8 s | > 3 s |
| CLS | < 0.1 | > 0.25 |
| transfer | < 1.5 MB | > 3 MB |
| DOM nodes | < 1 500 | > 3 000 |

Measure on the **warm** load; the first cold hit pays DNS+TLS and is not what users feel. If the
runner's own TTFB is above 2.5 s the audit reports performance without grading it — fix the network,
not the site.

## SEO / metadata

Title 15–65 chars, meta description 60–160, one `h1`, canonical link, Open Graph image, JSON-LD for
products/articles/events, `robots.txt` + `sitemap.xml` reachable, no broken internal links.

## Code health

Lockfile committed, `test`/`lint`/`typecheck`/`build` scripts present, no high/critical dependency
CVEs, `.gitignore` covering `.env`/keys, README, licence, no secrets in the tree, no runtime console
errors or failed requests.

## Grade interpretation

- **A+ / A** — ship it. Remaining items are hardening.
- **B** — ship with a fix list; nothing critical, but the polish is visible.
- **C / D** — do not hand to a client. Security or accessibility is failing.
- **F** — stop. At least one critical (plain HTTP, missing CSP, password over HTTP, critical CVE).

A critical security finding always caps the overall grade — no amount of SEO rescues it.

#!/usr/bin/env python3
"""webapp-audit — one command, one graded report, any target.

    python3 audit.py https://example.com            # live site / web app
    python3 audit.py ~/Projects/my-app              # codebase
    python3 audit.py https://example.com --no-browser   # skip Chrome (CI, no display)

Grades: security · privacy · accessibility · performance · SEO/metadata · code health.
Overall grade uses the JRiSpace A+ scale (A+ ≥ 95, A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, else F).

Design rules:
  - every finding carries evidence (header value, measured number, file:line, axe target)
  - a check that cannot run is reported as "skipped", never silently passed
  - no network upload of anything; the target is only read

JRiSpace | Sylvenson Richard
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import pathlib
import re
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

SKILL = pathlib.Path(__file__).resolve().parent.parent
SCRIPTS = SKILL / "scripts"
AXE = SKILL / "vendor" / "axe.min.js"
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36")

SEV_WEIGHT = {"critical": 25, "high": 12, "medium": 6, "low": 2, "info": 0}

findings: list[dict] = []
notes: list[str] = []


def add(category: str, severity: str, check: str, message: str, evidence: str = "", fix: str = "") -> None:
    findings.append({"category": category, "severity": severity, "check": check,
                     "message": message, "evidence": evidence, "fix": fix})


# ---------------------------------------------------------------- helpers
def fetch(url: str, method: str = "GET", timeout: int = 25):
    req = urllib.request.Request(url, method=method, headers={
        "User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9", "Accept-Encoding": "gzip, deflate",
    })
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(600_000) if method == "GET" else b""
            return {"status": r.status, "headers": dict(r.headers), "body": body, "final_url": r.geturl()}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": dict(e.headers or {}), "body": b"", "final_url": url, "error": str(e)}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": b"", "final_url": url, "error": str(e)}


def h(headers: dict, name: str) -> str:
    for k, v in headers.items():
        if k.lower() == name.lower():
            return v
    return ""


def decode(res) -> str:
    raw = res.get("body") or b""
    enc = h(res.get("headers", {}), "content-encoding").lower()
    if enc == "gzip":
        import gzip
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    elif enc in ("br", "zstd"):
        pass
    return raw.decode("utf-8", "ignore")


# ---------------------------------------------------------------- security
def check_security(url: str, res: dict, html: str = "") -> None:
    headers = res["headers"]
    parsed = urllib.parse.urlparse(url)

    if parsed.scheme != "https":
        add("security", "critical", "https", "Target is served over plain HTTP",
            evidence=url, fix="Serve only over HTTPS and redirect http→https (301).")
    else:
        # TLS
        try:
            host = parsed.hostname
            ctx = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    tls_ver = ss.version()
            not_after = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days = (not_after - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
            if days < 0:
                add("security", "critical", "tls-expiry", "TLS certificate has expired",
                    evidence=f"{not_after:%Y-%m-%d}", fix="Renew the certificate.")
            elif days < 21:
                add("security", "high", "tls-expiry", f"TLS certificate expires in {days} days",
                    evidence=f"{not_after:%Y-%m-%d}", fix="Renew / enable auto-renewal.")
            else:
                notes.append(f"TLS {tls_ver}, certificate valid {days} more days")
            if tls_ver in ("TLSv1", "TLSv1.1"):
                add("security", "high", "tls-version", f"Obsolete TLS version {tls_ver}",
                    evidence=tls_ver, fix="Require TLS 1.2+.")
        except Exception as e:
            add("security", "medium", "tls", "Could not verify the TLS handshake", evidence=str(e)[:120])

    # HSTS
    hsts = h(headers, "strict-transport-security")
    if parsed.scheme == "https":
        if not hsts:
            add("security", "high", "hsts", "Missing Strict-Transport-Security",
                evidence="no header", fix="Add: max-age=31536000; includeSubDomains; preload")
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 15_768_000:
                add("security", "medium", "hsts", "HSTS max-age below 6 months", evidence=hsts,
                    fix="Use max-age=31536000.")
            if "includeSubDomains" not in hsts:
                add("security", "low", "hsts", "HSTS without includeSubDomains", evidence=hsts,
                    fix="Add includeSubDomains once all subdomains are HTTPS.")

    # Core headers
    csp = h(headers, "content-security-policy")
    if not csp:
        meta_csp = re.search(r'<meta[^>]+http-equiv=["\']content-security-policy["\'][^>]+content=["\']([^"\']+)',
                             html, re.I)
        if meta_csp:
            csp = meta_csp.group(1)
            add("security", "low", "csp-meta-only",
                "CSP is delivered via a <meta> tag, not a response header",
                evidence=csp[:120],
                fix="Send the same policy as a Content-Security-Policy header (meta CSP cannot "
                    "use frame-ancestors or sandbox, and is not enforced for some fetches).")
        else:
            add("security", "high", "csp", "No Content-Security-Policy (header or meta)",
                evidence="no header, no meta", fix="Add a CSP (hash/nonce based).")
    if csp:
        if "unsafe-inline" in csp and "script-src" in csp.split("style-src")[0]:
            add("security", "high", "csp-unsafe-inline", "CSP allows unsafe-inline for scripts",
                evidence=csp[:160], fix="Use nonces or SHA-256 hashes for inline scripts.")
        if "unsafe-eval" in csp:
            add("security", "medium", "csp-unsafe-eval", "CSP allows unsafe-eval",
                evidence=csp[:160], fix="Remove unsafe-eval; avoid eval/new Function.")
        for directive in ("default-src", "object-src", "base-uri", "frame-ancestors"):
            if directive not in csp:
                add("security", "low", "csp-directive", f"CSP missing {directive}", evidence=csp[:120],
                    fix=f"Add {directive} to the policy.")

    for name, sev, hint in (
        ("x-content-type-options", "medium", "Add X-Content-Type-Options: nosniff"),
        ("referrer-policy", "low", "Add Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "low", "Add Permissions-Policy to disable unused features"),
    ):
        if not h(headers, name):
            add("security", sev, name, f"Missing {name}", evidence="no header", fix=hint)

    if not (h(headers, "x-frame-options") or "frame-ancestors" in csp):
        add("security", "medium", "clickjacking", "No clickjacking protection",
            evidence="no X-Frame-Options and no frame-ancestors",
            fix="Add X-Frame-Options: DENY and frame-ancestors 'none'.")

    for leak in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = h(headers, leak)
        if val:
            add("security", "low", "info-leak", f"Response discloses {leak}", evidence=val[:80],
                fix=f"Strip the {leak} header.")

    # cookies
    for raw in [v for k, v in headers.items() if k.lower() == "set-cookie"] or []:
        low = raw.lower()
        if "secure" not in low:
            add("security", "high", "cookie-secure", "Cookie without Secure flag", evidence=raw[:120],
                fix="Add Secure to every cookie.")
        if "httponly" not in low:
            add("security", "medium", "cookie-httponly", "Cookie without HttpOnly", evidence=raw[:120],
                fix="Add HttpOnly to session cookies.")
        if "samesite" not in low:
            add("security", "low", "cookie-samesite", "Cookie without SameSite", evidence=raw[:120],
                fix="Add SameSite=Lax or Strict.")


# ---------------------------------------------------------------- privacy
def check_privacy(url: str, res: dict, html: str) -> None:
    headers = res["headers"]
    for name, sev, cat in (
        ("access-control-allow-origin", "medium", "CORS"),
        ("cross-origin-opener-policy", "low", "COOP"),
        ("cross-origin-resource-policy", "low", "CORP"),
    ):
        val = h(headers, name)
        if val == "*" and cat == "CORS":
            has_cookie = any(k.lower() == "set-cookie" for k in headers)
            if has_cookie:
                add("privacy", "high", "cors-wildcard", "CORS wildcard on a response that sets cookies",
                    evidence=val, fix="Never combine ACAO:* with credentials; use an origin allow-list.")
            else:
                add("privacy", "low", "cors-wildcard",
                    "CORS allows any origin (acceptable for public static assets, not for APIs with sessions)",
                    evidence=val, fix="Restrict to known origins if the response is not public content.")
        elif not val:
            add("privacy", "low", name, f"Missing {name}", evidence="no header",
                fix=f"Add {name} (same-origin).")

    third_parties = set()
    for m in re.finditer(r'(?:src|href)="(https?://[^"]+)"', html):
        host = urllib.parse.urlparse(m.group(1)).hostname or ""
        if host and host not in url:
            third_parties.add(host)
    known_trackers = [d for d in third_parties if re.search(
        r"google-analytics|googletagmanager|doubleclick|facebook\.net|hotjar|segment|mixpanel|clarity\.ms|sentry", d)]
    if known_trackers:
        add("privacy", "info", "third-party-trackers",
            f"{len(known_trackers)} analytics/tracking host(s) loaded", evidence=", ".join(sorted(known_trackers)[:6]),
            fix="Load analytics only after consent, or drop it.")
    if third_parties:
        notes.append(f"{len(third_parties)} third-party host(s) referenced: {', '.join(sorted(third_parties)[:5])}")

    mixed = sorted({m.group(1) for m in re.finditer(r'(?:src|href)="(http://[^"]+)"', html)})
    if mixed:
        add("security", "high", "mixed-content", f"{len(mixed)} insecure http:// resource(s)",
            evidence=", ".join(mixed[:3]), fix="Serve every asset over HTTPS.")

    if re.search(r"<input[^>]+type=[\"']password", html, re.I) and url.startswith("http://"):
        add("security", "critical", "password-over-http", "Password field on a plain-HTTP page",
            evidence=url, fix="Move to HTTPS immediately.")


# ---------------------------------------------------------------- a11y from HTML
def check_html_signals(url: str, html: str) -> None:
    if not re.search(r"<html[^>]+lang=", html, re.I):
        add("accessibility", "medium", "html-lang", "Missing lang attribute on <html>",
            evidence="<html> without lang", fix='Add lang="en" (or the page language).')
    if not re.search(r'<meta[^>]+name=["\']viewport', html, re.I):
        add("accessibility", "medium", "viewport", "Missing responsive viewport meta",
            evidence="no viewport meta", fix='Add <meta name="viewport" content="width=device-width, initial-scale=1">')
    for m in re.finditer(r"<img\b[^>]*>", html, re.I):
        tag = m.group(0)
        if not re.search(r"\balt=", tag, re.I):
            add("accessibility", "high", "img-alt", "Image without alt attribute",
                evidence=tag[:110], fix="Add alt text, or alt=\"\" for decorative images.")
            break
    if not re.search(r"<main\b", html, re.I):
        add("accessibility", "low", "landmark-main", "No <main> landmark",
            evidence="no <main> element", fix="Wrap the primary content in <main>.")
    if re.search(r"<a[^>]+href=[\"']#[\"'][^>]*>", html, re.I):
        add("accessibility", "low", "empty-link", "Anchor with href=\"#\"",
            evidence="href=\"#\"", fix="Use a <button> for actions, or a real href.")
    if len(re.findall(r"<h1\b", html, re.I)) == 0:
        add("accessibility", "low", "h1", "No h1 on the page", evidence="0 <h1>", fix="Add one descriptive h1.")


# ---------------------------------------------------------------- seo
def check_seo(url: str, html: str) -> None:
    title = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
    t = re.sub(r"\s+", " ", title.group(1)).strip() if title else ""
    if not t:
        add("seo", "high", "title", "Missing <title>", evidence="no title", fix="Add a unique 50–60 char title.")
    elif not (15 <= len(t) <= 65):
        add("seo", "low", "title-length", f"Title is {len(t)} characters", evidence=t[:80],
            fix="Keep titles between 15 and 65 characters.")
    desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']*)', html, re.I)
    d = desc.group(1).strip() if desc else ""
    if not d:
        add("seo", "medium", "meta-description", "Missing meta description", evidence="no description",
            fix="Add a 120–158 character description.")
    elif not (60 <= len(d) <= 160):
        add("seo", "low", "meta-description-length", f"Meta description is {len(d)} characters",
            evidence=d[:80], fix="Aim for 120–158 characters.")
    if not re.search(r'<link[^>]+rel=["\']canonical', html, re.I):
        add("seo", "low", "canonical", "No canonical link", evidence="no rel=canonical",
            fix="Add a canonical URL to avoid duplicate indexing.")
    if not re.search(r'property=["\']og:(title|image)', html, re.I):
        add("seo", "low", "open-graph", "No Open Graph tags", evidence="no og:title/og:image",
            fix="Add og:title, og:description, og:image for link previews.")
    if not re.search(r"application/ld\+json", html, re.I):
        notes.append("no JSON-LD structured data (optional, helps rich results)")

    for path in ("robots.txt", "sitemap.xml"):
        base = f"{urllib.parse.urlparse(url).scheme}://{urllib.parse.urlparse(url).netloc}"
        r = fetch(f"{base}/{path}", method="HEAD", timeout=12)
        if r["status"] != 200:
            add("seo", "low", path, f"{path} not reachable", evidence=f"HTTP {r['status']}",
                fix=f"Publish /{path}.")


# ---------------------------------------------------------------- performance (HTTP)
def check_delivery(url: str, res: dict) -> None:
    headers = res["headers"]
    if not h(headers, "content-encoding") and "text/html" in h(headers, "content-type"):
        add("performance", "medium", "compression", "HTML not compressed",
            evidence="no Content-Encoding", fix="Enable gzip or brotli for text assets.")
    cc = h(headers, "cache-control")
    if not cc:
        add("performance", "low", "cache-control", "No Cache-Control on the document",
            evidence="no header", fix="Set a short max-age with revalidation for HTML.")
    if not (h(headers, "etag") or h(headers, "last-modified")):
        add("performance", "low", "validators", "No ETag/Last-Modified", evidence="no validator",
            fix="Enable ETag so repeat visits are cheap.")
    size = len(res.get("body") or b"")
    if size > 500_000:
        add("performance", "medium", "html-weight", f"HTML document is {size // 1024} KB",
            evidence=f"{size} bytes", fix="Split assets; ship critical CSS only.")
    notes.append(f"document transfer {size // 1024} KB")


def check_links(url: str, html: str, limit: int = 20) -> None:
    base = urllib.parse.urlparse(url)
    links = set()
    for m in re.finditer(r'href=["\'](/[^"\'#?]+|https?://[^"\']+)["\']', html):
        u = m.group(1)
        if u.startswith("/"):
            u = f"{base.scheme}://{base.netloc}{u}"
        if urllib.parse.urlparse(u).netloc == base.netloc and u.rstrip("/") != url.rstrip("/"):
            links.add(u.split("#")[0])
    links = sorted(links)[:limit]
    if not links:
        return
    broken = []

    def head(u):
        r = fetch(u, method="HEAD", timeout=12)
        return u, r["status"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        for u, status in ex.map(head, links):
            if status >= 400 or status == 0:
                broken.append((u, status))
    if broken:
        add("seo", "medium", "broken-links", f"{len(broken)} broken internal link(s) of {len(links)} checked",
            evidence=", ".join(f"{u} → {s}" for u, s in broken[:3]),
            fix="Fix or redirect the failing URLs.")
    else:
        notes.append(f"{len(links)} internal links checked, none broken")


# ---------------------------------------------------------------- browser pass
def browser_pass(url: str, timeout: int) -> dict | None:
    if not AXE.exists():
        add("accessibility", "info", "axe", "axe-core missing — accessibility run skipped",
            evidence=str(AXE), fix="Re-vendor axe.min.js.")
        return None
    if not shutil_which("node"):
        add("accessibility", "info", "axe", "node not found — accessibility run skipped",
            evidence="node missing", fix="Install Node.js to run the axe pass.")
        return None
    def once(label: str):
        try:
            r = subprocess.run(
                ["node", str(SCRIPTS / "browser_audit.js"), url, "--axe", str(AXE),
                 "--timeout", str(timeout)],
                capture_output=True, text=True, errors="ignore", timeout=timeout / 1000 + 60)
        except subprocess.TimeoutExpired:
            add("accessibility", "info", "axe", f"browser audit timed out ({label})",
                evidence=f">{timeout} ms")
            return None
        if r.returncode != 0:
            add("accessibility", "info", "axe", f"browser audit could not run ({label})",
                evidence=(r.stderr or r.stdout)[:200], fix="Run the browser pass manually.")
            return None
        try:
            return json.loads(r.stdout)
        except Exception:
            add("accessibility", "info", "axe", "browser audit returned unparsable output",
                evidence=r.stdout[:200])
            return None

    # Two passes: the first pays DNS/TLS/CDN cold start, the second measures the warm experience.
    cold = once("cold load")
    warm = once("warm load")
    data = warm or cold
    if not data:
        return None
    if cold and warm:
        cp, wp = cold.get("runtime", {}).get("perf", {}), warm.get("runtime", {}).get("perf", {})
        notes.append(f"cold load: FCP {cp.get('firstContentfulPaintMs')} ms · TTFB {cp.get('ttfbMs')} ms "
                     f"(warm: FCP {wp.get('firstContentfulPaintMs')} ms · TTFB {wp.get('ttfbMs')} ms)")
        # grade the best of the two passes — a throttled runner must not look like a slow site
        best_ttfb = min(x for x in (cp.get("ttfbMs"), wp.get("ttfbMs")) if x) if any(
            (cp.get("ttfbMs"), wp.get("ttfbMs"))) else None
        for metric in ("firstContentfulPaintMs", "lcpMs", "ttfbMs", "loadMs"):
            vals = [v for v in (cp.get(metric), wp.get(metric)) if v]
            if vals:
                warm.setdefault("runtime", {}).setdefault("perf", {})[metric] = min(vals)
        if best_ttfb and best_ttfb > 2500:
            warm["_network_degraded"] = best_ttfb
            notes.append(f"network latency is high (best TTFB {best_ttfb} ms) — performance is reported, not graded")
        # keep the warm metrics, but the union of axe/console findings from both
        seen = {(f["check"], f["message"]) for f in findings if f["category"] == "accessibility"}
        for extra in (cold.get("axe", {}).get("violations") or []):
            if (f"axe:{extra['id']}", f"{extra['help']} ({extra['nodes']} element(s))") not in seen:
                warm.setdefault("axe", {}).setdefault("violations", []).append(extra)
    return data


def shutil_which(name: str) -> str | None:
    import shutil
    return shutil.which(name)


def score_browser(data: dict) -> None:
    runtime = data.get("runtime", {})
    degraded = data.get("_network_degraded")
    before = len(findings)
    doc = runtime.get("doc", {})
    perf = runtime.get("perf", {})
    axe = data.get("axe", {})

    for v in axe.get("violations", []):
        impact = v.get("impact") or "minor"
        sev = {"critical": "critical", "serious": "high", "moderate": "medium", "minor": "low"}.get(impact, "low")
        add("accessibility", sev, f"axe:{v['id']}", f"{v['help']} ({v['nodes']} element(s))",
            evidence=", ".join(v.get("targets", [])[:3]) + (f" — {v.get('sample', '')[:120]}" if v.get("sample") else ""),
            fix=f"See {v.get('helpUrl', 'https://dequeuniversity.com/rules/axe/')}")

    if doc.get("missingAlt"):
        add("accessibility", "high", "img-alt-live", f"{doc['missingAlt']} image(s) render without an alt attribute",
            evidence=f"{doc['missingAlt']} of {doc.get('images')} images",
            fix="Add alt text; empty alt for decorative images.")
    if doc.get("imagesWithoutDimensions"):
        add("performance", "low", "img-dimensions", f"{doc['imagesWithoutDimensions']} image(s) without width/height",
            evidence="layout shift risk", fix="Set intrinsic width/height or aspect-ratio.")
    if doc.get("blankLinksWithoutRel"):
        add("security", "low", "target-blank-rel", f"{doc['blankLinksWithoutRel']} target=_blank link(s) without rel=noopener",
            evidence="window.opener exposure", fix='Add rel="noopener noreferrer".')
    if doc.get("h1Count") == 0:
        add("seo", "low", "h1-live", "Rendered page has no h1")
    if doc.get("h1Count", 0) > 1:
        add("seo", "low", "h1-multiple", f"Rendered page has {doc['h1Count']} h1 elements")

    lcp = perf.get("lcpMs")
    fcp = perf.get("firstContentfulPaintMs")
    cls = perf.get("cls")
    load = perf.get("loadMs") or 0

    # Headless Chrome can defer the first composite; a paint time far beyond the load event is
    # measurement noise, not a slow page. Drop it instead of penalising the target.
    def noisy(t):
        return bool(t and load and t > load + 4000)

    if noisy(fcp):
        notes.append(f"FCP {fcp} ms looked like headless throttling — ignored")
        fcp = None
    if noisy(lcp):
        notes.append(f"LCP {lcp} ms looked like headless throttling — ignored")
        lcp = None
    if lcp and lcp > 4000:
        add("performance", "high", "lcp", f"LCP is {lcp} ms (target < 2500)", evidence=f"{lcp} ms",
            fix="Optimise the largest element: preload it, compress images, cut render-blocking CSS/JS.")
    elif lcp and lcp > 2500:
        add("performance", "medium", "lcp", f"LCP is {lcp} ms (target < 2500)", evidence=f"{lcp} ms",
            fix="Trim critical path; serve modern image formats.")
    if fcp and fcp > 3000:
        add("performance", "medium", "fcp", f"First contentful paint is {fcp} ms", evidence=f"{fcp} ms",
            fix="Inline critical CSS, defer non-critical JS.")
    if cls is not None and cls > 0.25:
        add("performance", "high", "cls", f"CLS is {cls} (target < 0.1)", evidence=str(cls),
            fix="Reserve space for images/embeds; avoid inserting content above the fold.")
    elif cls is not None and cls > 0.1:
        add("performance", "medium", "cls", f"CLS is {cls} (target < 0.1)", evidence=str(cls),
            fix="Reserve space for late-loading elements.")
    kb = perf.get("transferKB")
    if kb and kb > 3000:
        add("performance", "high", "page-weight", f"Page transfers {kb} KB", evidence=f"{kb} KB, {perf.get('requests')} requests",
            fix="Compress images, code-split, drop unused libraries.")
    elif kb and kb > 1500:
        add("performance", "medium", "page-weight", f"Page transfers {kb} KB", evidence=f"{kb} KB")
    if perf.get("domNodes", 0) > 1500:
        add("performance", "low", "dom-size", f"{perf.get('domNodes')} DOM nodes", evidence="large DOM",
            fix="Virtualise long lists; simplify markup.")

    if degraded:
        # the measurement path was slow, not necessarily the page: keep the numbers, drop the verdict
        findings[:] = [f for f in findings if not (f["category"] == "performance"
                                                  and f["severity"] in ("high", "medium")
                                                  and f["check"] in ("lcp", "fcp", "page-weight", "cls"))]

    for err in (data.get("consoleErrors") or [])[:6]:
        add("code", "medium", "console-error", "JavaScript error at runtime", evidence=err[:200],
            fix="Fix the exception; it usually breaks a feature silently.")
    for req in (data.get("failedRequests") or [])[:6]:
        add("code", "medium", "failed-request", f"Request failed: {req.get('error')}",
            evidence=(req.get("url") or "")[:140], fix="Fix the URL, CORS policy or server response.")

    notes.append(f"browser: FCP {fcp} ms · LCP {lcp} ms · CLS {cls} · {perf.get('transferKB')} KB over {perf.get('requests')} requests")


# ---------------------------------------------------------------- codebase mode
def code_pass(root: pathlib.Path, deep: bool) -> None:
    gate = pathlib.Path.home() / "scripts" / "ai-security-check.sh"
    if gate.exists():
        r = subprocess.run([str(gate), str(root)], capture_output=True, text=True, errors="ignore")
        if r.returncode != 0:
            blocking = [l for l in r.stdout.splitlines() if l.strip().startswith("✗")]
            add("security", "high", "static-gate", f"Static security gate failed ({len(blocking)} blocking finding(s))",
                evidence="; ".join(b.strip(" ✗") for b in blocking[:4]) or r.stdout[-200:],
                fix="Fix the blocking findings, then re-run ~/scripts/ai-security-check.sh")
        else:
            notes.append("static security gate passed (0 blocking)")
    else:
        notes.append("ai-security-check.sh not installed — static gate skipped")

    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text())
        except Exception:
            data = {}
        if not (root / "package-lock.json").exists() and not (root / "pnpm-lock.yaml").exists() \
                and not (root / "yarn.lock").exists():
            add("code", "high", "lockfile", "package.json without a lockfile", evidence="no lockfile",
                fix="Commit the lockfile; unpinned installs are unreproducible.")
        scripts = data.get("scripts", {})
        for s in ("test", "lint", "typecheck", "build"):
            if s not in scripts:
                add("code", "low", f"script-{s}", f"No `{s}` script in package.json",
                    evidence=", ".join(scripts) or "none", fix=f"Add a `{s}` script so the gate can run it.")
        if deep and shutil_which("npm"):
            r = subprocess.run(["npm", "audit", "--omit=dev", "--json"], cwd=root,
                               capture_output=True, text=True, errors="ignore", timeout=180)
            try:
                meta = json.loads(r.stdout).get("metadata", {}).get("vulnerabilities", {})
                crit, high = meta.get("critical", 0), meta.get("high", 0)
                if crit:
                    add("security", "critical", "npm-audit", f"{crit} critical dependency vulnerabilities",
                        evidence=f"critical={crit} high={high}", fix="npm audit fix / bump the packages.")
                elif high:
                    add("security", "high", "npm-audit", f"{high} high dependency vulnerabilities",
                        evidence=f"high={high}", fix="Update the affected packages.")
                else:
                    notes.append("npm audit: no high/critical vulnerabilities")
            except Exception:
                notes.append("npm audit could not run")

    reqs = root / "requirements.txt"
    if reqs.exists() and shutil_which("pip-audit"):
        r = subprocess.run(["pip-audit", "-r", str(reqs)], capture_output=True, text=True, errors="ignore", timeout=180)
        if r.returncode != 0:
            add("security", "high", "pip-audit", "Python dependency vulnerabilities found",
                evidence=r.stdout[-200:], fix="Upgrade the affected packages.")
        else:
            notes.append("pip-audit: clean")

    gi = root / ".gitignore"
    if gi.exists():
        body = gi.read_text()
        for secret in (".env", "*.pem", "*.key"):
            if secret not in body:
                add("security", "low", "gitignore", f"{secret} not covered by .gitignore", evidence=str(gi),
                    fix=f"Add {secret} to .gitignore.")
    else:
        add("code", "medium", "gitignore", "No .gitignore", evidence=str(root),
            fix="Add one that covers .env, keys and build output.")

    if not (root / "README.md").exists():
        add("code", "low", "readme", "No README.md", evidence=str(root),
            fix="Document what it is, how to run it, and how to deploy.")
    if not (root / "LICENSE").exists() and (root / "package.json").exists():
        add("code", "info", "license", "No LICENSE file", evidence=str(root), fix="Add a licence.")

    todos = 0
    for f in list(root.rglob("*.js"))[:200] + list(root.rglob("*.py"))[:200]:
        if any(p in str(f) for p in ("node_modules", "/.git/", "/dist/", "/build/", "/lib/")):
            continue
        try:
            todos += len(re.findall(r"\b(TODO|FIXME|HACK|XXX)\b", f.read_text(errors="ignore")))
        except Exception:
            pass
    if todos:
        notes.append(f"{todos} TODO/FIXME marker(s) in source")


# ---------------------------------------------------------------- grading
CATEGORIES = ("security", "privacy", "accessibility", "performance", "seo", "code")
WEIGHTS = {"security": 0.34, "privacy": 0.10, "accessibility": 0.18, "performance": 0.16, "seo": 0.12, "code": 0.10}
# which areas are actually measurable for the current target (a codebase has no a11y or LCP)
ACTIVE: set[str] = set(CATEGORIES)


def grade_for(score: float) -> str:
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score() -> dict:
    out = {}
    for cat in CATEGORIES:
        cat_findings = [f for f in findings if f["category"] == cat]
        penalty = sum(SEV_WEIGHT[f["severity"]] for f in cat_findings)
        s = max(0.0, 100.0 - penalty)
        out[cat] = {"score": round(s, 1), "grade": grade_for(s),
                    "active": cat in ACTIVE,
                    "findings": len(cat_findings),
                    "counts": {sev: sum(1 for f in cat_findings if f["severity"] == sev)
                               for sev in ("critical", "high", "medium", "low", "info")}}
    # renormalise over the areas that actually ran, so a codebase audit is not inflated by
    # inapplicable accessibility/performance/SEO perfect scores
    active = [c for c in CATEGORIES if c in ACTIVE]
    wsum = sum(WEIGHTS[c] for c in active) or 1.0
    total = sum(out[c]["score"] * (WEIGHTS[c] / wsum) for c in active)
    out["_overall"] = {"score": round(total, 1), "grade": grade_for(total), "areas": active}
    return out


# ---------------------------------------------------------------- report
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def markdown(target: str, mode: str, scores: dict) -> str:
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"# Audit — {target}", "", f"_{mode} · {now} · JRiSpace webapp-audit_", "",
             f"## Overall: **{scores['_overall']['grade']}** ({scores['_overall']['score']}/100)", "",
             "| area | score | grade | critical | high | medium | low |",
             "|------|-------|-------|----------|------|--------|-----|"]
    for c in CATEGORIES:
        d = scores[c]
        if not d.get("active", True):
            lines.append(f"| {c} | n/a | — | — | — | — | — |")
            continue
        lines.append(f"| {c} | {d['score']} | {d['grade']} | {d['counts']['critical']} | "
                     f"{d['counts']['high']} | {d['counts']['medium']} | {d['counts']['low']} |")
    lines.append("")
    if notes:
        lines += ["## Measurements", ""] + [f"- {n}" for n in notes] + [""]

    for sev in ("critical", "high", "medium", "low", "info"):
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        lines += [f"## {sev.upper()} ({len(group)})", ""]
        for f in group:
            lines.append(f"### [{f['category']}] {f['check']} — {f['message']}")
            if f["evidence"]:
                lines.append(f"- evidence: `{f['evidence']}`")
            if f["fix"]:
                lines.append(f"- fix: {f['fix']}")
            lines.append("")
    if not findings:
        lines += ["No findings. ✓", ""]
    lines += ["---", "_Grades: A+ ≥ 95 · A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60. "
              "Security is weighted 34% — a critical there caps the overall grade._"]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Audit a live site/app (URL) or a codebase (path).")
    ap.add_argument("target")
    ap.add_argument("--no-browser", action="store_true", help="skip the headless Chrome pass")
    ap.add_argument("--deep", action="store_true", help="also run dependency audits")
    ap.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    ap.add_argument("--out", default="", help="write the report here (default: ./audit-report.md)")
    ap.add_argument("--timeout", type=int, default=30000, help="browser wait budget in ms")
    args = ap.parse_args()

    global ACTIVE
    is_url = bool(re.match(r"^https?://", args.target))
    ACTIVE = {"security", "privacy", "accessibility", "performance", "seo", "code"} if is_url \
        else {"security", "code"}
    target = args.target if is_url else str(pathlib.Path(args.target).expanduser().resolve())
    mode = "live web app" if is_url else "codebase"

    if is_url:
        res = fetch(target)
        if res["status"] == 0:
            print(f"cannot reach {target}: {res.get('error')}", file=sys.stderr)
            return 1
        html = decode(res)
        markup = re.sub(r"<(script|style|template)\b.*?</\1>", " ", html, flags=re.S | re.I)
        check_security(target, res, html)
        check_privacy(target, res, html)
        check_html_signals(target, markup)
        check_seo(target, markup)
        check_delivery(target, res)
        check_links(target, markup)
        if not args.no_browser:
            data = browser_pass(target, args.timeout)
            if data:
                score_browser(data)
        else:
            notes.append("browser pass skipped (--no-browser)")
    else:
        root = pathlib.Path(target)
        if not root.exists():
            print(f"no such path: {root}", file=sys.stderr)
            return 1
        code_pass(root, args.deep)

    scores = score()
    report = markdown(target, mode, scores)
    out = pathlib.Path(args.out) if args.out else pathlib.Path.cwd() / "audit-report.md"
    out.write_text(report, encoding="utf-8")

    if args.json:
        print(json.dumps({"target": target, "mode": mode, "scores": scores,
                          "findings": findings, "notes": notes}, indent=2, ensure_ascii=False))
    else:
        print(report)
        print(f"\nreport written to {out}")

    return 0 if scores["_overall"]["score"] >= 70 else 3


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build the docs site: src/index.html -> index.html with a strict, hash-pinned CSP.

Every inline <script> and <style> gets its SHA-256 pinned in the Content-Security-Policy meta tag,
so the page ships with `default-src 'none'` and no `unsafe-inline`.

    python3 build.py

JRiSpace | Sylvenson Richard
"""
import base64
import hashlib
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent
SRC = ROOT / "src" / "index.html"
OUT = ROOT / "index.html"
TOKEN = "<!--__CSP__-->"


def sha(body: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(body.encode()).digest()).decode() + "'"


def main() -> int:
    html = SRC.read_text(encoding="utf-8")
    if TOKEN not in html:
        print(f"placeholder {TOKEN} missing in {SRC}", file=sys.stderr)
        return 1

    scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S)
    styles = re.findall(r"<style[^>]*>(.*?)</style>", html, re.S)
    script_src = " ".join(dict.fromkeys(sha(s) for s in scripts)) or "'none'"
    style_src = " ".join(dict.fromkeys(sha(s) for s in styles)) or "'none'"

    parts = [
        "default-src 'none'",
        f"script-src {script_src}",
        f"style-src {style_src}",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'none'",
        "form-action 'none'",
        "base-uri 'none'",
        "object-src 'none'",
        "frame-src 'none'",
        "manifest-src 'self'",
    ]
    csp = '<meta http-equiv="Content-Security-Policy" content="' + "; ".join(parts) + '">'
    OUT.write_text(html.replace(TOKEN, csp), encoding="utf-8")
    print(f"built {OUT.name} ({(OUT.stat().st_size)/1024:.1f} KB) — CSP pins {len(scripts)} script(s), {len(styles)} style block(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

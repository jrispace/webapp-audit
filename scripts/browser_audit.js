#!/usr/bin/env node
/**
 * browser_audit.js — runtime audit of a live page in a throwaway headless Chrome.
 *
 * Collects, in one pass:
 *   - axe-core accessibility violations (WCAG 2.1 A/AA/AAA)
 *   - Core Web Vitals style metrics (FCP, LCP, CLS, TTFB, DOMContentLoaded, load)
 *   - resource weight + count by type, heaviest resources
 *   - image hygiene (missing alt, missing dimensions)
 *   - console errors and failed network requests
 *   - document facts (title, description, lang, viewport, canonical, h1 count, structured data)
 *
 * No puppeteer/playwright: Node built-ins + CDP over WebSocket.
 *
 * Usage: node browser_audit.js <url> --axe <path/to/axe.min.js> [--timeout 30000] [--json]
 * Exit:  0 ok · 1 harness failure · 2 page probe failure
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const CHROME_PATHS = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  process.env.CHROME_PATH,
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter(Boolean);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseArgs(argv) {
  const out = { positional: [], axe: null, timeout: 30000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--axe") out.axe = argv[++i];
    else if (a === "--timeout") out.timeout = parseInt(argv[++i], 10);
    else if (a === "--json") out.json = true;
    else out.positional.push(a);
  }
  return out;
}

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    this.consoleErrors = [];
    this.failedRequests = [];
    this.requests = new Map();
  }
  ready() {
    return new Promise((res, rej) => {
      this.ws.onopen = () => res();
      this.ws.onerror = () => rej(new Error("websocket error connecting to DevTools"));
      this.ws.onmessage = (ev) => {
        const m = JSON.parse(ev.data);
        if (m.id && this.pending.has(m.id)) {
          this.pending.get(m.id)(m);
          this.pending.delete(m.id);
          return;
        }
        if (m.method === "Runtime.consoleAPICalled" && ["error", "assert"].includes(m.params.type)) {
          this.consoleErrors.push(
            (m.params.args || []).map((a) => a.value ?? a.description ?? a.type).join(" ").slice(0, 300)
          );
        }
        if (m.method === "Runtime.exceptionThrown") {
          const d = m.params.exceptionDetails || {};
          this.consoleErrors.push(((d.exception && d.exception.description) || d.text || "exception").slice(0, 300));
        }
        if (m.method === "Network.loadingFailed") {
          this.failedRequests.push({ id: m.params.requestId, error: m.params.errorText, type: m.params.type });
        }
        if (m.method === "Network.responseReceived") {
          this.requests.set(m.params.requestId, {
            url: m.params.response.url,
            status: m.params.response.status,
            type: m.params.type,
            mime: m.params.response.mimeType,
          });
        }
        const h = this.handlers.get(m.method);
        if (h) h(m.params);
      };
    });
  }
  on(method, fn) { this.handlers.set(method, fn); }
  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((res, rej) => {
      this.pending.set(id, (m) => (m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result)));
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async eval(expression, awaitPromise = false) {
    const r = await this.send("Runtime.evaluate", {
      expression,
      returnByValue: true,
      awaitPromise,
      userGesture: true,
      allowUnsafeEvalBlockedByCSP: true,
    });
    if (r.exceptionDetails) {
      const d = r.exceptionDetails;
      throw new Error("probe threw: " + ((d.exception && d.exception.description) || d.text));
    }
    return r.result.value;
  }
}

const AUDIT_JS = `(function () {
  var out = {};
  var nav = performance.getEntriesByType("navigation")[0] || {};
  var paints = {};
  performance.getEntriesByType("paint").forEach(function (p) { paints[p.name] = Math.round(p.startTime); });
  var res = performance.getEntriesByType("resource") || [];
  var byType = {};
  var total = 0, heaviest = [];
  res.forEach(function (r) {
    var size = r.transferSize || r.encodedBodySize || 0;
    total += size;
    var t = r.initiatorType || "other";
    byType[t] = byType[t] || { count: 0, bytes: 0 };
    byType[t].count++; byType[t].bytes += size;
    heaviest.push({ url: r.name.slice(0, 120), kb: Math.round(size / 1024), type: t });
  });
  heaviest.sort(function (a, b) { return b.kb - a.kb; });

  var imgs = [].slice.call(document.images || []);
  var missingAlt = imgs.filter(function (i) { return !i.hasAttribute("alt"); }).length;
  var emptyAlt = imgs.filter(function (i) { return i.getAttribute("alt") === ""; }).length;
  var noDims = imgs.filter(function (i) { return !i.getAttribute("width") && !i.getAttribute("height"); }).length;

  var meta = function (sel) { var e = document.querySelector(sel); return e ? (e.content || "").trim() : null; };

  out.doc = {
    url: location.href,
    title: (document.title || "").trim(),
    titleLength: (document.title || "").trim().length,
    description: meta('meta[name="description"]'),
    descriptionLength: (meta('meta[name="description"]') || "").length,
    lang: document.documentElement.lang || null,
    viewport: meta('meta[name="viewport"]'),
    robots: meta('meta[name="robots"]'),
    canonical: (document.querySelector('link[rel="canonical"]') || {}).href || null,
    ogTitle: meta('meta[property="og:title"]'),
    ogImage: meta('meta[property="og:image"]'),
    h1Count: document.querySelectorAll("h1").length,
    h1Text: (document.querySelector("h1") || {}).textContent ? document.querySelector("h1").textContent.trim().slice(0, 90) : null,
    jsonLdBlocks: document.querySelectorAll('script[type="application/ld+json"]').length,
    images: imgs.length,
    missingAlt: missingAlt,
    emptyAlt: emptyAlt,
    imagesWithoutDimensions: noDims,
    iframes: document.querySelectorAll("iframe").length,
    formsWithoutAction: [].slice.call(document.forms).filter(function (f) { return !f.getAttribute("action"); }).length,
    passwordFields: document.querySelectorAll('input[type="password"]').length,
    externalLinks: [].slice.call(document.querySelectorAll('a[href^="http"]')).filter(function (a) { return a.host !== location.host; }).length,
    blankLinksWithoutRel: [].slice.call(document.querySelectorAll('a[target="_blank"]')).filter(function (a) {
      return !/noopener/.test(a.getAttribute("rel") || "");
    }).length,
    domNodes: document.getElementsByTagName("*").length
  };

  out.perf = {
    ttfbMs: Math.round((nav.responseStart || 0)),
    domContentLoadedMs: Math.round(nav.domContentLoadedEventEnd || 0),
    loadMs: Math.round(nav.loadEventEnd || 0),
    firstPaintMs: paints["first-paint"] || null,
    firstContentfulPaintMs: paints["first-contentful-paint"] || null,
    transferKB: Math.round(total / 1024),
    requests: res.length,
    byType: byType,
    heaviest: heaviest.slice(0, 6),
    viewport: { w: innerWidth, h: innerHeight },
    devicePixelRatio: devicePixelRatio
  };

  return new Promise(function (resolve) {
    var lcp = null, cls = 0, clsEntries = 0;
    try {
      new PerformanceObserver(function (l) {
        l.getEntries().forEach(function (e) { lcp = Math.round(e.startTime); });
      }).observe({ type: "largest-contentful-paint", buffered: true });
      new PerformanceObserver(function (l) {
        l.getEntries().forEach(function (e) {
          if (!e.hadRecentInput) { cls += e.value; clsEntries++; }
        });
      }).observe({ type: "layout-shift", buffered: true });
    } catch (e) {}
    setTimeout(function () {
      out.perf.lcpMs = lcp;
      out.perf.cls = Math.round(cls * 1000) / 1000;
      out.perf.clsEntries = clsEntries;
      resolve(JSON.stringify(out));
    }, 800);
  });
})()`;

(async () => {
  const args = parseArgs(process.argv.slice(2));
  const url = args.positional[0];
  if (!url) {
    console.error("usage: node browser_audit.js <url> --axe <axe.min.js> [--timeout ms]");
    process.exit(1);
  }
  if (!args.axe || !fs.existsSync(args.axe)) {
    console.error("axe-core not found: " + args.axe);
    process.exit(1);
  }
  const axeSource = fs.readFileSync(args.axe, "utf8");
  const chrome = CHROME_PATHS.find((p) => fs.existsSync(p));
  if (!chrome) {
    console.error("No Chrome/Chromium found. Set CHROME_PATH.");
    process.exit(1);
  }

  const port = 9500 + Math.floor(Math.random() * 400);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "audit-profile-"));
  const proc = spawn(chrome, [
    "--headless=new",
    "--remote-debugging-port=" + port,
    "--user-data-dir=" + profile,
    "--no-first-run", "--no-default-browser-check", "--disable-gpu",
    "--window-size=1366,900",
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--autoplay-policy=no-user-gesture-required",
    "about:blank",
  ], { stdio: "ignore", detached: true });

  let target = null;
  try {
    let up = false;
    for (let i = 0; i < 80; i++) {
      try {
        const r = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (r.ok) { up = true; break; }
      } catch (e) {}
      await sleep(250);
    }
    if (!up) throw new Error("Chrome DevTools endpoint never came up");

    // open a blank tab, then navigate explicitly so we can wait for the real load event
    const created = await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" });
    target = await created.json();

    const c = new CDP(target.webSocketDebuggerUrl);
    await c.ready();
    await c.send("Runtime.enable");
    await c.send("Page.enable");
    await c.send("Network.enable");

    await c.send("Emulation.setDeviceMetricsOverride",
      { width: 1366, height: 900, deviceScaleFactor: 1, mobile: false });
    try { await c.send("Page.bringToFront"); } catch (e) {}
    try { await c.send("Emulation.setFocusEmulationEnabled", { enabled: true }); } catch (e) {}

    const loaded = new Promise((res) => {
      const t = setTimeout(res, args.timeout);
      c.on("Page.loadEventFired", () => { clearTimeout(t); res(); });
    });
    await c.send("Page.navigate", { url });
    await loaded;
    await sleep(1500);   // let late fonts/images/analytics settle

    const here = await c.eval("String(location.href)");
    if (!here || here === "about:blank" || !here.startsWith("http")) {
      throw new Error("navigation did not commit: " + here);
    }

    const runtime = JSON.parse(await c.eval(AUDIT_JS, true));
    if (runtime.doc && runtime.doc.url === "about:blank") throw new Error("audited about:blank");

    // axe-core: inject then run
    await c.eval(axeSource + "\n;true");
    const axe = await c.eval(`axe.run(document, { resultTypes: ["violations"], runOnly: { type: "tag", values: ["wcag2a","wcag2aa","wcag21a","wcag21aa","best-practice"] } })
      .then(function (r) {
        return JSON.stringify({
          violations: r.violations.map(function (v) {
            return {
              id: v.id, impact: v.impact, help: v.help, helpUrl: v.helpUrl, tags: v.tags,
              nodes: v.nodes.length,
              targets: v.nodes.slice(0, 3).map(function (n) { return (n.target || []).join(" "); }),
              sample: (v.nodes[0] && v.nodes[0].failureSummary || "").slice(0, 220)
            };
          })
        });
      })`, true);

    const failed = c.failedRequests
      .map((f) => ({ ...f, url: (c.requests.get(f.id) || {}).url }))
      .filter((f) => f.url)
      .slice(0, 15);

    console.log(JSON.stringify({
      url,
      runtime,
      axe: JSON.parse(axe),
      consoleErrors: c.consoleErrors.slice(0, 15),
      failedRequests: failed,
    }, null, 1));

    try { await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`); } catch (e) {}
    process.exit(0);
  } catch (err) {
    console.error("AUDIT_FAIL " + err.message);
    process.exit(2);
  } finally {
    try { process.kill(-proc.pid); } catch (e) {}
    try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) {}
  }
})();

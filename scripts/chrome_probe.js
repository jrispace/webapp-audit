#!/usr/bin/env node
/**
 * chrome_verify.js — run JS inside a real Chrome page (file:// or http://) with no
 * puppeteer/playwright install and without touching the user's Chrome settings.
 *
 * Boots a throwaway `--headless=new` Chrome with `--remote-debugging-port`, opens the URL,
 * waits for the app to render, evaluates a probe, prints the result, kills Chrome.
 * Uses Node 22 built-ins only: fetch + WebSocket.
 *
 * Usage:
 *   node chrome_verify.js <url> [probe.js | "js expression"] [--boot "<js expr>"] [--timeout 30000] [--keep]
 *
 *   --boot      expression polled until truthy before the probe runs (default:
 *               a check that document.body exists). Use it to wait for rows to render.
 *   --timeout   ms to wait for --boot and for the probe (default 30000; probe promises
 *               should do their own inner polling for debounced handlers)
 *   --keep      leave Chrome running (debugging); prints the port
 *
 * The probe must be a single expression. With awaitPromise the cleanest shape is:
 *
 *   (function(){
 *     document.getElementById('live').click();
 *     return new Promise(function(res){
 *       var t0 = Date.now(), iv = setInterval(function(){
 *         var st = document.getElementById('live').getAttribute('data-state');
 *         if(st === 'ok' || st === 'error' || Date.now() - t0 > 30000){
 *           clearInterval(iv);
 *           res(JSON.stringify({ state: st, ms: Date.now() - t0 }));
 *         }
 *       }, 250);
 *     });
 *   })()
 *
 * Exit codes: 0 = probe ran, 1 = harness/boot failure, 2 = probe threw.
 */
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const CHROME_PATHS = [
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function parseArgs(argv) {
  const out = { positional: [], boot: null, timeout: 30000, keep: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--boot") out.boot = argv[++i];
    else if (a === "--timeout") out.timeout = parseInt(argv[++i], 10);
    else if (a === "--keep") out.keep = true;
    else out.positional.push(a);
  }
  return out;
}

class CDP {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.id = 0;
    this.pending = new Map();
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
        }
      };
    });
  }
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

(async () => {
  const args = parseArgs(process.argv.slice(2));
  if (!args.positional.length) {
    console.error("usage: node chrome_verify.js <url> [probe.js | \"expr\"] [--boot expr] [--timeout ms] [--keep]");
    process.exit(1);
  }
  const url = args.positional[0];
  let probeSrc = args.positional[1];
  if (probeSrc && fs.existsSync(probeSrc)) probeSrc = fs.readFileSync(probeSrc, "utf8");
  if (!probeSrc) probeSrc = "JSON.stringify({title: document.title, url: location.href})";
  const bootExpr = args.boot || "!!document.body && document.body.children.length > 0";

  const chrome = CHROME_PATHS.find((p) => fs.existsSync(p));
  if (!chrome) {
    console.error("No Chrome/Chromium binary found in: " + CHROME_PATHS.join(", "));
    process.exit(1);
  }

  const port = 9333 + Math.floor(Math.random() * 400);
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), "cdp-profile-"));
  const proc = spawn(
    chrome,
    [
      "--headless=new",
      "--remote-debugging-port=" + port,
      "--user-data-dir=" + profile,
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-gpu",
      "--allow-file-access-from-files",
      "--autoplay-policy=no-user-gesture-required",
      "about:blank",
    ],
    { stdio: "ignore", detached: true }
  );

  let target = null;
  try {
    let up = false;
    for (let i = 0; i < 60; i++) {
      try {
        const r = await fetch(`http://127.0.0.1:${port}/json/version`);
        if (r.ok) { up = true; break; }
      } catch (e) {}
      await sleep(250);
    }
    if (!up) throw new Error("Chrome DevTools endpoint never came up");

    const created = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`, { method: "PUT" });
    target = await created.json();

    const c = new CDP(target.webSocketDebuggerUrl);
    await c.ready();
    await c.send("Runtime.enable");
    await c.send("Page.enable");

    // wait for boot
    const booted = await c.eval(
      `new Promise(function(res){
         var t0 = Date.now();
         var iv = setInterval(function(){
           var ok = false;
           try { ok = !!(${bootExpr}); } catch(e){ ok = false; }
           if(ok){ clearInterval(iv); res(1); }
           else if(Date.now() - t0 > ${args.timeout}){ clearInterval(iv); res(0); }
         }, 100);
       })`,
      true
    );
    if (!booted) console.error("[warn] boot condition never became truthy; probing anyway");

    const value = await c.eval(probeSrc, true);
    let printed = value;
    if (typeof value === "string") {
      try { printed = JSON.stringify(JSON.parse(value), null, 1); } catch (e) { printed = value; }
    } else if (value && typeof value === "object") {
      printed = JSON.stringify(value, null, 1);
    }
    console.log(printed);

    try { await fetch(`http://127.0.0.1:${port}/json/close/${target.id}`); } catch (e) {}
    process.exit(0);
  } catch (err) {
    console.error("FAIL " + err.message);
    process.exit(2);
  } finally {
    if (!args.keep) {
      try { process.kill(-proc.pid); } catch (e) {}
      try { fs.rmSync(profile, { recursive: true, force: true }); } catch (e) {}
    } else {
      console.error("[keep] Chrome on port " + port);
    }
  }
})();

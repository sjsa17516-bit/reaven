// ===================================================================
// Panel Pro v5.0 — Cloudflare Worker + D1
// VLESS + Trojan | subscriptions | panel
// ===================================================================
import { connect } from "cloudflare:sockets";

const VERSION = "5.0";

export default {
  async fetch(request, env) {
    if (!env.DB) return new Response("D1 binding 'DB' missing", { status: 500 });
    try {
      await ensureSchema(env.DB);
    } catch (e) {
      return new Response("Database setup failed: " + (e.message || e), { status: 500 });
    }
    const url = new URL(request.url);
    const path = url.pathname;

    if ((request.headers.get("Upgrade") || "").toLowerCase() === "websocket") {
      return handleWebSocket(request, env);
    }

    if (path.startsWith("/sub/")) return handleSub(url, env, "base64", false);
    if (path.startsWith("/frag/")) return handleSub(url, env, "base64", true);
    if (path.startsWith("/clash/")) return handleSub(url, env, "clash", false);
    if (path.startsWith("/clash-frag/")) return handleSub(url, env, "clash", true);
    if (path.startsWith("/singbox/")) return handleSub(url, env, "singbox", false);
    if (path.startsWith("/singbox-frag/")) return handleSub(url, env, "singbox", true);
    if (path.startsWith("/warp/")) return handleWarp(url, env);
    if (path.startsWith("/qr/")) return handleQr(url, env);
    if (path.startsWith("/api/")) return handleApi(request, url, env);
    if (path === "/panel" || path === "/panel/") return handlePanel(request, env);
    if (path === "/dns-query") return handleDoH(request);

    return handleCamouflage(env);
  },
};

// ── Schema ──────────────────────────────────────────────────────────
let schemaReady = false;
async function ensureSchema(db) {
  if (schemaReady) return;
  await db.prepare(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    uuid TEXT NOT NULL,
    trojan_pass TEXT,
    limit_gb REAL,
    used_gb REAL DEFAULT 0,
    expiry_days INTEGER,
    max_devices INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0,
    daily_request_limit INTEGER DEFAULT 0,
    reset_interval_days INTEGER,
    last_reset_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    is_active INTEGER DEFAULT 1,
    note TEXT DEFAULT '',
    protocol TEXT DEFAULT 'vless'
  )`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`).run();
  await db.prepare(`CREATE TABLE IF NOT EXISTS active_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    client_ip TEXT,
    connected_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`).run();
  await db.prepare(`CREATE INDEX IF NOT EXISTS idx_conn_uuid ON active_connections(uuid)`).run();
  const cols = [
    "ALTER TABLE users ADD COLUMN max_devices INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN request_count INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN daily_request_limit INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN reset_interval_days INTEGER",
    "ALTER TABLE users ADD COLUMN last_reset_at TEXT DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE users ADD COLUMN note TEXT DEFAULT ''",
    "ALTER TABLE users ADD COLUMN trojan_pass TEXT",
    "ALTER TABLE users ADD COLUMN protocol TEXT DEFAULT 'vless'",
    "ALTER TABLE users ADD COLUMN used_gb REAL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN limit_gb REAL",
    "ALTER TABLE users ADD COLUMN expiry_days INTEGER",
    "ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1",
    "ALTER TABLE users ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP",
    "ALTER TABLE users ADD COLUMN uuid TEXT",
  ];
  for (const sql of cols) {
    try { await db.prepare(sql).run(); } catch { /* column already exists */ }
  }
  schemaReady = true;
}

// ── Helpers ─────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}
function sqlTime(s) {
  if (!s) return NaN;
  const raw = String(s).trim();
  const iso = raw.includes("T") ? raw : raw.replace(" ", "T") + "Z";
  return Date.parse(iso);
}
function numOrNull(v) {
  if (v === undefined || v === null || v === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
function intOrZero(v) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}
function formatHost(addr) {
  const a = String(addr);
  return a.includes(":") && !a.startsWith("[") ? `[${a}]` : a;
}
function splitHostPort(input, fallbackPort) {
  const s = String(input || "").trim();
  if (!s) return ["", fallbackPort];
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end > 1) {
      const host = s.slice(1, end);
      const rest = s.slice(end + 1);
      const port = rest.startsWith(":") ? parseInt(rest.slice(1), 10) : fallbackPort;
      return [host, Number.isFinite(port) ? port : fallbackPort];
    }
  }
  const colon = s.lastIndexOf(":");
  if (colon > 0 && s.indexOf(":") === colon) {
    const port = parseInt(s.slice(colon + 1), 10);
    return [s.slice(0, colon), Number.isFinite(port) ? port : fallbackPort];
  }
  return [s, fallbackPort];
}
const FP_ALLOWED = ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];
const ALPN_ALLOWED = ["h2,http/1.1", "http/1.1", "h2"];
async function getLinkOpts(env) {
  const fp = (await getSetting(env.DB, "link_fp", "chrome")).trim();
  const alpn = (await getSetting(env.DB, "link_alpn", "h2,http/1.1")).trim();
  return {
    fp: FP_ALLOWED.includes(fp) ? fp : "chrome",
    alpn: ALPN_ALLOWED.includes(alpn) ? alpn : "h2,http/1.1",
  };
}
const DEFAULT_OPTS = { fp: "chrome", alpn: "h2,http/1.1" };
function addrParts(addr) {
  const [h, p] = splitHostPort(addr, 443);
  return { host: h, port: p || 443 };
}
function yamlQuote(s) {
  return '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}
function utf8Base64(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
}
function b64urlToBytes(s) {
  let t = String(s).trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = t.length % 4;
  if (pad) t += "=".repeat(4 - pad);
  const d = atob(t);
  const out = new Uint8Array(d.length);
  for (let i = 0; i < d.length; i++) out[i] = d.charCodeAt(i);
  return out;
}
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function pathUser(url) {
  try { return decodeURIComponent(url.pathname.split("/")[3] || ""); }
  catch { return ""; }
}
function fragmentDelay(interval) {
  const raw = String(interval || "10-20").trim();
  if (/^\d+(\.\d+)?(ms|s)$/.test(raw)) return raw;
  const n = parseInt(raw, 10);
  return (Number.isFinite(n) && n > 0 ? n : 10) + "ms";
}
function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
function sha224hex(str) {
  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);
  const bytes = new TextEncoder().encode(str);
  const bitLen = bytes.length * 8;
  const total = Math.ceil((bitLen + 1 + 64) / 512) * 64;
  const buf = new Uint8Array(total);
  buf.set(bytes);
  buf[bytes.length] = 0x80;
  const view = new DataView(buf.buffer);
  view.setUint32(total - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(total - 4, bitLen >>> 0);
  const h = new Uint32Array([
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
    0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
  ]);
  const w = new Uint32Array(64);
  for (let i = 0; i < buf.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = view.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >>> 3);
      const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  let hex = "";
  for (let i = 0; i < 7; i++) hex += h[i].toString(16).padStart(8, "0");
  return hex;
}
async function sha256(t) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(t));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function getSetting(db, k, fb = "") {
  try {
    const r = await db.prepare("SELECT value FROM settings WHERE key=?").bind(k).first();
    return r && r.value != null ? r.value : fb;
  } catch {
    return fb;
  }
}
async function setSetting(db, k, v) {
  await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k, String(v)).run();
}
async function getPassHash(db) {
  const v = await getSetting(db, "panel_password", "");
  return v ? v : null;
}
async function isAuth(req, env) {
  const h = await getPassHash(env.DB);
  if (!h) return true;
  const c = req.headers.get("Cookie") || "";
  const m = c.split(";").map((x) => x.trim()).find((x) => x.startsWith("session="));
  return !!(m && safeEqual(m.slice(8), h));
}
function cookie(h) {
  return `session=${h}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
}
function clearCookie() {
  return "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
}
async function readJson(req) {
  try { return await req.json(); } catch { return {}; }
}
function json(o, s = 200, extra = {}) {
  return new Response(JSON.stringify(o), {
    status: s,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
}
function html(body, extra = {}) {
  return new Response(body, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      ...extra,
    },
  });
}
async function writeAll(writable, data) {
  if (!data || !data.byteLength) return;
  const w = writable.getWriter();
  try { await w.write(data); }
  finally { try { w.releaseLock(); } catch { /* already released */ } }
}
function makeCounter(env, username) {
  let total = 0;
  return {
    add(n) { if (n > 0) total += n; },
    flush() {
      if (total <= 0) return;
      const gb = total / (1024 ** 3);
      total = 0;
      env.DB.prepare("UPDATE users SET used_gb=used_gb+? WHERE username=?").bind(gb, username).run().catch(() => {});
    },
  };
}

// ── Public site ─────────────────────────────────────────────────────
async function handleCamouflage(env) {
  const name = await getSetting(env.DB, "camouflage_name", "Northline Cloud");
  const safe = escHtml(name);
  const year = new Date().getFullYear();
  const body = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="${safe} designs and operates a global edge network for low-latency applications.">
<title>${safe}</title>
<style>
  :root { color-scheme: dark; --bg:#07090f; --ink:#eef2f8; --muted:#93a0b5; --line:rgba(255,255,255,.1); --accent:#8aa4ff; --teal:#5eead4; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html { scroll-behavior: smooth; }
  body { min-height: 100vh; font-family: "Segoe UI", Inter, system-ui, sans-serif; background: var(--bg); color: var(--ink); line-height: 1.6; }
  .scene { position: fixed; inset: 0; z-index: 0; pointer-events: none; background:
    radial-gradient(900px 480px at 8% -10%, rgba(138,164,255,.22), transparent 60%),
    radial-gradient(720px 420px at 100% 0%, rgba(94,234,212,.12), transparent 55%),
    radial-gradient(800px 480px at 50% 120%, rgba(138,164,255,.1), transparent 50%),
    var(--bg); }
  .scene:before { content: ""; position: absolute; inset: 0; background-image:
    linear-gradient(to right, rgba(255,255,255,.035) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(255,255,255,.035) 1px, transparent 1px);
    background-size: 72px 72px; mask-image: radial-gradient(ellipse at 50% 15%, #000 10%, transparent 72%); }
  header, main, footer { position: relative; z-index: 1; }
  header { display: flex; justify-content: space-between; align-items: center; gap: 1rem; padding: 1.15rem 6vw; border-bottom: 1px solid var(--line); backdrop-filter: blur(16px); }
  .logo { display: flex; align-items: center; gap: .7rem; font-weight: 700; letter-spacing: -.02em; }
  .mark { width: 14px; height: 14px; border-radius: 4px; background: conic-gradient(from 210deg, var(--accent), var(--teal), var(--accent)); box-shadow: 0 0 18px rgba(138,164,255,.7); }
  nav { display: flex; gap: 1.4rem; }
  nav a { color: var(--muted); text-decoration: none; font-size: .92rem; }
  nav a:hover { color: var(--ink); }
  main { max-width: 1120px; margin: 0 auto; padding: 5.5rem 1.5rem 4rem; }
  .eyebrow { color: var(--teal); font-size: .78rem; letter-spacing: .16em; font-weight: 700; }
  h1 { font-size: clamp(2.5rem, 6vw, 4.6rem); line-height: 1.02; letter-spacing: -.045em; font-weight: 650; max-width: 14ch; margin: .8rem 0 1rem; }
  .lede { max-width: 42rem; color: var(--muted); font-size: 1.12rem; }
  .actions { display: flex; gap: .75rem; flex-wrap: wrap; margin-top: 1.8rem; }
  .btn { display: inline-flex; align-items: center; padding: .8rem 1.15rem; border-radius: 999px; text-decoration: none; font-weight: 650; background: linear-gradient(135deg, var(--accent), #6d8bff); color: #07101c; }
  .btn.ghost { background: transparent; color: var(--ink); border: 1px solid var(--line); }
  .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin: 3.5rem 0; }
  .metric, .card { background: rgba(16,20,30,.72); border: 1px solid var(--line); border-radius: 18px; padding: 1.25rem 1.3rem; box-shadow: inset 0 1px 0 rgba(255,255,255,.05); }
  .metric strong { display: block; font-size: 1.7rem; letter-spacing: -.03em; }
  .metric span, .card p { color: var(--muted); }
  .features { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
  .card h3 { margin-bottom: .4rem; letter-spacing: -.02em; }
  .band { margin-top: 1rem; display: grid; gap: .7rem; }
  .row { display: flex; justify-content: space-between; gap: 1rem; padding: .9rem 1rem; border: 1px solid var(--line); border-radius: 14px; background: rgba(255,255,255,.02); }
  .ok { color: var(--teal); font-weight: 700; font-size: .85rem; }
  footer { border-top: 1px solid var(--line); padding: 1.4rem 6vw 2rem; color: var(--muted); display: flex; justify-content: space-between; gap: 1rem; flex-wrap: wrap; font-size: .88rem; }
  @media (max-width: 800px) { .metrics, .features { grid-template-columns: 1fr; } nav { display: none; } h1 { max-width: none; } }
</style>
</head>
<body>
<div class="scene"></div>
<header>
  <div class="logo"><span class="mark"></span>${safe}</div>
  <nav>
    <a href="#platform">Platform</a>
    <a href="#network">Network</a>
    <a href="#security">Security</a>
  </nav>
</header>
<main>
  <p class="eyebrow">EDGE PLATFORM</p>
  <h1>Infrastructure that stays close to the work.</h1>
  <p class="lede">Deploy services across a private global network with predictable latency, automatic scaling, and security controls built into every region.</p>
  <div class="actions">
    <a class="btn" href="#platform">Explore the platform</a>
    <a class="btn ghost" href="#network">View network status</a>
  </div>
  <section class="metrics" id="platform">
    <div class="metric"><strong>300+</strong><span>cities on the network</span></div>
    <div class="metric"><strong>99.99%</strong><span>regional availability target</span></div>
    <div class="metric"><strong>&lt;50 ms</strong><span>typical in-region round trip</span></div>
  </section>
  <section class="features">
    <article class="card" id="network"><h3>Global anycast</h3><p>Traffic lands at the nearest healthy location and fails over without a manual cut.</p></article>
    <article class="card"><h3>Serverless runtime</h3><p>Run request-driven workloads that scale down to zero when the queue is empty.</p></article>
    <article class="card" id="security"><h3>Default security</h3><p>TLS, DDoS absorption, and a web application firewall are part of the base platform.</p></article>
  </section>
  <section class="band" aria-label="Service status">
    <div class="row"><span>Edge network</span><span class="ok">Operational</span></div>
    <div class="row"><span>Control plane</span><span class="ok">Operational</span></div>
    <div class="row"><span>Storage replication</span><span class="ok">Operational</span></div>
  </section>
</main>
<footer><span>&copy; ${year} ${safe}</span><span>All systems operational</span></footer>
</body>
</html>`;
  return html(body, { "Cache-Control": "public, max-age=3600" });
}

async function handleDoH(request) {
  const upstream = "https://cloudflare-dns.com/dns-query";
  if (request.method === "GET") {
    const u = new URL(request.url);
    return fetch(upstream + u.search, { headers: { Accept: request.headers.get("Accept") || "application/dns-message" } });
  }
  return fetch(upstream, {
    method: "POST",
    headers: { "Content-Type": request.headers.get("Content-Type") || "application/dns-message" },
    body: request.body,
  });
}

// ── API ─────────────────────────────────────────────────────────────
async function handleApi(request, url, env) {
  const db = env.DB;

  if (url.pathname === "/api/setup" && request.method === "POST") {
    if (await getPassHash(db)) return json({ error: "قبلاً تنظیم شده" }, 400);
    const { password } = await readJson(request);
    if (!password || password.length < 4) return json({ error: "حداقل ۴ کاراکتر" }, 400);
    const h = await sha256(password);
    await setSetting(db, "panel_password", h);
    return json({ success: true }, 200, { "Set-Cookie": cookie(h) });
  }
  if (url.pathname === "/api/login" && request.method === "POST") {
    const { password } = await readJson(request);
    const stored = await getPassHash(db);
    const h = await sha256(password || "");
    if (stored && safeEqual(h, stored)) return json({ success: true }, 200, { "Set-Cookie": cookie(h) });
    return json({ error: "رمز اشتباه" }, 401);
  }
  if (url.pathname === "/api/logout" && request.method === "POST") {
    return json({ success: true }, 200, { "Set-Cookie": clearCookie() });
  }
  if (!(await isAuth(request, env))) return json({ error: "Unauthorized" }, 401);

  if (url.pathname === "/api/change-password" && request.method === "POST") {
    const { current, next } = await readJson(request);
    if (!next || next.length < 4) return json({ error: "حداقل ۴ کاراکتر" }, 400);
    const stored = await getPassHash(db);
    if (stored && !safeEqual(await sha256(current || ""), stored)) return json({ error: "رمز فعلی اشتباه" }, 401);
    const nh = await sha256(next);
    await setSetting(db, "panel_password", nh);
    return json({ success: true }, 200, { "Set-Cookie": cookie(nh) });
  }

  if (url.pathname === "/api/settings" && request.method === "GET") {
    return json({
      clean_ips: await getSetting(db, "clean_ips", ""),
      proxy_ips: await getSetting(db, "proxy_ips", ""),
      default_remark: await getSetting(db, "default_remark", "Pro"),
      fragment_enabled: (await getSetting(db, "fragment_enabled", "0")) === "1",
      fragment_length: await getSetting(db, "fragment_length", "100-200"),
      fragment_interval: await getSetting(db, "fragment_interval", "10-20"),
      camouflage_name: await getSetting(db, "camouflage_name", "Northline Cloud"),
      warp_endpoints: await getSetting(db, "warp_endpoints", "engage.cloudflareclient.com:2408"),
      link_fp: (await getLinkOpts({ DB: db })).fp,
      link_alpn: (await getLinkOpts({ DB: db })).alpn,
    });
  }
  if (url.pathname === "/api/settings" && request.method === "PUT") {
    const b = await readJson(request);
    for (const [k, def] of [
      ["clean_ips", ""], ["proxy_ips", ""], ["default_remark", "Pro"],
      ["fragment_length", "100-200"], ["fragment_interval", "10-20"],
      ["camouflage_name", "Northline Cloud"], ["warp_endpoints", "engage.cloudflareclient.com:2408"],
      ["link_fp", "chrome"], ["link_alpn", "h2,http/1.1"],
    ]) {
      if (b[k] === undefined) continue;
      let v = (b[k] || def).toString().trim();
      if (k === "link_fp" && !FP_ALLOWED.includes(v)) v = def;
      if (k === "link_alpn" && !ALPN_ALLOWED.includes(v)) v = def;
      await setSetting(db, k, v);
    }
    if ("fragment_enabled" in b) {
      await setSetting(db, "fragment_enabled", b.fragment_enabled === true || b.fragment_enabled === "1" || b.fragment_enabled === 1 ? "1" : "0");
    }
    return json({ success: true });
  }

  if (url.pathname === "/api/online" && request.method === "GET") {
    await db.prepare("DELETE FROM active_connections WHERE connected_at < datetime('now','-30 minutes')").run();
    const { results } = await db.prepare("SELECT uuid, client_ip, connected_at FROM active_connections ORDER BY connected_at DESC").all();
    const by = {};
    for (const r of results || []) {
      if (!by[r.uuid]) by[r.uuid] = [];
      by[r.uuid].push({ ip: r.client_ip, at: r.connected_at });
    }
    return json({ online: by, total: (results || []).length });
  }

  if (url.pathname === "/api/users" && request.method === "GET") {
    const { results } = await db.prepare("SELECT * FROM users ORDER BY id DESC").all();
    return json({ users: results || [] });
  }

  if (url.pathname === "/api/users" && request.method === "POST") {
    try {
      const b = await readJson(request);
      const username = String(b.username || "").trim();
      if (!username || username.length < 2) return json({ error: "نام کاربری خیلی کوتاه است" }, 400);
      if (username.length > 32) return json({ error: "نام کاربری خیلی بلند است" }, 400);
      if (/[\u0000-\u001f/\\]/.test(username)) return json({ error: "نام کاربری نویسه غیرمجاز دارد" }, 400);
      const exists = await db.prepare("SELECT id FROM users WHERE username=?").bind(username).first();
      if (exists) return json({ error: "این نام کاربری تکراری است" }, 400);
      const uuid = crypto.randomUUID();
      const trojanPass = uuid.replace(/-/g, "").slice(0, 16);
      const proto = b.protocol === "trojan" ? "trojan" : b.protocol === "both" ? "both" : "vless";
      await db.prepare(
        "INSERT INTO users (username, uuid, trojan_pass, limit_gb, expiry_days, max_devices, reset_interval_days, daily_request_limit, note, protocol, used_gb, is_active) VALUES (?,?,?,?,?,?,?,?,?,?,0,1)"
      ).bind(
        username, uuid, trojanPass,
        numOrNull(b.limit_gb), numOrNull(b.expiry_days), intOrZero(b.max_devices),
        numOrNull(b.reset_interval_days), intOrZero(b.daily_request_limit),
        String(b.note || ""), proto
      ).run();
      return json({ success: true, uuid, trojan_pass: trojanPass });
    } catch (e) {
      return json({ error: "خطای دیتابیس: " + (e.message || String(e)) }, 500);
    }
  }

  if (url.pathname === "/api/users/bulk" && request.method === "POST") {
    const { usernames, action } = await readJson(request);
    if (!Array.isArray(usernames) || !usernames.length) return json({ error: "انتخاب نشده" }, 400);
    const clean = usernames.map((x) => String(x)).filter(Boolean);
    if (!clean.length) return json({ error: "انتخاب نشده" }, 400);
    const ph = clean.map(() => "?").join(",");
    if (action === "delete") await db.prepare(`DELETE FROM users WHERE username IN (${ph})`).bind(...clean).run();
    else if (action === "disable") await db.prepare(`UPDATE users SET is_active=0 WHERE username IN (${ph})`).bind(...clean).run();
    else if (action === "enable") await db.prepare(`UPDATE users SET is_active=1 WHERE username IN (${ph})`).bind(...clean).run();
    else if (action === "reset") await db.prepare(`UPDATE users SET used_gb=0, request_count=0, last_reset_at=CURRENT_TIMESTAMP, is_active=1 WHERE username IN (${ph})`).bind(...clean).run();
    else return json({ error: "نامعتبر" }, 400);
    return json({ success: true });
  }

  if (url.pathname.startsWith("/api/users/") && request.method === "DELETE") {
    const u = pathUser(url);
    if (!u) return json({ error: "نامعتبر" }, 400);
    await db.prepare("DELETE FROM users WHERE username=?").bind(u).run();
    return json({ success: true });
  }

  if (url.pathname.startsWith("/api/users/") && request.method === "PUT") {
    const u = pathUser(url);
    if (!u) return json({ error: "نامعتبر" }, 400);
    const b = await readJson(request);
    if (b.toggle !== undefined) {
      await db.prepare("UPDATE users SET is_active=CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE username=?").bind(u).run();
      return json({ success: true });
    }
    if (b.reset_usage) {
      await db.prepare("UPDATE users SET used_gb=0, request_count=0, last_reset_at=CURRENT_TIMESTAMP, is_active=1 WHERE username=?").bind(u).run();
      return json({ success: true });
    }
    if (b.regen_uuid) {
      const nu = crypto.randomUUID();
      const tp = nu.replace(/-/g, "").slice(0, 16);
      await db.prepare("UPDATE users SET uuid=?, trojan_pass=? WHERE username=?").bind(nu, tp, u).run();
      return json({ success: true, uuid: nu, trojan_pass: tp });
    }
    const proto = b.protocol === "trojan" || b.protocol === "both" || b.protocol === "vless" ? b.protocol : null;
    await db.prepare(`UPDATE users SET
      limit_gb=?, expiry_days=?, max_devices=?, reset_interval_days=?, daily_request_limit=?,
      note=COALESCE(?, note), protocol=COALESCE(?, protocol)
      WHERE username=?`).bind(
      numOrNull(b.limit_gb),
      numOrNull(b.expiry_days),
      b.max_devices !== undefined ? intOrZero(b.max_devices) : 0,
      numOrNull(b.reset_interval_days),
      b.daily_request_limit !== undefined ? intOrZero(b.daily_request_limit) : 0,
      b.note !== undefined ? String(b.note) : null,
      proto,
      u
    ).run();
    return json({ success: true });
  }

  if (url.pathname === "/api/export" && request.method === "GET") {
    const { results } = await db.prepare("SELECT * FROM users ORDER BY id").all();
    return json({ exported_at: new Date().toISOString(), version: VERSION, users: results || [] });
  }
  return json({ error: "Not Found" }, 404);
}

// ── Links ───────────────────────────────────────────────────────────
function buildVless(user, host, addr, remark, o = DEFAULT_OPTS) {
  const path = encodeURIComponent("/?ed=2560");
  return `vless://${user.uuid}@${formatHost(addrParts(addr).host)}:${addrParts(addr).port}?encryption=none&security=tls&sni=${encodeURIComponent(host)}&fp=${o.fp}&type=ws&host=${encodeURIComponent(host)}&path=${path}&alpn=${o.alpn}#${encodeURIComponent(remark)}`;
}
function buildTrojan(user, host, addr, remark, o = DEFAULT_OPTS) {
  const pass = encodeURIComponent(user.trojan_pass || user.uuid);
  const path = encodeURIComponent("/?ed=2560");
  return `trojan://${pass}@${formatHost(addrParts(addr).host)}:${addrParts(addr).port}?security=tls&sni=${encodeURIComponent(host)}&fp=${o.fp}&type=ws&host=${encodeURIComponent(host)}&path=${path}&alpn=${o.alpn}#${encodeURIComponent(remark)}`;
}
async function getAddrs(env, host) {
  const raw = await getSetting(env.DB, "clean_ips", "");
  const ips = [...new Set(raw.split(/[\s,;]+/).map((s) => s.trim()).filter((s) => s && /^[A-Za-z0-9.:[\]_-]+$/.test(s)))];
  return ips.length ? ips : [host];
}
function applySingboxFragment(tls, enabled, interval) {
  if (!enabled) return;
  tls.fragment = true;
  tls.fragment_fallback_delay = fragmentDelay(interval);
}

async function handleSub(url, env, format, forceFrag) {
  const key = pathPart(url, 2);
  const user = await env.DB.prepare("SELECT * FROM users WHERE username=? OR uuid=?").bind(key, key).first();
  if (!user) return new Response("Not Found", { status: 404 });
  if (!user.is_active) return new Response("Disabled", { status: 403 });

  const host = url.hostname;
  const addrs = await getAddrs(env, host);
  const o = await getLinkOpts(env);
  const prefix = (await getSetting(env.DB, "default_remark", "Pro")) + " | ";
  const fragOn = forceFrag || (await getSetting(env.DB, "fragment_enabled", "0")) === "1";
  const fragInt = await getSetting(env.DB, "fragment_interval", "10-20");
  const proto = user.protocol || "vless";
  const headers = { "Cache-Control": "no-store", "Profile-Update-Interval": "12" };

  const links = [];
  addrs.forEach((addr, i) => {
    const tag = addrs.length > 1 ? `${prefix}${i + 1}-` : prefix;
    if (proto === "vless" || proto === "both") links.push(buildVless(user, host, addr, `${tag}${user.username}`, o));
    if (proto === "trojan" || proto === "both") links.push(buildTrojan(user, host, addr, `${tag}${user.username}`, o));
  });

  if (format === "base64") {
    return new Response(utf8Base64(links.join("\n")), { headers: { ...headers, "Content-Type": "text/plain; charset=utf-8" } });
  }

  if (format === "clash") {
    let yaml = "proxies:\n";
    const names = [];
    let idx = 0;
    for (const addr of addrs) {
      if (proto === "vless" || proto === "both") {
        const n = `${user.username}-vless-${++idx}`;
        names.push(n);
        yaml += `  - name: ${yamlQuote(n)}\n    type: vless\n    server: ${yamlQuote(addrParts(addr).host)}\n    port: ${addrParts(addr).port}\n    uuid: ${yamlQuote(user.uuid)}\n    tls: true\n    servername: ${yamlQuote(host)}\n    client-fingerprint: ${o.fp}\n    network: ws\n    ws-opts:\n      path: "/?ed=2560"\n      headers:\n        Host: ${yamlQuote(host)}\n    alpn: [${o.alpn.split(',').join(', ')}]\n    udp: false\n`;
      }
      if (proto === "trojan" || proto === "both") {
        const n = `${user.username}-trojan-${++idx}`;
        names.push(n);
        yaml += `  - name: ${yamlQuote(n)}\n    type: trojan\n    server: ${yamlQuote(addrParts(addr).host)}\n    port: ${addrParts(addr).port}\n    password: ${yamlQuote(user.trojan_pass || user.uuid)}\n    tls: true\n    sni: ${yamlQuote(host)}\n    client-fingerprint: ${o.fp}\n    network: ws\n    ws-opts:\n      path: "/?ed=2560"\n      headers:\n        Host: ${yamlQuote(host)}\n    alpn: [${o.alpn.split(',').join(', ')}]\n    udp: false\n`;
      }
    }
    yaml += `proxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n${names.map((n) => "      - " + yamlQuote(n)).join("\n")}\n  - name: AUTO\n    type: url-test\n    proxies:\n${names.map((n) => "      - " + yamlQuote(n)).join("\n")}\n    url: http://www.gstatic.com/generate_204\n    interval: 300\nrules:\n  - GEOIP,IR,DIRECT\n  - DOMAIN-SUFFIX,ir,DIRECT\n  - MATCH,PROXY\n`;
    return new Response(yaml, { headers: { ...headers, "Content-Type": "text/yaml; charset=utf-8" } });
  }

  if (format === "singbox") {
    const outbounds = [];
    let idx = 0;
    for (const addr of addrs) {
      if (proto === "vless" || proto === "both") {
        const tag = `${user.username}-vless-${++idx}`;
        const ob = {
          type: "vless", tag, server: addrParts(addr).host, server_port: addrParts(addr).port, uuid: user.uuid,
          tls: { enabled: true, server_name: host, utls: { enabled: true, fingerprint: o.fp }, alpn: o.alpn.split(",") },
          transport: { type: "ws", path: "/?ed=2560", headers: { Host: host } },
        };
        applySingboxFragment(ob.tls, fragOn, fragInt);
        outbounds.push(ob);
      }
      if (proto === "trojan" || proto === "both") {
        const tag = `${user.username}-trojan-${++idx}`;
        const ob = {
          type: "trojan", tag, server: addrParts(addr).host, server_port: addrParts(addr).port, password: user.trojan_pass || user.uuid,
          tls: { enabled: true, server_name: host, utls: { enabled: true, fingerprint: o.fp }, alpn: o.alpn.split(",") },
          transport: { type: "ws", path: "/?ed=2560", headers: { Host: host } },
        };
        applySingboxFragment(ob.tls, fragOn, fragInt);
        outbounds.push(ob);
      }
    }
    const tags = outbounds.map((o) => o.tag);
    const config = {
      outbounds: [
        ...outbounds,
        { type: "selector", tag: "proxy", outbounds: tags },
        { type: "urltest", tag: "auto", outbounds: tags, url: "http://www.gstatic.com/generate_204", interval: "5m" },
        { type: "direct", tag: "direct" },
        { type: "block", tag: "block" },
      ],
      route: { rules: [{ geoip: ["ir"], outbound: "direct" }, { domain_suffix: [".ir"], outbound: "direct" }], final: "proxy" },
    };
    return new Response(JSON.stringify(config, null, 2), { headers: { ...headers, "Content-Type": "application/json; charset=utf-8" } });
  }
  return new Response("Not Found", { status: 404 });
}

function pathPart(url, index) {
  try { return decodeURIComponent(url.pathname.split("/")[index] || ""); }
  catch { return ""; }
}

async function handleWarp(url, env) {
  const endpoints = (await getSetting(env.DB, "warp_endpoints", "engage.cloudflareclient.com:2408"))
    .split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
  const configs = endpoints.map((ep, i) => {
    const [host, port] = splitHostPort(ep, 2408);
    return `# Warp endpoint ${i + 1}
# Replace the private key with a key from the official Warp client or wgcf.
[Interface]
PrivateKey = REPLACE_WITH_YOUR_WARP_PRIVATE_KEY
Address = 172.16.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${host}:${port}
PersistentKeepalive = 25
`;
  });
  return new Response(configs.join("\n---\n"), {
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

const QR_SOURCE = "/* QR code generator - Copyright (c) 2009 Kazuhiko Arase, MIT license (http://www.opensource.org/licenses/mit-license.php). QR Code is a registered trademark of DENSO WAVE INCORPORATED. */\n(function(g){var M={},C={};function R(n){n=String(n).replace(/^\\.\\//,\"\").replace(/\\.js$/,\"\");if(!C[n]){var m={exports:{}};C[n]=m;M[n](m,m.exports,R);}return C[n].exports;}\nM[\"QRMode\"]=function(module,exports,require){module.exports = {\n    MODE_NUMBER :       1 << 0,\n    MODE_ALPHA_NUM :    1 << 1,\n    MODE_8BIT_BYTE :    1 << 2,\n    MODE_KANJI :        1 << 3\n};\n\n};\nM[\"QRErrorCorrectLevel\"]=function(module,exports,require){module.exports = {\n\tL : 1,\n\tM : 0,\n\tQ : 3,\n\tH : 2\n};\n\n};\nM[\"QRMaskPattern\"]=function(module,exports,require){module.exports = {\n\tPATTERN000 : 0,\n\tPATTERN001 : 1,\n\tPATTERN010 : 2,\n\tPATTERN011 : 3,\n\tPATTERN100 : 4,\n\tPATTERN101 : 5,\n\tPATTERN110 : 6,\n\tPATTERN111 : 7\n};\n\n};\nM[\"QRMath\"]=function(module,exports,require){var QRMath = {\n\tglog : function(n) {\n\t\tif (n < 1) {\n\t\t\tthrow new Error(\"glog(\" + n + \")\");\n\t\t}\n\t\treturn QRMath.LOG_TABLE[n];\n\t},\n\tgexp : function(n) {\n\t\twhile (n < 0) {\n\t\t\tn += 255;\n\t\t}\n\t\twhile (n >= 256) {\n\t\t\tn -= 255;\n\t\t}\n\t\treturn QRMath.EXP_TABLE[n];\n\t},\n\tEXP_TABLE : new Array(256),\n\tLOG_TABLE : new Array(256)\n};\nfor (var i = 0; i < 8; i++) {\n\tQRMath.EXP_TABLE[i] = 1 << i;\n}\nfor (var i = 8; i < 256; i++) {\n\tQRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4]\n\t\t^ QRMath.EXP_TABLE[i - 5]\n\t\t^ QRMath.EXP_TABLE[i - 6]\n\t\t^ QRMath.EXP_TABLE[i - 8];\n}\nfor (var i = 0; i < 255; i++) {\n\tQRMath.LOG_TABLE[QRMath.EXP_TABLE[i] ] = i;\n}\nmodule.exports = QRMath;\n\n};\nM[\"QRPolynomial\"]=function(module,exports,require){var QRMath = require('./QRMath');\nfunction QRPolynomial(num, shift) {\n\tif (num.length === undefined) {\n\t\tthrow new Error(num.length + \"/\" + shift);\n\t}\n\tvar offset = 0;\n\twhile (offset < num.length && num[offset] === 0) {\n\t\toffset++;\n\t}\n\tthis.num = new Array(num.length - offset + shift);\n\tfor (var i = 0; i < num.length - offset; i++) {\n\t\tthis.num[i] = num[i + offset];\n\t}\n}\nQRPolynomial.prototype = {\n\tget : function(index) {\n\t\treturn this.num[index];\n\t},\n\tgetLength : function() {\n\t\treturn this.num.length;\n\t},\n\tmultiply : function(e) {\n\t\tvar num = new Array(this.getLength() + e.getLength() - 1);\n\t\tfor (var i = 0; i < this.getLength(); i++) {\n\t\t\tfor (var j = 0; j < e.getLength(); j++) {\n\t\t\t\tnum[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i) ) + QRMath.glog(e.get(j) ) );\n\t\t\t}\n\t\t}\n\t\treturn new QRPolynomial(num, 0);\n\t},\n\tmod : function(e) {\n\t\tif (this.getLength() - e.getLength() < 0) {\n\t\t\treturn this;\n\t\t}\n\t\tvar ratio = QRMath.glog(this.get(0) ) - QRMath.glog(e.get(0) );\n\t\tvar num = new Array(this.getLength() );\n\t\tfor (var i = 0; i < this.getLength(); i++) {\n\t\t\tnum[i] = this.get(i);\n\t\t}\n\t\tfor (var x = 0; x < e.getLength(); x++) {\n\t\t\tnum[x] ^= QRMath.gexp(QRMath.glog(e.get(x) ) + ratio);\n\t\t}\n\t\treturn new QRPolynomial(num, 0).mod(e);\n\t}\n};\nmodule.exports = QRPolynomial;\n\n};\nM[\"QRUtil\"]=function(module,exports,require){var QRMode = require('./QRMode');\nvar QRPolynomial = require('./QRPolynomial');\nvar QRMath = require('./QRMath');\nvar QRMaskPattern = require('./QRMaskPattern');\nvar QRUtil = {\n    PATTERN_POSITION_TABLE : [\n        [],\n        [6, 18],\n        [6, 22],\n        [6, 26],\n        [6, 30],\n        [6, 34],\n        [6, 22, 38],\n        [6, 24, 42],\n        [6, 26, 46],\n        [6, 28, 50],\n        [6, 30, 54],        \n        [6, 32, 58],\n        [6, 34, 62],\n        [6, 26, 46, 66],\n        [6, 26, 48, 70],\n        [6, 26, 50, 74],\n        [6, 30, 54, 78],\n        [6, 30, 56, 82],\n        [6, 30, 58, 86],\n        [6, 34, 62, 90],\n        [6, 28, 50, 72, 94],\n        [6, 26, 50, 74, 98],\n        [6, 30, 54, 78, 102],\n        [6, 28, 54, 80, 106],\n        [6, 32, 58, 84, 110],\n        [6, 30, 58, 86, 114],\n        [6, 34, 62, 90, 118],\n        [6, 26, 50, 74, 98, 122],\n        [6, 30, 54, 78, 102, 126],\n        [6, 26, 52, 78, 104, 130],\n        [6, 30, 56, 82, 108, 134],\n        [6, 34, 60, 86, 112, 138],\n        [6, 30, 58, 86, 114, 142],\n        [6, 34, 62, 90, 118, 146],\n        [6, 30, 54, 78, 102, 126, 150],\n        [6, 24, 50, 76, 102, 128, 154],\n        [6, 28, 54, 80, 106, 132, 158],\n        [6, 32, 58, 84, 110, 136, 162],\n        [6, 26, 54, 82, 110, 138, 166],\n        [6, 30, 58, 86, 114, 142, 170]\n    ],\n    G15 : (1 << 10) | (1 << 8) | (1 << 5) | (1 << 4) | (1 << 2) | (1 << 1) | (1 << 0),\n    G18 : (1 << 12) | (1 << 11) | (1 << 10) | (1 << 9) | (1 << 8) | (1 << 5) | (1 << 2) | (1 << 0),\n    G15_MASK : (1 << 14) | (1 << 12) | (1 << 10)    | (1 << 4) | (1 << 1),\n    getBCHTypeInfo : function(data) {\n        var d = data << 10;\n        while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15) >= 0) {\n            d ^= (QRUtil.G15 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G15) ) );    \n        }\n        return ( (data << 10) | d) ^ QRUtil.G15_MASK;\n    },\n    getBCHTypeNumber : function(data) {\n        var d = data << 12;\n        while (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18) >= 0) {\n            d ^= (QRUtil.G18 << (QRUtil.getBCHDigit(d) - QRUtil.getBCHDigit(QRUtil.G18) ) );    \n        }\n        return (data << 12) | d;\n    },\n    getBCHDigit : function(data) {\n        var digit = 0;\n        while (data !== 0) {\n            digit++;\n            data >>>= 1;\n        }\n        return digit;\n    },\n    getPatternPosition : function(typeNumber) {\n        return QRUtil.PATTERN_POSITION_TABLE[typeNumber - 1];\n    },\n    getMask : function(maskPattern, i, j) {\n        switch (maskPattern) {\n        case QRMaskPattern.PATTERN000 : return (i + j) % 2 === 0;\n        case QRMaskPattern.PATTERN001 : return i % 2 === 0;\n        case QRMaskPattern.PATTERN010 : return j % 3 === 0;\n        case QRMaskPattern.PATTERN011 : return (i + j) % 3 === 0;\n        case QRMaskPattern.PATTERN100 : return (Math.floor(i / 2) + Math.floor(j / 3) ) % 2 === 0;\n        case QRMaskPattern.PATTERN101 : return (i * j) % 2 + (i * j) % 3 === 0;\n        case QRMaskPattern.PATTERN110 : return ( (i * j) % 2 + (i * j) % 3) % 2 === 0;\n        case QRMaskPattern.PATTERN111 : return ( (i * j) % 3 + (i + j) % 2) % 2 === 0;\n        default :\n            throw new Error(\"bad maskPattern:\" + maskPattern);\n        }\n    },\n    getErrorCorrectPolynomial : function(errorCorrectLength) {\n        var a = new QRPolynomial([1], 0);\n        for (var i = 0; i < errorCorrectLength; i++) {\n            a = a.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0) );\n        }\n        return a;\n    },\n    getLengthInBits : function(mode, type) {\n        if (1 <= type && type < 10) {\n            switch(mode) {\n            case QRMode.MODE_NUMBER     : return 10;\n            case QRMode.MODE_ALPHA_NUM  : return 9;\n            case QRMode.MODE_8BIT_BYTE  : return 8;\n            case QRMode.MODE_KANJI      : return 8;\n            default :\n                throw new Error(\"mode:\" + mode);\n            }\n        } else if (type < 27) {\n            switch(mode) {\n            case QRMode.MODE_NUMBER     : return 12;\n            case QRMode.MODE_ALPHA_NUM  : return 11;\n            case QRMode.MODE_8BIT_BYTE  : return 16;\n            case QRMode.MODE_KANJI      : return 10;\n            default :\n                throw new Error(\"mode:\" + mode);\n            }\n        } else if (type < 41) {\n            switch(mode) {\n            case QRMode.MODE_NUMBER     : return 14;\n            case QRMode.MODE_ALPHA_NUM  : return 13;\n            case QRMode.MODE_8BIT_BYTE  : return 16;\n            case QRMode.MODE_KANJI      : return 12;\n            default :\n                throw new Error(\"mode:\" + mode);\n            }\n        } else {\n            throw new Error(\"type:\" + type);\n        }\n    },\n    getLostPoint : function(qrCode) {\n        var moduleCount = qrCode.getModuleCount();\n        var lostPoint = 0;\n        var row = 0; \n        var col = 0;\n        for (row = 0; row < moduleCount; row++) {\n            for (col = 0; col < moduleCount; col++) {\n                var sameCount = 0;\n                var dark = qrCode.isDark(row, col);\n                for (var r = -1; r <= 1; r++) {\n                    if (row + r < 0 || moduleCount <= row + r) {\n                        continue;\n                    }\n                    for (var c = -1; c <= 1; c++) {\n                        if (col + c < 0 || moduleCount <= col + c) {\n                            continue;\n                        }\n                        if (r === 0 && c === 0) {\n                            continue;\n                        }\n                        if (dark === qrCode.isDark(row + r, col + c) ) {\n                            sameCount++;\n                        }\n                    }\n                }\n                if (sameCount > 5) {\n                    lostPoint += (3 + sameCount - 5);\n                }\n            }\n        }\n        for (row = 0; row < moduleCount - 1; row++) {\n            for (col = 0; col < moduleCount - 1; col++) {\n                var count = 0;\n                if (qrCode.isDark(row,     col    ) ) count++;\n                if (qrCode.isDark(row + 1, col    ) ) count++;\n                if (qrCode.isDark(row,     col + 1) ) count++;\n                if (qrCode.isDark(row + 1, col + 1) ) count++;\n                if (count === 0 || count === 4) {\n                    lostPoint += 3;\n                }\n            }\n        }\n        for (row = 0; row < moduleCount; row++) {\n            for (col = 0; col < moduleCount - 6; col++) {\n                if (qrCode.isDark(row, col) && \n                        !qrCode.isDark(row, col + 1) && \n                         qrCode.isDark(row, col + 2) && \n                         qrCode.isDark(row, col + 3) && \n                         qrCode.isDark(row, col + 4) && \n                        !qrCode.isDark(row, col + 5) && \n                         qrCode.isDark(row, col + 6) ) {\n                    lostPoint += 40;\n                }\n            }\n        }\n        for (col = 0; col < moduleCount; col++) {\n            for (row = 0; row < moduleCount - 6; row++) {\n                if (qrCode.isDark(row, col) &&\n                        !qrCode.isDark(row + 1, col) &&\n                         qrCode.isDark(row + 2, col) &&\n                         qrCode.isDark(row + 3, col) &&\n                         qrCode.isDark(row + 4, col) &&\n                        !qrCode.isDark(row + 5, col) &&\n                         qrCode.isDark(row + 6, col) ) {\n                    lostPoint += 40;\n                }\n            }\n        }\n        var darkCount = 0;\n        for (col = 0; col < moduleCount; col++) {\n            for (row = 0; row < moduleCount; row++) {\n                if (qrCode.isDark(row, col) ) {\n                    darkCount++;\n                }\n            }\n        }\n        var ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;\n        lostPoint += ratio * 10;\n        return lostPoint;       \n    }\n};\nmodule.exports = QRUtil;\n\n};\nM[\"QRRSBlock\"]=function(module,exports,require){var QRErrorCorrectLevel = require('./QRErrorCorrectLevel');\nfunction QRRSBlock(totalCount, dataCount) {\n\tthis.totalCount = totalCount;\n\tthis.dataCount  = dataCount;\n}\nQRRSBlock.RS_BLOCK_TABLE = [\n\t[1, 26, 19],\n\t[1, 26, 16],\n\t[1, 26, 13],\n\t[1, 26, 9],\n\t[1, 44, 34],\n\t[1, 44, 28],\n\t[1, 44, 22],\n\t[1, 44, 16],\n\t[1, 70, 55],\n\t[1, 70, 44],\n\t[2, 35, 17],\n\t[2, 35, 13],\n\t[1, 100, 80],\n\t[2, 50, 32],\n\t[2, 50, 24],\n\t[4, 25, 9],\n\t[1, 134, 108],\n\t[2, 67, 43],\n\t[2, 33, 15, 2, 34, 16],\n\t[2, 33, 11, 2, 34, 12],\n\t[2, 86, 68],\n\t[4, 43, 27],\n\t[4, 43, 19],\n\t[4, 43, 15],\n\t[2, 98, 78],\n\t[4, 49, 31],\n\t[2, 32, 14, 4, 33, 15],\n\t[4, 39, 13, 1, 40, 14],\n\t[2, 121, 97],\n\t[2, 60, 38, 2, 61, 39],\n\t[4, 40, 18, 2, 41, 19],\n\t[4, 40, 14, 2, 41, 15],\n\t[2, 146, 116],\n\t[3, 58, 36, 2, 59, 37],\n\t[4, 36, 16, 4, 37, 17],\n\t[4, 36, 12, 4, 37, 13],\n\t[2, 86, 68, 2, 87, 69],\n\t[4, 69, 43, 1, 70, 44],\n\t[6, 43, 19, 2, 44, 20],\n\t[6, 43, 15, 2, 44, 16],\n\t[4, 101, 81],\n\t[1, 80, 50, 4, 81, 51],\n\t[4, 50, 22, 4, 51, 23],\n\t[3, 36, 12, 8, 37, 13],\n\t[2, 116, 92, 2, 117, 93],\n\t[6, 58, 36, 2, 59, 37],\n\t[4, 46, 20, 6, 47, 21],\n\t[7, 42, 14, 4, 43, 15],\n\t[4, 133, 107],\n\t[8, 59, 37, 1, 60, 38],\n\t[8, 44, 20, 4, 45, 21],\n\t[12, 33, 11, 4, 34, 12],\n\t[3, 145, 115, 1, 146, 116],\n\t[4, 64, 40, 5, 65, 41],\n\t[11, 36, 16, 5, 37, 17],\n\t[11, 36, 12, 5, 37, 13],\n\t[5, 109, 87, 1, 110, 88],\n\t[5, 65, 41, 5, 66, 42],\n\t[5, 54, 24, 7, 55, 25],\n\t[11, 36, 12],\n\t[5, 122, 98, 1, 123, 99],\n\t[7, 73, 45, 3, 74, 46],\n\t[15, 43, 19, 2, 44, 20],\n\t[3, 45, 15, 13, 46, 16],\n\t[1, 135, 107, 5, 136, 108],\n\t[10, 74, 46, 1, 75, 47],\n\t[1, 50, 22, 15, 51, 23],\n\t[2, 42, 14, 17, 43, 15],\n\t[5, 150, 120, 1, 151, 121],\n\t[9, 69, 43, 4, 70, 44],\n\t[17, 50, 22, 1, 51, 23],\n\t[2, 42, 14, 19, 43, 15],\n\t[3, 141, 113, 4, 142, 114],\n\t[3, 70, 44, 11, 71, 45],\n\t[17, 47, 21, 4, 48, 22],\n\t[9, 39, 13, 16, 40, 14],\n\t[3, 135, 107, 5, 136, 108],\n\t[3, 67, 41, 13, 68, 42],\n\t[15, 54, 24, 5, 55, 25],\n\t[15, 43, 15, 10, 44, 16],\n\t[4, 144, 116, 4, 145, 117],\n\t[17, 68, 42],\n\t[17, 50, 22, 6, 51, 23],\n\t[19, 46, 16, 6, 47, 17],\n\t[2, 139, 111, 7, 140, 112],\n\t[17, 74, 46],\n\t[7, 54, 24, 16, 55, 25],\n\t[34, 37, 13],\n\t[4, 151, 121, 5, 152, 122],\n\t[4, 75, 47, 14, 76, 48],\n\t[11, 54, 24, 14, 55, 25],\n\t[16, 45, 15, 14, 46, 16],\n\t[6, 147, 117, 4, 148, 118],\n\t[6, 73, 45, 14, 74, 46],\n\t[11, 54, 24, 16, 55, 25],\n\t[30, 46, 16, 2, 47, 17],\n\t[8, 132, 106, 4, 133, 107],\n\t[8, 75, 47, 13, 76, 48],\n\t[7, 54, 24, 22, 55, 25],\n\t[22, 45, 15, 13, 46, 16],\n\t[10, 142, 114, 2, 143, 115],\n\t[19, 74, 46, 4, 75, 47],\n\t[28, 50, 22, 6, 51, 23],\n\t[33, 46, 16, 4, 47, 17],\n\t[8, 152, 122, 4, 153, 123],\n\t[22, 73, 45, 3, 74, 46],\n\t[8, 53, 23, 26, 54, 24],\n\t[12, 45, 15, 28, 46, 16],\n\t[3, 147, 117, 10, 148, 118],\n\t[3, 73, 45, 23, 74, 46],\n\t[4, 54, 24, 31, 55, 25],\n\t[11, 45, 15, 31, 46, 16],\n\t[7, 146, 116, 7, 147, 117],\n\t[21, 73, 45, 7, 74, 46],\n\t[1, 53, 23, 37, 54, 24],\n\t[19, 45, 15, 26, 46, 16],\n\t[5, 145, 115, 10, 146, 116],\n\t[19, 75, 47, 10, 76, 48],\n\t[15, 54, 24, 25, 55, 25],\n\t[23, 45, 15, 25, 46, 16],\n\t[13, 145, 115, 3, 146, 116],\n\t[2, 74, 46, 29, 75, 47],\n\t[42, 54, 24, 1, 55, 25],\n\t[23, 45, 15, 28, 46, 16],\n\t[17, 145, 115],\n\t[10, 74, 46, 23, 75, 47],\n\t[10, 54, 24, 35, 55, 25],\n\t[19, 45, 15, 35, 46, 16],\n\t[17, 145, 115, 1, 146, 116],\n\t[14, 74, 46, 21, 75, 47],\n\t[29, 54, 24, 19, 55, 25],\n\t[11, 45, 15, 46, 46, 16],\n\t[13, 145, 115, 6, 146, 116],\n\t[14, 74, 46, 23, 75, 47],\n\t[44, 54, 24, 7, 55, 25],\n\t[59, 46, 16, 1, 47, 17],\n\t[12, 151, 121, 7, 152, 122],\n\t[12, 75, 47, 26, 76, 48],\n\t[39, 54, 24, 14, 55, 25],\n\t[22, 45, 15, 41, 46, 16],\n\t[6, 151, 121, 14, 152, 122],\n\t[6, 75, 47, 34, 76, 48],\n\t[46, 54, 24, 10, 55, 25],\n\t[2, 45, 15, 64, 46, 16],\n\t[17, 152, 122, 4, 153, 123],\n\t[29, 74, 46, 14, 75, 47],\n\t[49, 54, 24, 10, 55, 25],\n\t[24, 45, 15, 46, 46, 16],\n\t[4, 152, 122, 18, 153, 123],\n\t[13, 74, 46, 32, 75, 47],\n\t[48, 54, 24, 14, 55, 25],\n\t[42, 45, 15, 32, 46, 16],\n\t[20, 147, 117, 4, 148, 118],\n\t[40, 75, 47, 7, 76, 48],\n\t[43, 54, 24, 22, 55, 25],\n\t[10, 45, 15, 67, 46, 16],\n\t[19, 148, 118, 6, 149, 119],\n\t[18, 75, 47, 31, 76, 48],\n\t[34, 54, 24, 34, 55, 25],\n\t[20, 45, 15, 61, 46, 16]\n];\nQRRSBlock.getRSBlocks = function(typeNumber, errorCorrectLevel) {\n\tvar rsBlock = QRRSBlock.getRsBlockTable(typeNumber, errorCorrectLevel);\n\tif (rsBlock === undefined) {\n\t\tthrow new Error(\"bad rs block @ typeNumber:\" + typeNumber + \"/errorCorrectLevel:\" + errorCorrectLevel);\n\t}\n\tvar length = rsBlock.length / 3;\n\tvar list = [];\n\tfor (var i = 0; i < length; i++) {\n\t\tvar count = rsBlock[i * 3 + 0];\n\t\tvar totalCount = rsBlock[i * 3 + 1];\n\t\tvar dataCount  = rsBlock[i * 3 + 2];\n\t\tfor (var j = 0; j < count; j++) {\n\t\t\tlist.push(new QRRSBlock(totalCount, dataCount) );\t\n\t\t}\n\t}\n\treturn list;\n};\nQRRSBlock.getRsBlockTable = function(typeNumber, errorCorrectLevel) {\n\tswitch(errorCorrectLevel) {\n\tcase QRErrorCorrectLevel.L :\n\t\treturn QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];\n\tcase QRErrorCorrectLevel.M :\n\t\treturn QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];\n\tcase QRErrorCorrectLevel.Q :\n\t\treturn QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];\n\tcase QRErrorCorrectLevel.H :\n\t\treturn QRRSBlock.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];\n\tdefault :\n\t\treturn undefined;\n\t}\n};\nmodule.exports = QRRSBlock;\n\n};\nM[\"QRBitBuffer\"]=function(module,exports,require){function QRBitBuffer() {\n\tthis.buffer = [];\n\tthis.length = 0;\n}\nQRBitBuffer.prototype = {\n\tget : function(index) {\n\t\tvar bufIndex = Math.floor(index / 8);\n\t\treturn ( (this.buffer[bufIndex] >>> (7 - index % 8) ) & 1) == 1;\n\t},\n\tput : function(num, length) {\n\t\tfor (var i = 0; i < length; i++) {\n\t\t\tthis.putBit( ( (num >>> (length - i - 1) ) & 1) == 1);\n\t\t}\n\t},\n\tgetLengthInBits : function() {\n\t\treturn this.length;\n\t},\n\tputBit : function(bit) {\n\t\tvar bufIndex = Math.floor(this.length / 8);\n\t\tif (this.buffer.length <= bufIndex) {\n\t\t\tthis.buffer.push(0);\n\t\t}\n\t\tif (bit) {\n\t\t\tthis.buffer[bufIndex] |= (0x80 >>> (this.length % 8) );\n\t\t}\n\t\tthis.length++;\n\t}\n};\nmodule.exports = QRBitBuffer;\n\n};\nM[\"QR8bitByte\"]=function(module,exports,require){var QRMode = require('./QRMode');\nfunction QR8bitByte(data) {\n\tthis.mode = QRMode.MODE_8BIT_BYTE;\n\tthis.data = data;\n}\nQR8bitByte.prototype = {\n\tgetLength : function() {\n\t\treturn this.data.length;\n\t},\n\twrite : function(buffer) {\n\t\tfor (var i = 0; i < this.data.length; i++) {\n\t\t\tbuffer.put(this.data.charCodeAt(i), 8);\n\t\t}\n\t}\n};\nmodule.exports = QR8bitByte;\n\n};\nM[\"index\"]=function(module,exports,require){\nvar QR8bitByte = require('./QR8bitByte');\nvar QRUtil = require('./QRUtil');\nvar QRPolynomial = require('./QRPolynomial');\nvar QRRSBlock = require('./QRRSBlock');\nvar QRBitBuffer = require('./QRBitBuffer');\nfunction QRCode(typeNumber, errorCorrectLevel) {\n\tthis.typeNumber = typeNumber;\n\tthis.errorCorrectLevel = errorCorrectLevel;\n\tthis.modules = null;\n\tthis.moduleCount = 0;\n\tthis.dataCache = null;\n\tthis.dataList = [];\n}\nQRCode.prototype = {\n\taddData : function(data) {\n\t\tvar newData = new QR8bitByte(data);\n\t\tthis.dataList.push(newData);\n\t\tthis.dataCache = null;\n\t},\n\tisDark : function(row, col) {\n\t\tif (row < 0 || this.moduleCount <= row || col < 0 || this.moduleCount <= col) {\n\t\t\tthrow new Error(row + \",\" + col);\n\t\t}\n\t\treturn this.modules[row][col];\n\t},\n\tgetModuleCount : function() {\n\t\treturn this.moduleCount;\n\t},\n\tmake : function() {\n\t\tif (this.typeNumber < 1 ){\n\t\t\tvar typeNumber = 1;\n\t\t\tfor (typeNumber = 1; typeNumber < 40; typeNumber++) {\n\t\t\t\tvar rsBlocks = QRRSBlock.getRSBlocks(typeNumber, this.errorCorrectLevel);\n\t\t\t\tvar buffer = new QRBitBuffer();\n\t\t\t\tvar totalDataCount = 0;\n\t\t\t\tfor (var i = 0; i < rsBlocks.length; i++) {\n\t\t\t\t\ttotalDataCount += rsBlocks[i].dataCount;\n\t\t\t\t}\n\t\t\t\tfor (var x = 0; x < this.dataList.length; x++) {\n\t\t\t\t\tvar data = this.dataList[x];\n\t\t\t\t\tbuffer.put(data.mode, 4);\n\t\t\t\t\tbuffer.put(data.getLength(), QRUtil.getLengthInBits(data.mode, typeNumber) );\n\t\t\t\t\tdata.write(buffer);\n\t\t\t\t}\n\t\t\t\tif (buffer.getLengthInBits() <= totalDataCount * 8)\n\t\t\t\t\tbreak;\n\t\t\t}\n\t\t\tthis.typeNumber = typeNumber;\n\t\t}\n\t\tthis.makeImpl(false, this.getBestMaskPattern() );\n\t},\n\tmakeImpl : function(test, maskPattern) {\n\t\tthis.moduleCount = this.typeNumber * 4 + 17;\n\t\tthis.modules = new Array(this.moduleCount);\n\t\tfor (var row = 0; row < this.moduleCount; row++) {\n\t\t\tthis.modules[row] = new Array(this.moduleCount);\n\t\t\tfor (var col = 0; col < this.moduleCount; col++) {\n\t\t\t\tthis.modules[row][col] = null;//(col + row) % 3;\n\t\t\t}\n\t\t}\n\t\tthis.setupPositionProbePattern(0, 0);\n\t\tthis.setupPositionProbePattern(this.moduleCount - 7, 0);\n\t\tthis.setupPositionProbePattern(0, this.moduleCount - 7);\n\t\tthis.setupPositionAdjustPattern();\n\t\tthis.setupTimingPattern();\n\t\tthis.setupTypeInfo(test, maskPattern);\n\t\tif (this.typeNumber >= 7) {\n\t\t\tthis.setupTypeNumber(test);\n\t\t}\n\t\tif (this.dataCache === null) {\n\t\t\tthis.dataCache = QRCode.createData(this.typeNumber, this.errorCorrectLevel, this.dataList);\n\t\t}\n\t\tthis.mapData(this.dataCache, maskPattern);\n\t},\n\tsetupPositionProbePattern : function(row, col)  {\n\t\tfor (var r = -1; r <= 7; r++) {\n\t\t\tif (row + r <= -1 || this.moduleCount <= row + r) continue;\n\t\t\tfor (var c = -1; c <= 7; c++) {\n\t\t\t\tif (col + c <= -1 || this.moduleCount <= col + c) continue;\n\t\t\t\tif ( (0 <= r && r <= 6 && (c === 0 || c === 6) ) || \n                     (0 <= c && c <= 6 && (r === 0 || r === 6) ) || \n                     (2 <= r && r <= 4 && 2 <= c && c <= 4) ) {\n\t\t\t\t\tthis.modules[row + r][col + c] = true;\n\t\t\t\t} else {\n\t\t\t\t\tthis.modules[row + r][col + c] = false;\n\t\t\t\t}\n\t\t\t}\t\t\n\t\t}\t\t\n\t},\n\tgetBestMaskPattern : function() {\n\t\tvar minLostPoint = 0;\n\t\tvar pattern = 0;\n\t\tfor (var i = 0; i < 8; i++) {\n\t\t\tthis.makeImpl(true, i);\n\t\t\tvar lostPoint = QRUtil.getLostPoint(this);\n\t\t\tif (i === 0 || minLostPoint >  lostPoint) {\n\t\t\t\tminLostPoint = lostPoint;\n\t\t\t\tpattern = i;\n\t\t\t}\n\t\t}\n\t\treturn pattern;\n\t},\n\tcreateMovieClip : function(target_mc, instance_name, depth) {\n\t\tvar qr_mc = target_mc.createEmptyMovieClip(instance_name, depth);\n\t\tvar cs = 1;\n\t\tthis.make();\n\t\tfor (var row = 0; row < this.modules.length; row++) {\n\t\t\tvar y = row * cs;\n\t\t\tfor (var col = 0; col < this.modules[row].length; col++) {\n\t\t\t\tvar x = col * cs;\n\t\t\t\tvar dark = this.modules[row][col];\n\t\t\t\tif (dark) {\n\t\t\t\t\tqr_mc.beginFill(0, 100);\n\t\t\t\t\tqr_mc.moveTo(x, y);\n\t\t\t\t\tqr_mc.lineTo(x + cs, y);\n\t\t\t\t\tqr_mc.lineTo(x + cs, y + cs);\n\t\t\t\t\tqr_mc.lineTo(x, y + cs);\n\t\t\t\t\tqr_mc.endFill();\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t\treturn qr_mc;\n\t},\n\tsetupTimingPattern : function() {\n\t\tfor (var r = 8; r < this.moduleCount - 8; r++) {\n\t\t\tif (this.modules[r][6] !== null) {\n\t\t\t\tcontinue;\n\t\t\t}\n\t\t\tthis.modules[r][6] = (r % 2 === 0);\n\t\t}\n\t\tfor (var c = 8; c < this.moduleCount - 8; c++) {\n\t\t\tif (this.modules[6][c] !== null) {\n\t\t\t\tcontinue;\n\t\t\t}\n\t\t\tthis.modules[6][c] = (c % 2 === 0);\n\t\t}\n\t},\n\tsetupPositionAdjustPattern : function() {\n\t\tvar pos = QRUtil.getPatternPosition(this.typeNumber);\n\t\tfor (var i = 0; i < pos.length; i++) {\n\t\t\tfor (var j = 0; j < pos.length; j++) {\n\t\t\t\tvar row = pos[i];\n\t\t\t\tvar col = pos[j];\n\t\t\t\tif (this.modules[row][col] !== null) {\n\t\t\t\t\tcontinue;\n\t\t\t\t}\n\t\t\t\tfor (var r = -2; r <= 2; r++) {\n\t\t\t\t\tfor (var c = -2; c <= 2; c++) {\n\t\t\t\t\t\tif (Math.abs(r) === 2 || \n                            Math.abs(c) === 2 ||\n                            (r === 0 && c === 0) ) {\n\t\t\t\t\t\t\tthis.modules[row + r][col + c] = true;\n\t\t\t\t\t\t} else {\n\t\t\t\t\t\t\tthis.modules[row + r][col + c] = false;\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t},\n\tsetupTypeNumber : function(test) {\n\t\tvar bits = QRUtil.getBCHTypeNumber(this.typeNumber);\n        var mod;\n\t\tfor (var i = 0; i < 18; i++) {\n\t\t\tmod = (!test && ( (bits >> i) & 1) === 1);\n\t\t\tthis.modules[Math.floor(i / 3)][i % 3 + this.moduleCount - 8 - 3] = mod;\n\t\t}\n\t\tfor (var x = 0; x < 18; x++) {\n\t\t\tmod = (!test && ( (bits >> x) & 1) === 1);\n\t\t\tthis.modules[x % 3 + this.moduleCount - 8 - 3][Math.floor(x / 3)] = mod;\n\t\t}\n\t},\n\tsetupTypeInfo : function(test, maskPattern) {\n\t\tvar data = (this.errorCorrectLevel << 3) | maskPattern;\n\t\tvar bits = QRUtil.getBCHTypeInfo(data);\n        var mod;\n\t\tfor (var v = 0; v < 15; v++) {\n\t\t\tmod = (!test && ( (bits >> v) & 1) === 1);\n\t\t\tif (v < 6) {\n\t\t\t\tthis.modules[v][8] = mod;\n\t\t\t} else if (v < 8) {\n\t\t\t\tthis.modules[v + 1][8] = mod;\n\t\t\t} else {\n\t\t\t\tthis.modules[this.moduleCount - 15 + v][8] = mod;\n\t\t\t}\n\t\t}\n\t\tfor (var h = 0; h < 15; h++) {\n\t\t\tmod = (!test && ( (bits >> h) & 1) === 1);\n\t\t\tif (h < 8) {\n\t\t\t\tthis.modules[8][this.moduleCount - h - 1] = mod;\n\t\t\t} else if (h < 9) {\n\t\t\t\tthis.modules[8][15 - h - 1 + 1] = mod;\n\t\t\t} else {\n\t\t\t\tthis.modules[8][15 - h - 1] = mod;\n\t\t\t}\n\t\t}\n\t\tthis.modules[this.moduleCount - 8][8] = (!test);\n\t},\n\tmapData : function(data, maskPattern) {\n\t\tvar inc = -1;\n\t\tvar row = this.moduleCount - 1;\n\t\tvar bitIndex = 7;\n\t\tvar byteIndex = 0;\n\t\tfor (var col = this.moduleCount - 1; col > 0; col -= 2) {\n\t\t\tif (col === 6) col--;\n\t\t\twhile (true) {\n\t\t\t\tfor (var c = 0; c < 2; c++) {\n\t\t\t\t\tif (this.modules[row][col - c] === null) {\n\t\t\t\t\t\tvar dark = false;\n\t\t\t\t\t\tif (byteIndex < data.length) {\n\t\t\t\t\t\t\tdark = ( ( (data[byteIndex] >>> bitIndex) & 1) === 1);\n\t\t\t\t\t\t}\n\t\t\t\t\t\tvar mask = QRUtil.getMask(maskPattern, row, col - c);\n\t\t\t\t\t\tif (mask) {\n\t\t\t\t\t\t\tdark = !dark;\n\t\t\t\t\t\t}\n\t\t\t\t\t\tthis.modules[row][col - c] = dark;\n\t\t\t\t\t\tbitIndex--;\n\t\t\t\t\t\tif (bitIndex === -1) {\n\t\t\t\t\t\t\tbyteIndex++;\n\t\t\t\t\t\t\tbitIndex = 7;\n\t\t\t\t\t\t}\n\t\t\t\t\t}\n\t\t\t\t}\n\t\t\t\trow += inc;\n\t\t\t\tif (row < 0 || this.moduleCount <= row) {\n\t\t\t\t\trow -= inc;\n\t\t\t\t\tinc = -inc;\n\t\t\t\t\tbreak;\n\t\t\t\t}\n\t\t\t}\n\t\t}\n\t}\n};\nQRCode.PAD0 = 0xEC;\nQRCode.PAD1 = 0x11;\nQRCode.createData = function(typeNumber, errorCorrectLevel, dataList) {\n\tvar rsBlocks = QRRSBlock.getRSBlocks(typeNumber, errorCorrectLevel);\n\tvar buffer = new QRBitBuffer();\n\tfor (var i = 0; i < dataList.length; i++) {\n\t\tvar data = dataList[i];\n\t\tbuffer.put(data.mode, 4);\n\t\tbuffer.put(data.getLength(), QRUtil.getLengthInBits(data.mode, typeNumber) );\n\t\tdata.write(buffer);\n\t}\n\tvar totalDataCount = 0;\n\tfor (var x = 0; x < rsBlocks.length; x++) {\n\t\ttotalDataCount += rsBlocks[x].dataCount;\n\t}\n\tif (buffer.getLengthInBits() > totalDataCount * 8) {\n\t\tthrow new Error(\"code length overflow. (\" + \n            buffer.getLengthInBits() + \n            \">\" +  \n            totalDataCount * 8 + \n            \")\");\n\t}\n\tif (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {\n\t\tbuffer.put(0, 4);\n\t}\n\twhile (buffer.getLengthInBits() % 8 !== 0) {\n\t\tbuffer.putBit(false);\n\t}\n\twhile (true) {\n\t\tif (buffer.getLengthInBits() >= totalDataCount * 8) {\n\t\t\tbreak;\n\t\t}\n\t\tbuffer.put(QRCode.PAD0, 8);\n\t\tif (buffer.getLengthInBits() >= totalDataCount * 8) {\n\t\t\tbreak;\n\t\t}\n\t\tbuffer.put(QRCode.PAD1, 8);\n\t}\n\treturn QRCode.createBytes(buffer, rsBlocks);\n};\nQRCode.createBytes = function(buffer, rsBlocks) {\n\tvar offset = 0;\n\tvar maxDcCount = 0;\n\tvar maxEcCount = 0;\n\tvar dcdata = new Array(rsBlocks.length);\n\tvar ecdata = new Array(rsBlocks.length);\n\tfor (var r = 0; r < rsBlocks.length; r++) {\n\t\tvar dcCount = rsBlocks[r].dataCount;\n\t\tvar ecCount = rsBlocks[r].totalCount - dcCount;\n\t\tmaxDcCount = Math.max(maxDcCount, dcCount);\n\t\tmaxEcCount = Math.max(maxEcCount, ecCount);\n\t\tdcdata[r] = new Array(dcCount);\n\t\tfor (var i = 0; i < dcdata[r].length; i++) {\n\t\t\tdcdata[r][i] = 0xff & buffer.buffer[i + offset];\n\t\t}\n\t\toffset += dcCount;\n\t\tvar rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);\n\t\tvar rawPoly = new QRPolynomial(dcdata[r], rsPoly.getLength() - 1);\n\t\tvar modPoly = rawPoly.mod(rsPoly);\n\t\tecdata[r] = new Array(rsPoly.getLength() - 1);\n\t\tfor (var x = 0; x < ecdata[r].length; x++) {\n            var modIndex = x + modPoly.getLength() - ecdata[r].length;\n\t\t\tecdata[r][x] = (modIndex >= 0)? modPoly.get(modIndex) : 0;\n\t\t}\n\t}\n\tvar totalCodeCount = 0;\n\tfor (var y = 0; y < rsBlocks.length; y++) {\n\t\ttotalCodeCount += rsBlocks[y].totalCount;\n\t}\n\tvar data = new Array(totalCodeCount);\n\tvar index = 0;\n\tfor (var z = 0; z < maxDcCount; z++) {\n\t\tfor (var s = 0; s < rsBlocks.length; s++) {\n\t\t\tif (z < dcdata[s].length) {\n\t\t\t\tdata[index++] = dcdata[s][z];\n\t\t\t}\n\t\t}\n\t}\n\tfor (var xx = 0; xx < maxEcCount; xx++) {\n\t\tfor (var t = 0; t < rsBlocks.length; t++) {\n\t\t\tif (xx < ecdata[t].length) {\n\t\t\t\tdata[index++] = ecdata[t][xx];\n\t\t\t}\n\t\t}\n\t}\n\treturn data;\n};\nmodule.exports = QRCode;\n\n};\nvar QRCode=R(\"index\"),EC=R(\"QRErrorCorrectLevel\");\nfunction qrcode(t,lv){\n  var data=[],q=null,level=EC[lv||\"M\"];\n  var o={\n    addData:function(s){data.push(unescape(encodeURIComponent(String(s))));},\n    make:function(){\n      var t0=t>0?t:1,last;\n      for(var n=t0;n<=40;n++){\n        try{var c=new QRCode(n,level);for(var i=0;i<data.length;i++)c.addData(data[i]);c.make();q=c;return;}catch(e){last=e;if(t>0)break;}\n      }\n      throw last||new Error(\"QR overflow\");\n    },\n    getModuleCount:function(){return q.getModuleCount();},\n    isDark:function(r,c){return q.isDark(r,c);},\n    createSvgTag:function(opt){\n      opt=opt||{};var cs=opt.cellSize||4,mg=opt.margin==null?cs*4:opt.margin,n=q.getModuleCount(),size=n*cs+mg*2,d=\"\";\n      for(var r=0;r<n;r++)for(var c=0;c<n;c++)if(q.isDark(r,c))d+=\"M\"+(mg+c*cs)+\",\"+(mg+r*cs)+\"h\"+cs+\"v\"+cs+\"h-\"+cs+\"z\";\n      return '<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 '+size+' '+size+'\"'+(opt.scalable?'':' width=\"'+size+'\" height=\"'+size+'\"')+' shape-rendering=\"crispEdges\"><rect width=\"100%\" height=\"100%\" fill=\"#fff\"/><path d=\"'+d+'\" fill=\"#000\"/></svg>';\n    }\n  };\n  return o;\n}\nqrcode.stringToBytesFuncs={\"UTF-8\":function(s){return s;}};\nqrcode.stringToBytes=qrcode.stringToBytesFuncs[\"UTF-8\"];\ng.qrcode=qrcode;\n})(typeof window!==\"undefined\"?window:globalThis);\n";

async function handleQr(url, env) {
  const key = pathPart(url, 2);
  const user = await env.DB.prepare("SELECT * FROM users WHERE username=? OR uuid=?").bind(key, key).first();
  if (!user) return new Response("Not Found", { status: 404 });
  const host = url.hostname;
  const addrs = await getAddrs(env, host);
  const o = await getLinkOpts(env);
  const proto = user.protocol || "vless";
  const links = [];
  addrs.forEach((addr, i) => {
    const tag = addrs.length > 1 ? `${i + 1}-${user.username}` : user.username;
    if (proto === "vless" || proto === "both") links.push(buildVless(user, host, addr, tag, o));
    if (proto === "trojan" || proto === "both") links.push(buildTrojan(user, host, addr, tag, o));
  });
  const payload = JSON.stringify({ username: user.username, links }).replace(/</g, "\\u003c");
  const lib = String(QR_SOURCE || "").replace(/<\/script/gi, "<\\/script");
  const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Config QR</title>${CSS}</head>
<body>
<div class="scene" aria-hidden="true"><div class="lines"></div></div>
<div class="auth">
  <div class="mark">P</div>
  <p class="eyebrow">CONFIG</p>
  <h2 id="who"></h2>
  <div id="items"></div>
  <button type="button" id="copyAll" style="width:100%;margin-top:.8rem">Copy all links</button>
</div>
<script id="cfg" type="application/json">${payload}</script>
<script>${lib}
(function(){
  var cfg = JSON.parse(document.getElementById('cfg').textContent);
  document.getElementById('who').textContent = cfg.username;
  var box = document.getElementById('items');
  function copy(text, btn){
    navigator.clipboard.writeText(text).then(function(){
      var o = btn.textContent; btn.textContent = 'Copied'; setTimeout(function(){ btn.textContent = o; }, 1200);
    }).catch(function(){ prompt('Link', text); });
  }
  cfg.links.forEach(function(link, i){
    var wrap = document.createElement('div');
    wrap.style.marginTop = '1rem';
    var qrbox = document.createElement('div'); qrbox.className = 'qrbox';
    var pre = document.createElement('pre'); pre.className = 'code'; pre.textContent = link;
    var btn = document.createElement('button'); btn.type = 'button'; btn.style.width = '100%'; btn.textContent = 'Copy link ' + (i + 1);
    btn.onclick = function(){ copy(link, btn); };
    wrap.appendChild(qrbox); wrap.appendChild(pre); wrap.appendChild(btn);
    box.appendChild(wrap);
    if (typeof qrcode === 'function') {
      qrcode.stringToBytes = qrcode.stringToBytesFuncs['UTF-8'];
      var qr = qrcode(0, 'M');
      qr.addData(link);
      qr.make();
      qrbox.innerHTML = qr.createSvgTag({cellSize:4, margin:12, scalable:true});
    }
  });
  var all = document.getElementById('copyAll');
  all.onclick = function(){ copy(cfg.links.join('\\n'), all); };
})();
</script></body></html>`;
  return html(page, { "Cache-Control": "no-store" });
}

// ── WebSocket ───────────────────────────────────────────────────────
async function handleWebSocket(request, env) {
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();
  let remote = null;
  let buf = new Uint8Array(0);
  let connId = null;
  let counter = null;
  let started = false;
  const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
  const early = request.headers.get("sec-websocket-protocol") || "";
  const readable = makeReadable(server, early);
  const proxyIps = (await getSetting(env.DB, "proxy_ips", "")).split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);

  const cleanup = () => {
    if (counter) counter.flush();
    if (connId != null) {
      env.DB.prepare("DELETE FROM active_connections WHERE id=?").bind(connId).run().catch(() => {});
      connId = null;
    }
  };

  readable.pipeTo(new WritableStream({
    async write(chunk) {
      if (remote) {
        counter?.add(chunk.byteLength);
        await writeAll(remote.writable, chunk);
        return;
      }
      if (started) return;
      const next = new Uint8Array(buf.byteLength + chunk.byteLength);
      next.set(buf, 0);
      next.set(new Uint8Array(chunk), buf.byteLength);
      buf = next;
      if (buf.byteLength > 8192) { server.close(1008, "header too large"); return; }

      let parsed = null;
      let isTrojan = false;
      if (buf[0] <= 1) {
        parsed = parseVless(buf);
        if (parsed && parsed.invalid) { server.close(1008, "bad header"); return; }
        if (!parsed) return;
      } else {
        parsed = parseTrojan(buf);
        if (!parsed) return;
        if (parsed.invalid) { server.close(1008, "bad header"); return; }
        isTrojan = true;
      }

      let user = null;
      if (isTrojan) user = await findTrojanUser(env.DB, parsed.password);
      else user = await env.DB.prepare("SELECT * FROM users WHERE uuid=? AND is_active=1").bind(parsed.uuid).first();
      if (!user) { server.close(1008, "unauthorized"); return; }

      if (user.reset_interval_days && user.last_reset_at) {
        const last = sqlTime(user.last_reset_at);
        if (!Number.isNaN(last) && Date.now() > last + Number(user.reset_interval_days) * 86400000) {
          await env.DB.prepare("UPDATE users SET used_gb=0, request_count=0, last_reset_at=CURRENT_TIMESTAMP WHERE username=?").bind(user.username).run();
          user.used_gb = 0; user.request_count = 0;
        }
      } else if (user.daily_request_limit > 0 && user.last_reset_at) {
        const last = sqlTime(user.last_reset_at);
        if (!Number.isNaN(last) && Date.now() > last + 86400000) {
          await env.DB.prepare("UPDATE users SET request_count=0, last_reset_at=CURRENT_TIMESTAMP WHERE username=?").bind(user.username).run();
          user.request_count = 0;
        }
      }
      if (user.limit_gb && Number(user.used_gb || 0) >= Number(user.limit_gb)) { server.close(1008, "quota"); return; }
      if (user.expiry_days && user.created_at) {
        const created = sqlTime(user.created_at);
        if (!Number.isNaN(created) && Date.now() > created + Number(user.expiry_days) * 86400000) { server.close(1008, "expired"); return; }
      }
      if (user.daily_request_limit > 0 && Number(user.request_count || 0) >= Number(user.daily_request_limit)) { server.close(1008, "daily limit"); return; }

      if (user.max_devices > 0) {
        await env.DB.prepare("DELETE FROM active_connections WHERE connected_at < datetime('now','-30 minutes')").run();
        const { results } = await env.DB.prepare("SELECT DISTINCT client_ip FROM active_connections WHERE uuid=?").bind(user.uuid).all();
        const ips = new Set((results || []).map((r) => r.client_ip));
        if (!ips.has(clientIp) && ips.size >= Number(user.max_devices)) { server.close(1008, "device limit"); return; }
      }

      const ins = await env.DB.prepare("INSERT INTO active_connections (uuid, client_ip) VALUES (?,?)").bind(user.uuid, clientIp).run();
      connId = ins.meta ? ins.meta.last_row_id : null;
      env.DB.prepare("UPDATE users SET request_count=request_count+1 WHERE username=?").bind(user.username).run().catch(() => {});
      counter = makeCounter(env, user.username);
      started = true;

      if (!isTrojan) server.send(new Uint8Array([parsed.version, 0]));
      const payload = buf.slice(parsed.headerLength);
      counter.add(payload.byteLength);

      const open = async (hostname, port) => {
        const sock = await connect({ hostname, port });
        await writeAll(sock.writable, payload);
        return sock;
      };

      try {
        remote = await open(parsed.addr, parsed.port);
        pipeRemote(remote, server, counter, cleanup);
      } catch {
        let ok = false;
        for (const pip of proxyIps) {
          try {
            const [ph, pp] = splitHostPort(pip, parsed.port);
            if (!ph) continue;
            remote = await open(ph, pp);
            pipeRemote(remote, server, counter, cleanup);
            ok = true;
            break;
          } catch { /* try the next proxy */ }
        }
        if (!ok) { cleanup(); server.close(1011, "upstream failed"); }
      }
    },
    close() { cleanup(); try { remote && remote.close(); } catch { /* already closed */ } },
  })).catch(() => { cleanup(); try { remote && remote.close(); } catch { /* already closed */ } });

  const headers = {};
  if (early) headers["Sec-WebSocket-Protocol"] = early.split(",")[0].trim();
  return new Response(null, { status: 101, webSocket: client, headers });
}

async function findTrojanUser(db, presented) {
  const raw = String(presented || "");
  const folded = raw.toLowerCase();
  const { results } = await db.prepare("SELECT * FROM users WHERE is_active=1 AND (protocol='trojan' OR protocol='both')").all();
  for (const user of results || []) {
    const candidates = [user.trojan_pass, user.uuid, String(user.uuid || "").replace(/-/g, "")].filter(Boolean);
    for (const candidate of candidates) {
      if (candidate === raw || candidate.toLowerCase() === folded) return user;
      if (/^[0-9a-f]{56}$/.test(folded) && sha224hex(candidate) === folded) return user;
    }
  }
  return null;
}

function makeReadable(ws, earlyHeader) {
  let canceled = false;
  return new ReadableStream({
    start(ctrl) {
      if (earlyHeader) {
        try { ctrl.enqueue(b64urlToBytes(earlyHeader.split(",")[0].trim())); }
        catch { /* protocol token is not early data */ }
      }
      ws.addEventListener("message", (e) => {
        if (canceled) return;
        const d = e.data;
        if (d instanceof ArrayBuffer) ctrl.enqueue(new Uint8Array(d));
        else if (ArrayBuffer.isView(d)) ctrl.enqueue(new Uint8Array(d.buffer, d.byteOffset, d.byteLength));
        else if (typeof d === "string") ctrl.enqueue(new TextEncoder().encode(d));
        else if (d && typeof d.arrayBuffer === "function") d.arrayBuffer().then((ab) => { if (!canceled) ctrl.enqueue(new Uint8Array(ab)); });
      });
      ws.addEventListener("close", () => { if (!canceled) try { ctrl.close(); } catch { /* closed */ } });
      ws.addEventListener("error", (e) => { try { ctrl.error(e); } catch { /* closed */ } });
    },
    cancel() { canceled = true; try { ws.close(); } catch { /* closed */ } },
  });
}

function pipeRemote(socket, server, counter, onDone) {
  let done = false;
  const finish = () => {
    if (done) return;
    done = true;
    counter.flush();
    onDone?.();
    try { server.close(); } catch { /* closed */ }
  };
  socket.readable.pipeTo(new WritableStream({
    write(c) { counter.add(c.byteLength); server.send(c); },
    close: finish,
    abort: finish,
  })).catch(finish);
}

function parseVless(buffer) {
  const b = new Uint8Array(buffer);
  if (b.byteLength < 18) return null;
  const version = b[0];
  const hex = [...b.slice(1, 17)].map((x) => x.toString(16).padStart(2, "0")).join("");
  const uuid = hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
  const addon = b[17];
  const base = 18 + addon;
  if (b.byteLength < base + 4) return null;
  let off = base;
  if (b[off++] !== 1) return { invalid: true };
  const port = (b[off] << 8) | b[off + 1];
  off += 2;
  const atype = b[off++];
  let addr = "";
  if (atype === 1) {
    if (b.byteLength < off + 4) return null;
    addr = b[off] + "." + b[off + 1] + "." + b[off + 2] + "." + b[off + 3];
    off += 4;
  } else if (atype === 2) {
    if (b.byteLength < off + 1) return null;
    const len = b[off];
    if (!len || b.byteLength < off + 1 + len) return null;
    off += 1;
    addr = new TextDecoder().decode(b.slice(off, off + len));
    off += len;
  } else if (atype === 3) {
    if (b.byteLength < off + 16) return null;
    const parts = [];
    for (let i = 0; i < 8; i++) { parts.push(((b[off] << 8) | b[off + 1]).toString(16)); off += 2; }
    addr = parts.join(":");
  } else return { invalid: true };
  if (!addr || !port) return { invalid: true };
  return { version, uuid, port, addr, headerLength: off };
}

function parseTrojan(buffer) {
  const b = new Uint8Array(buffer);
  if (b.byteLength < 3) return null;
  const crlf = findCRLF(b);
  if (crlf < 1) return b.byteLength > 128 ? { invalid: true } : null;
  let pass = "";
  try { pass = new TextDecoder().decode(b.slice(0, crlf)); } catch { return { invalid: true }; }
  if (!pass || pass.length > 128) return { invalid: true };
  const socks = parseTrojanSocks(b, crlf + 2, pass);
  if (socks && socks.invalid) return socks;
  return socks;
}
function findCRLF(b) {
  const n = Math.min(b.byteLength - 1, 128);
  for (let i = 0; i < n; i++) if (b[i] === 0x0d && b[i + 1] === 0x0a) return i;
  return -1;
}
function parseTrojanSocks(b, off, password) {
  if (b.byteLength < off + 3) return null;
  if (b[off] !== 1) return { invalid: true };
  const atype = b[off + 1];
  let addr = "";
  let aoff = off + 2;
  if (atype === 1) {
    if (b.byteLength < aoff + 6) return null;
    addr = b[aoff] + "." + b[aoff + 1] + "." + b[aoff + 2] + "." + b[aoff + 3];
    aoff += 4;
  } else if (atype === 3) {
    if (b.byteLength < aoff + 1) return null;
    const len = b[aoff];
    aoff += 1;
    if (!len || b.byteLength < aoff + len + 2) return null;
    addr = new TextDecoder().decode(b.slice(aoff, aoff + len));
    aoff += len;
  } else if (atype === 4) {
    if (b.byteLength < aoff + 18) return null;
    const parts = [];
    for (let i = 0; i < 8; i++) { parts.push(((b[aoff] << 8) | b[aoff + 1]).toString(16)); aoff += 2; }
    addr = parts.join(":");
  } else return { invalid: true };
  const port = (b[aoff] << 8) | b[aoff + 1];
  aoff += 2;
  if (!addr || !port) return { invalid: true };
  return { password, addr, port, headerLength: aoff };
}

// ── Panel ───────────────────────────────────────────────────────────
async function handlePanel(request, env) {
  const has = await getPassHash(env.DB);
  const headers = { "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow" };
  if (!has) return html(SETUP, headers);
  if (!(await isAuth(request, env))) return html(LOGIN, headers);
  return html(DASH, headers);
}

const CSS = `
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Vazirmatn:wght@400;500;600;700;800&display=swap');
:root {
  color-scheme: dark;
  --bg:#07090f; --elev:#10141c; --card:rgba(14,18,28,.78);
  --line:rgba(255,255,255,.08); --line-strong:rgba(255,255,255,.14);
  --text:#eef2f8; --muted:#93a0b5; --accent:#8aa4ff; --accent-2:#5eead4;
  --green:#3ddc97; --red:#ff6b81; --amber:#f5c16c;
  --shadow:0 24px 60px rgba(0,0,0,.35);
}
body.light {
  color-scheme: light;
  --bg:#e7ebf2; --elev:#ffffff; --card:rgba(255,255,255,.84);
  --line:rgba(15,23,42,.08); --line-strong:rgba(15,23,42,.14);
  --text:#121826; --muted:#5c6b82; --accent:#3d5afe; --accent-2:#0f766e;
  --green:#059669; --red:#e11d48; --amber:#b45309;
  --shadow:0 18px 40px rgba(20,30,60,.08);
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body { min-height: 100%; }
body {
  font-family: Vazirmatn, Inter, Tahoma, sans-serif;
  background: var(--bg); color: var(--text); direction: rtl;
  padding: 1.25rem; overflow-x: hidden;
}
body.en { direction: ltr; font-family: Inter, Vazirmatn, "Segoe UI", sans-serif; }
button, input, textarea, select { font-family: inherit; }
.scene { position: fixed; inset: 0; z-index: 0; pointer-events: none; background:
  radial-gradient(900px 480px at 8% -10%, rgba(138,164,255,.22), transparent 60%),
  radial-gradient(700px 420px at 100% 0%, rgba(94,234,212,.13), transparent 55%),
  radial-gradient(800px 500px at 50% 115%, rgba(138,164,255,.1), transparent 50%),
  var(--bg); }
.lines { position: absolute; inset: 0; background-image:
  linear-gradient(to right, rgba(255,255,255,.04) 1px, transparent 1px),
  linear-gradient(to bottom, rgba(255,255,255,.04) 1px, transparent 1px);
  background-size: 72px 72px; mask-image: radial-gradient(ellipse at 50% 18%, #000 12%, transparent 74%); }
body.light .lines { background-image:
  linear-gradient(to right, rgba(15,23,42,.05) 1px, transparent 1px),
  linear-gradient(to bottom, rgba(15,23,42,.05) 1px, transparent 1px); }
.wrap { max-width: 1180px; margin: 0 auto; position: relative; z-index: 1; }
.auth { width: min(440px, 100%); margin: 8vh auto; position: relative; z-index: 1; padding: 2rem; border-radius: 24px; background: var(--card); border: 1px solid var(--line); box-shadow: var(--shadow), inset 0 1px 0 rgba(255,255,255,.06); backdrop-filter: blur(18px); }
.mark { width: 42px; height: 42px; border-radius: 14px; display: grid; place-items: center; font-weight: 800; color: #07101c; background: conic-gradient(from 210deg, var(--accent), var(--accent-2), var(--accent)); box-shadow: 0 10px 28px rgba(138,164,255,.35); margin-bottom: .9rem; }
.eyebrow { color: var(--accent-2); font-size: .72rem; letter-spacing: .16em; font-weight: 700; }
h2 { font-size: 1.55rem; letter-spacing: -.03em; margin: .2rem 0 1rem; }
.topbar { display: flex; justify-content: space-between; align-items: center; gap: .8rem; flex-wrap: wrap; margin-bottom: 1rem; padding: .85rem 1rem; border: 1px solid var(--line); border-radius: 20px; background: var(--card); backdrop-filter: blur(16px); box-shadow: var(--shadow); position: sticky; top: .6rem; z-index: 5; }
.brand-lock { display: flex; align-items: center; gap: .75rem; }
.brand-lock .mark { margin: 0; width: 38px; height: 38px; }
.brand { font-weight: 800; letter-spacing: -.03em; font-size: 1.15rem; }
.subbrand { color: var(--muted); font-size: .75rem; }
.nav { display: flex; gap: .4rem; flex-wrap: wrap; align-items: center; }
input, textarea, select {
  width: 100%; padding: .78rem .9rem; border-radius: 12px; border: 1px solid var(--line);
  background: var(--elev); color: var(--text); font-size: .92rem; outline: none;
}
input:focus, textarea:focus, select:focus { border-color: var(--accent); box-shadow: 0 0 0 4px rgba(138,164,255,.16); }
button {
  padding: .72rem 1rem; border: 0; border-radius: 12px; cursor: pointer; font-weight: 700;
  color: #07101c; background: linear-gradient(135deg, var(--accent), #6d8bff);
  box-shadow: 0 8px 20px rgba(138,164,255,.22);
}
button:hover { transform: translateY(-1px); }
button:active { transform: translateY(0); }
button.ghost { background: transparent; color: var(--text); border: 1px solid var(--line); box-shadow: none; }
button.danger { color: white; background: linear-gradient(135deg, #fb7185, #e11d48); box-shadow: none; }
button.sm { padding: .42rem .7rem; font-size: .78rem; }
button.onpage { outline: 1px solid var(--accent); }
.stats, .fields { display: grid; gap: .75rem; }
.stats { grid-template-columns: repeat(4, 1fr); margin-bottom: 1rem; }
.fields { grid-template-columns: repeat(4, 1fr); }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 20px; padding: 1.15rem; margin-bottom: 1rem; backdrop-filter: blur(16px); box-shadow: var(--shadow), inset 0 1px 0 rgba(255,255,255,.05); }
.card h3 { letter-spacing: -.02em; margin-bottom: .35rem; }
.stat { font-size: 1.8rem; font-weight: 800; letter-spacing: -.04em; font-variant-numeric: tabular-nums; }
.stat-label, .muted { color: var(--muted); }
.stat-label { font-size: .78rem; margin-bottom: .25rem; }
table { width: 100%; border-collapse: collapse; font-size: .84rem; }
th { text-align: start; color: var(--muted); font-weight: 600; padding: .7rem .45rem; border-bottom: 1px solid var(--line); }
td { padding: .75rem .45rem; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:hover td { background: rgba(255,255,255,.025); }
.pill, .badge { display: inline-flex; align-items: center; border-radius: 999px; font-size: .68rem; font-weight: 800; letter-spacing: .04em; padding: .16rem .5rem; }
.pill.on { background: rgba(61,220,151,.14); color: var(--green); }
.pill.off { background: rgba(255,107,129,.14); color: var(--red); }
.badge { text-transform: uppercase; border: 1px solid var(--line); }
.badge.vless { color: #b7c6ff; background: rgba(138,164,255,.12); }
.badge.trojan { color: #99f6e4; background: rgba(94,234,212,.12); }
.badge.both { color: #fde68a; background: rgba(245,193,108,.12); }
.meter { height: 6px; border-radius: 99px; background: rgba(255,255,255,.08); margin-top: .35rem; overflow: hidden; }
.meter span { display: block; height: 100%; background: linear-gradient(90deg, var(--accent), var(--accent-2)); }
.meter span.warn { background: var(--amber); }
.meter span.bad { background: var(--red); }
.live { color: var(--green); font-weight: 800; }
.actions { display: flex; flex-wrap: wrap; gap: .15rem .35rem; }
.link { background: none; border: 0; box-shadow: none; color: var(--accent); padding: 0; font-size: .75rem; font-weight: 700; }
.link.danger { color: var(--red); background: none; }
/* glass action buttons (user table) */
.actions { gap: .4rem .4rem; }
.actions .link { position: relative; overflow: hidden; cursor: pointer;
  padding: .38rem .75rem; border-radius: 999px; font-size: .74rem; font-weight: 700; letter-spacing: .01em; line-height: 1.2;
  color: var(--text);
  background: linear-gradient(145deg, rgba(255,255,255,.16), rgba(255,255,255,.05));
  border: 1px solid rgba(255,255,255,.18);
  box-shadow: 0 4px 14px rgba(0,0,0,.22), inset 0 1px 0 rgba(255,255,255,.28), inset 0 -1px 0 rgba(255,255,255,.04);
  -webkit-backdrop-filter: blur(10px) saturate(160%); backdrop-filter: blur(10px) saturate(160%);
  transition: transform .18s ease, box-shadow .18s ease, background .18s ease, border-color .18s ease, color .18s ease; }
.actions .link::before { content: ""; position: absolute; inset: 0 0 52% 0; border-radius: inherit; pointer-events: none;
  background: linear-gradient(180deg, rgba(255,255,255,.22), rgba(255,255,255,0)); }
.actions .link:hover { transform: translateY(-1px); color: #fff;
  background: linear-gradient(145deg, rgba(138,164,255,.38), rgba(94,234,212,.16));
  border-color: rgba(138,164,255,.55);
  box-shadow: 0 8px 20px rgba(138,164,255,.28), inset 0 1px 0 rgba(255,255,255,.4); }
.actions .link:active { transform: translateY(0) scale(.96); box-shadow: 0 2px 8px rgba(0,0,0,.25), inset 0 1px 2px rgba(0,0,0,.2); }
.actions .link:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.actions .link.danger { color: var(--red);
  background: linear-gradient(145deg, rgba(255,107,129,.22), rgba(255,107,129,.06));
  border-color: rgba(255,107,129,.38); }
.actions .link.danger:hover { color: #fff;
  background: linear-gradient(145deg, rgba(255,107,129,.6), rgba(255,107,129,.25));
  border-color: rgba(255,107,129,.7); box-shadow: 0 8px 20px rgba(255,107,129,.32), inset 0 1px 0 rgba(255,255,255,.35); }
body.light .actions .link { color: var(--text);
  background: linear-gradient(145deg, rgba(255,255,255,.85), rgba(255,255,255,.45));
  border-color: rgba(15,23,42,.12);
  box-shadow: 0 4px 12px rgba(15,23,42,.1), inset 0 1px 0 rgba(255,255,255,.9); }
body.light .actions .link:hover { color: var(--accent);
  background: linear-gradient(145deg, rgba(61,90,254,.16), rgba(15,118,110,.08));
  border-color: rgba(61,90,254,.4); box-shadow: 0 8px 18px rgba(61,90,254,.2), inset 0 1px 0 rgba(255,255,255,.9); }
body.light .actions .link.danger { color: var(--red); }
body.light .actions .link.danger:hover { color: #fff; }
.guide summary { cursor: pointer; list-style: none; }
.guide summary::-webkit-details-marker { display: none; }
.guide h4 { margin: .9rem 0 .3rem; color: var(--accent-2); }
.guide ol { padding-inline-start: 1.2rem; line-height: 1.9; }
.guide code { font-size: .8rem; padding: .05rem .35rem; border-radius: 6px; background: rgba(138,164,255,.12); }
body:not(.en) .g-en { display: none; }
body.en .g-fa { display: none; }
@media (prefers-reduced-motion: reduce) { .actions .link { transition: none; } .actions .link:hover { transform: none; } }
.mono { font-family: Consolas, ui-monospace, monospace; font-size: .68rem; direction: ltr; unicode-bidi: isolate; }
.code, code, .ltr { direction: ltr; unicode-bidi: isolate; }
.code { white-space: pre-wrap; word-break: break-all; background: var(--elev); border: 1px solid var(--line); border-radius: 12px; padding: .8rem; font-size: .75rem; margin: .8rem 0; max-height: 9rem; overflow: auto; }
.qrbox { display: flex; justify-content: center; background: white; border-radius: 16px; padding: .6rem; margin: .4rem 0 .2rem; }
.qrbox svg { width: min(260px, 100%); height: auto; }
.err { color: var(--red); min-height: 1.2em; margin-top: .45rem; font-size: .84rem; }
.result { margin-top: .7rem; padding: .75rem .85rem; border-radius: 12px; background: rgba(94,234,212,.08); border: 1px solid rgba(94,234,212,.25); font-size: .8rem; }
.section { display: none; }
.section.active { display: block; }
.toast { position: fixed; bottom: 1.3rem; left: 50%; transform: translateX(-50%) translateY(12px); background: var(--elev); color: var(--text); border: 1px solid var(--line-strong); padding: .7rem 1.1rem; border-radius: 999px; opacity: 0; pointer-events: none; transition: .25s; z-index: 30; box-shadow: var(--shadow); }
.toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
.modal-bg { position: fixed; inset: 0; background: rgba(2,6,16,.62); display: none; align-items: center; justify-content: center; z-index: 20; backdrop-filter: blur(8px); padding: 1rem; }
.modal-bg.show { display: flex; }
.modal { width: min(460px, 100%); background: var(--elev); border: 1px solid var(--line); border-radius: 22px; padding: 1.3rem; box-shadow: var(--shadow); }
.modal h3 { margin-bottom: .7rem; }
.warn { background: rgba(245,193,108,.1); border: 1px solid rgba(245,193,108,.28); border-radius: 16px; padding: .95rem 1rem; margin-bottom: 1rem; font-size: .88rem; line-height: 1.7; }
.switch { display: flex; align-items: center; gap: .75rem; margin: .7rem 0; cursor: pointer; }
.switch input { position: absolute; opacity: 0; width: 1px; height: 1px; }
.track { width: 46px; height: 26px; border-radius: 99px; background: rgba(255,255,255,.14); position: relative; flex: 0 0 auto; }
.track:after { content: ""; position: absolute; width: 20px; height: 20px; border-radius: 50%; background: white; top: 3px; inset-inline-start: 3px; transition: .18s; }
.switch input:checked + .track { background: linear-gradient(135deg, var(--accent), var(--accent-2)); }
.switch input:checked + .track:after { inset-inline-start: 23px; }
.switch input:focus-visible + .track { box-shadow: 0 0 0 4px rgba(138,164,255,.2); }
.frag-status { font-size: .75rem; font-weight: 800; }
.frag-status.on { color: var(--green); }
.frag-status.off { color: var(--red); }
.toolbar { display: flex; gap: .5rem; flex-wrap: wrap; margin: .7rem 0; }
.empty { text-align: center; color: var(--muted); padding: 1.4rem !important; }
.links { margin: .4rem 1.1rem; line-height: 1.9; }
.row-actions { display: flex; gap: .5rem; justify-content: flex-end; margin-top: .8rem; }
footer.panel { color: var(--muted); font-size: .75rem; text-align: center; padding: .4rem 0 1rem; }
@media (max-width: 900px) { .stats, .fields { grid-template-columns: 1fr 1fr; } }
@media (max-width: 640px) { body { padding: .7rem; } .stats, .fields { grid-template-columns: 1fr; } .topbar { position: static; } }
@media (prefers-reduced-motion: reduce) { button { transition: none; } }
</style>`;

const SETUP = `<!doctype html><html lang="fa"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Panel Pro</title>${CSS}</head>
<body>
<div class="scene" aria-hidden="true"><div class="lines"></div></div>
<div class="auth">
  <div class="mark">P</div>
  <p class="eyebrow">PANEL PRO ${VERSION}</p>
  <h2>Set the panel password</h2>
  <input id="p" type="password" autocomplete="new-password" placeholder="At least 4 characters" autofocus>
  <button type="button" style="width:100%;margin-top:.8rem" onclick="go()">Create panel</button>
  <div class="err" id="e"></div>
</div>
<script>
if (localStorage.getItem('th')==='l') document.body.classList.add('light');
async function go(){
  var r = await fetch('/api/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});
  var d = await r.json();
  if (d.error) document.getElementById('e').textContent = d.error; else location.reload();
}
document.getElementById('p').onkeydown = function(e){ if(e.key==='Enter') go(); };
</script></body></html>`;

const LOGIN = `<!doctype html><html lang="fa"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Panel Pro</title>${CSS}</head>
<body>
<div class="scene" aria-hidden="true"><div class="lines"></div></div>
<div class="auth">
  <div class="mark">P</div>
  <p class="eyebrow">PANEL PRO ${VERSION}</p>
  <h2>Sign in</h2>
  <input id="p" type="password" autocomplete="current-password" placeholder="Password" autofocus>
  <button type="button" style="width:100%;margin-top:.8rem" onclick="go()">Continue</button>
  <div class="err" id="e"></div>
</div>
<script>
if (localStorage.getItem('th')==='l') document.body.classList.add('light');
async function go(){
  var r = await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:document.getElementById('p').value})});
  var d = await r.json();
  if (d.error) document.getElementById('e').textContent = d.error; else location.reload();
}
document.getElementById('p').onkeydown = function(e){ if(e.key==='Enter') go(); };
</script></body></html>`;

const DASH = `<!doctype html><html lang="fa"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Panel Pro ${VERSION}</title>${CSS}</head>
<body>
<div class="scene" aria-hidden="true"><div class="lines"></div></div>
<div class="wrap">
<header class="topbar">
  <div class="brand-lock">
    <div class="mark">P</div>
    <div>
      <div class="eyebrow">OPERATIONS</div>
      <div class="brand">Panel Pro</div>
      <div class="subbrand">Version ${VERSION}</div>
    </div>
  </div>
  <nav class="nav">
    <button type="button" class="ghost sm" id="nav-users" onclick="show('users')" data-i18n="nav_users">کاربران</button>
    <button type="button" class="ghost sm" id="nav-settings" onclick="show('settings')" data-i18n="nav_settings">تنظیمات</button>
    <button type="button" class="ghost sm" id="nav-security" onclick="show('security')" data-i18n="nav_security">امنیت</button>
    <button type="button" class="ghost sm" onclick="setLang('fa')" id="btn-fa">FA</button>
    <button type="button" class="ghost sm" onclick="setLang('en')" id="btn-en">EN</button>
    <button type="button" class="ghost sm" onclick="toggleTheme()" id="tb">Night</button>
    <button type="button" class="ghost sm" onclick="logout()" data-i18n="nav_logout">خروج</button>
  </nav>
</header>

<section class="stats">
  <article class="card"><div class="stat-label" data-i18n="stat_total">کل</div><div class="stat" id="sT">—</div></article>
  <article class="card"><div class="stat-label" data-i18n="stat_active">فعال</div><div class="stat" id="sA">—</div></article>
  <article class="card"><div class="stat-label" data-i18n="stat_online">آنلاین</div><div class="stat" id="sO">—</div></article>
  <article class="card"><div class="stat-label" data-i18n="stat_usage">مصرف GB</div><div class="stat" id="sU">—</div></article>
</section>

<section id="sec-users" class="section active">
  <div class="card">
    <h3 data-i18n="add_user">کاربر جدید</h3>
    <p class="muted" data-i18n="add_help">نام کاربری لازم است. بقیه فیلدها اختیاری‌اند.</p>
    <div class="fields" style="margin-top:.8rem">
      <input id="u" data-i18n-ph="ph_username" placeholder="نام کاربری *">
      <select id="proto"><option value="vless">VLESS</option><option value="trojan">Trojan</option><option value="both" data-i18n="opt_both">هر دو</option></select>
      <input id="g" data-i18n-ph="ph_gb" placeholder="حجم GB">
      <input id="d" data-i18n-ph="ph_days" placeholder="روز اعتبار">
      <input id="md" data-i18n-ph="ph_devices" placeholder="حد دستگاه">
      <input id="ri" data-i18n-ph="ph_reset" placeholder="ریست هر N روز">
      <input id="drl" data-i18n-ph="ph_daily" placeholder="سقف درخواست روزانه">
      <input id="note" data-i18n-ph="ph_note" placeholder="یادداشت">
    </div>
    <button type="button" style="margin-top:.8rem" onclick="addUser()" data-i18n="btn_add">افزودن</button>
    <div class="err" id="e"></div>
    <div class="result" id="made" hidden></div>
  </div>
  <div class="card">
    <h3 data-i18n="users_list">کاربران</h3>
    <div class="toolbar">
      <input id="search" data-i18n-ph="ph_search" placeholder="جستجو..." style="flex:1;min-width:180px">
      <button type="button" class="ghost sm" onclick="load()" data-i18n="btn_refresh">تازه‌سازی</button>
      <button type="button" class="ghost sm" onclick="exportU()" data-i18n="btn_export">خروجی</button>
    </div>
    <div class="toolbar">
      <button type="button" class="ghost sm" onclick="bulk('enable')" data-i18n="bulk_enable">فعال</button>
      <button type="button" class="ghost sm" onclick="bulk('disable')" data-i18n="bulk_disable">غیرفعال</button>
      <button type="button" class="ghost sm" onclick="bulk('reset')" data-i18n="bulk_reset">ریست</button>
      <button type="button" class="danger sm" onclick="bulk('delete')" data-i18n="bulk_delete">حذف</button>
    </div>
    <div style="overflow-x:auto">
      <table id="t"><thead><tr>
        <th><input type="checkbox" id="chkAll" aria-label="Select all"></th>
        <th data-i18n="th_user">کاربر</th>
        <th data-i18n="th_proto">پروتکل</th>
        <th data-i18n="th_status">وضعیت</th>
        <th data-i18n="th_usage">مصرف</th>
        <th data-i18n="th_online">آنلاین</th>
        <th data-i18n="th_actions">عملیات</th>
      </tr></thead><tbody></tbody></table>
    </div>
  </div>
</section>

<section id="sec-settings" class="section">
  <div class="card">
    <h3 data-i18n="set_clean">Clean IP</h3>
    <p class="muted" data-i18n="set_clean_h">هر خط یک آدرس. اگر پینگ برقرار نیست، این فهرست را خالی بگذار تا از دامنه خود ورکر استفاده شود.</p>
    <textarea id="cleanIps" rows="4"></textarea>
  </div>
  <div class="card">
    <h3 data-i18n="set_proxy">Proxy IP</h3>
    <p class="muted" data-i18n="set_proxy_h">اختیاری. فقط وقتی اتصال مستقیم به مقصد شکست بخورد استفاده می‌شود. هر خط یک IP یا host:port.</p>
    <textarea id="proxyIps" rows="3" placeholder="203.0.113.10 or 203.0.113.10:443"></textarea>
  </div>
  <div class="card">
    <h3 data-i18n="set_frag">Fragment</h3>
    <p class="muted" data-i18n="set_frag_h">روی اشتراک Sing-box اعمال می‌شود. مسیر singbox-frag همیشه آن را روشن می‌کند. فاصله به عنوان تأخیر fragment ذخیره می‌شود.</p>
    <label class="switch">
      <input type="checkbox" id="fragEn">
      <span class="track"></span>
      <span data-i18n="frag_toggle">فعال برای اشتراک Sing-box</span>
      <span class="frag-status off" id="fragLabel">OFF</span>
    </label>
    <div class="fields">
      <input id="fragLen" placeholder="Length 100-200">
      <input id="fragInt" placeholder="Interval 10-20">
    </div>
  </div>
  <div class="card">
    <h3 data-i18n="set_linkopt">TLS options</h3>
    <p class="muted" data-i18n="set_linkopt_h">Fingerprint and ALPN used in all generated links and subscriptions.</p>
    <div class="fields">
      <label class="muted" style="display:block"><span data-i18n="lbl_fp">Fingerprint</span>
        <select id="linkFp" style="margin-top:.3rem"><option>chrome</option><option>firefox</option><option>safari</option><option>ios</option><option>android</option><option>edge</option><option>360</option><option>qq</option><option>random</option><option>randomized</option></select></label>
      <label class="muted" style="display:block"><span data-i18n="lbl_alpn">ALPN</span>
        <select id="linkAlpn" style="margin-top:.3rem"><option value="h2,http/1.1">h2,http/1.1</option><option value="http/1.1">http/1.1</option><option value="h2">h2</option></select></label>
    </div>
  </div>
  <div class="card">
    <h3 data-i18n="set_warp">Warp endpoints</h3>
    <textarea id="warpEp" rows="2" placeholder="engage.cloudflareclient.com:2408"></textarea>
  </div>
  <div class="card">
    <h3 data-i18n="set_camo">Public site</h3>
    <p class="muted" data-i18n="set_camo_h">نامی که در صفحه اصلی، قبل از ورود به پنل، نشان داده می‌شود.</p>
    <input id="camName" placeholder="Northline Cloud">
    <input id="remark" placeholder="Config prefix" style="margin-top:.55rem">
    <button type="button" style="margin-top:.8rem" onclick="saveSet()" data-i18n="btn_save_all">ذخیره تنظیمات</button>
  </div>
  <details class="card guide">
    <summary><strong class="g-fa">راهنمای اتصال به کلودفلر روی فایروال‌ها</strong><strong class="g-en">Connecting to Cloudflare through the firewalls</strong></summary>
    <div class="g-fa">
      <p class="muted">این مقادیر تنظیمات سمت کلاینت هستند (مثلاً v2rayN، Aether و ...). فقط fingerprint و ALPN از همین پنل روی لینک‌ها اعمال می‌شوند.</p>
      <h4>همراه اول</h4>
      <ol class="muted">
        <li><strong>CDN/Worker با ECH:</strong> از یک آدرس مناسب مثل <code class="ltr">188.114.97.6</code> استفاده کنید، finalMask و cipherSuites را پاک کنید، fingerprint را روی <code class="ltr">chrome</code> بگذارید و در echConfigList مقدار <code class="ltr">cloudflare-ech.com+udp://1.1.1.1</code> را وارد کنید.</li>
        <li><strong>CDN/Worker با IPv6:</strong> echConfigList و cipherSuites را پاک کنید، fingerprint را روی <code class="ltr">chrome</code> بگذارید و از یک آدرس IPv6 مثل <code class="ltr">2a06:98c1:3121::7</code> استفاده کنید. اگر دامنه‌ی شما فیلتر نیست finalMask را خالی بگذارید، وگرنه آن را روی <code class="ltr">tlshello-0-len</code> (همان مقدار متد F&amp;F) بگذارید.</li>
        <li><strong>WARP با IPv6:</strong> در Aether پروتکل را روی wireguard/warp-in-warp بگذارید، نوع IP را IPv6 انتخاب کنید، اسکن کنید و بعد از پیدا شدن آیپی، اسم بدهید و ذخیره کنید.</li>
      </ol>
      <h4>ایرانسل</h4>
      <ol class="muted">
        <li><strong>CDN/Worker با روش F&amp;F:</strong> echConfigList را پاک کنید، از یک آدرس مناسب مثل <code class="ltr">188.114.97.6</code> استفاده کنید، finalMask را روی <code class="ltr">tlshello-0-len</code>، cipherSuites را روی <code class="ltr">semi-python</code> و fingerprint را روی <code class="ltr">unsafe</code> بگذارید. ALPN را درست انتخاب کنید: <code class="ltr">http/1.1</code> برای ws و <code class="ltr">h2,http/1.1</code> برای XHTTP.</li>
        <li><strong>WARP:</strong> همان مراحل همراه اول، با این تفاوت که روی ایرانسل هر نوع IP کار می‌کند.</li>
        <li><strong>MASQUE/H2:</strong> در Aether پروتکل را روی MASQUE-HTTP/2 بگذارید، fingerprint را روی <code class="ltr">semi-python</code> و finalMask را روی <code class="ltr">tlshello-0-len</code> قرار دهید، اسکن کنید و بعد از پیدا شدن آیپی، اسم بدهید و ذخیره کنید.</li>
      </ol>
      <p class="muted">ممکن است سیم‌کارت شما همراه اول باشد ولی فایروالتان ایرانسل باشد و برعکس. اپراتورهای دیگر هم معمولاً از یکی از این دو فایروال استفاده می‌کنند. آدرس IPv6 و آدرس با پورت (مثل <code class="ltr">ip:2053</code>) در فهرست Clean IP پشتیبانی می‌شوند.</p>
    </div>
    <div class="g-en">
      <p class="muted">These are client-side settings (v2rayN, Aether, etc.). Only fingerprint and ALPN are applied to links from this panel.</p>
      <h4>MCI (Hamrah-e Aval)</h4>
      <ol class="muted">
        <li><strong>CDN/Worker with ECH:</strong> use a suitable address such as <code class="ltr">188.114.97.6</code>, clear finalMask and cipherSuites, set fingerprint to <code class="ltr">chrome</code>, and set echConfigList to <code class="ltr">cloudflare-ech.com+udp://1.1.1.1</code>.</li>
        <li><strong>CDN/Worker with IPv6:</strong> clear echConfigList and cipherSuites, set fingerprint to <code class="ltr">chrome</code>, and use an IPv6 address such as <code class="ltr">2a06:98c1:3121::7</code>. If your domain is not blocked leave finalMask empty, otherwise set it to <code class="ltr">tlshello-0-len</code> (the F&amp;F value).</li>
        <li><strong>WARP with IPv6:</strong> in Aether set the protocol to wireguard/warp-in-warp, choose IPv6, scan, then name and save the endpoint it finds.</li>
      </ol>
      <h4>Irancell</h4>
      <ol class="muted">
        <li><strong>CDN/Worker with F&amp;F:</strong> clear echConfigList, use a suitable address such as <code class="ltr">188.114.97.6</code>, set finalMask to <code class="ltr">tlshello-0-len</code>, cipherSuites to <code class="ltr">semi-python</code> and fingerprint to <code class="ltr">unsafe</code>. Pick ALPN correctly: <code class="ltr">http/1.1</code> for ws, <code class="ltr">h2,http/1.1</code> for XHTTP.</li>
        <li><strong>WARP:</strong> same steps as MCI, but any IP type works on Irancell.</li>
        <li><strong>MASQUE/H2:</strong> in Aether set the protocol to MASQUE-HTTP/2, fingerprint to <code class="ltr">semi-python</code> and finalMask to <code class="ltr">tlshello-0-len</code>, scan, then name and save the endpoint.</li>
      </ol>
      <p class="muted">Your SIM may be MCI while the firewall in your area is Irancell, and vice versa. Other ISPs usually sit behind one of these two firewalls. IPv6 addresses and addresses with a port (e.g. <code class="ltr">ip:2053</code>) are supported in the Clean IP list.</p>
    </div>
  </details>
  <div class="card">
    <h3 data-i18n="set_links">Subscription paths</h3>
    <ul class="muted links">
      <li class="ltr"><code>/sub/USER</code> Base64</li>
      <li class="ltr"><code>/clash/USER</code> Clash</li>
      <li class="ltr"><code>/singbox/USER</code> Sing-box</li>
      <li class="ltr"><code>/singbox-frag/USER</code> Sing-box + fragment</li>
      <li class="ltr"><code>/qr/USER</code> QR</li>
      <li class="ltr"><code>/warp/</code> Warp template</li>
      <li class="ltr"><code>/panel</code> This panel</li>
    </ul>
  </div>
</section>

<section id="sec-security" class="section">
  <div class="warn" data-i18n="warn_ban"><strong>Operating notes:</strong> use your own domain, keep the panel at /panel, and leave Proxy IP empty unless a direct connection fails.</div>
  <div class="card">
    <h3 data-i18n="chg_pass">تغییر رمز</h3>
    <input id="curP" type="password" autocomplete="current-password" data-i18n-ph="ph_cur" placeholder="رمز فعلی">
    <input id="newP" type="password" autocomplete="new-password" data-i18n-ph="ph_new" placeholder="رمز جدید" style="margin-top:.55rem">
    <button type="button" style="margin-top:.8rem" onclick="chgPass()" data-i18n="btn_chg">تغییر</button>
    <div class="err" id="pwE"></div>
  </div>
</section>
<footer class="panel">Panel Pro ${VERSION}</footer>
</div>

<div class="modal-bg" id="em">
  <div class="modal" role="dialog" aria-modal="true">
    <h3 data-i18n="edit_user">ویرایش</h3>
    <input type="hidden" id="eu">
    <input id="eg" data-i18n-ph="ph_gb" placeholder="GB">
    <input id="edays" data-i18n-ph="ph_days" placeholder="Days">
    <input id="emd" data-i18n-ph="ph_devices" placeholder="Devices">
    <input id="eri" data-i18n-ph="ph_reset" placeholder="Reset N days">
    <input id="edrl" data-i18n-ph="ph_daily" placeholder="Daily limit">
    <input id="enote" data-i18n-ph="ph_note" placeholder="Note">
    <select id="eproto"><option value="vless">VLESS</option><option value="trojan">Trojan</option><option value="both">Both</option></select>
    <div class="row-actions">
      <button type="button" class="ghost" onclick="closeEdit()" data-i18n="btn_cancel">انصراف</button>
      <button type="button" onclick="saveEdit()" data-i18n="btn_save">ذخیره</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
var I18N = {
  fa: {
    nav_users:"کاربران", nav_settings:"تنظیمات", nav_security:"امنیت", nav_logout:"خروج",
    stat_total:"کل کاربران", stat_active:"فعال", stat_online:"اتصال آنلاین", stat_usage:"مصرف GB",
    add_user:"کاربر جدید", add_help:"نام کاربری لازم است. بقیه فیلدها اختیاری‌اند.", btn_add:"افزودن کاربر",
    users_list:"فهرست کاربران", ph_username:"نام کاربری *", ph_gb:"سقف حجم GB", ph_days:"مدت اعتبار، روز",
    ph_devices:"حداکثر دستگاه", ph_reset:"ریست حجم هر N روز", ph_daily:"سقف درخواست روزانه", ph_note:"یادداشت",
    ph_search:"جستجوی نام...", opt_both:"هر دو", btn_refresh:"تازه‌سازی", btn_export:"خروجی JSON",
    bulk_enable:"فعال‌سازی", bulk_disable:"غیرفعال", bulk_reset:"ریست مصرف", bulk_delete:"حذف",
    th_user:"کاربر", th_proto:"پروتکل", th_status:"وضعیت", th_usage:"مصرف", th_online:"آنلاین", th_actions:"عملیات",
    set_clean:"آدرس‌های Clean IP", set_clean_h:"هر خط یک آدرس. اگر اتصال برقرار نیست، فهرست را خالی بگذار.",
    set_proxy:"آدرس جایگزین Proxy IP", set_proxy_h:"اختیاری. فقط پس از شکست اتصال مستقیم استفاده می‌شود.",
    set_frag:"Fragment", set_frag_h:"روی اشتراک Sing-box اعمال می‌شود. مسیر /singbox-frag/ همیشه آن را روشن می‌کند. عدد اولِ فاصله، تأخیر fragment به میلی‌ثانیه است.",
    frag_toggle:"روشن برای اشتراک معمولی Sing-box", btn_save_all:"ذخیره تنظیمات",
    set_linkopt:"گزینه‌های TLS", set_linkopt_h:"Fingerprint و ALPN که در همه‌ی لینک‌ها و اشتراک‌ها استفاده می‌شود. برای ws روی ایرانسل http/1.1 را انتخاب کنید.", lbl_fp:"Fingerprint", lbl_alpn:"ALPN",
    set_warp:"نقاط Warp", set_camo:"نام سایت عمومی", set_camo_h:"این نام در صفحه اول، بیرون از پنل، دیده می‌شود.",
    set_links:"مسیرهای اشتراک", warn_ban:"<strong>نکته عملیاتی:</strong> از دامنه خودتان استفاده کنید، پنل را فقط در /panel نگه دارید، و Proxy IP را خالی بگذارید مگر اتصال مستقیم شکست بخورد.",
    chg_pass:"تغییر رمز پنل", ph_cur:"رمز فعلی", ph_new:"رمز جدید", btn_chg:"تغییر رمز",
    edit_user:"ویرایش کاربر", btn_cancel:"انصراف", btn_save:"ذخیره",
    toast_saved:"ذخیره شد", status_on:"فعال", status_off:"خاموش",
    empty:"هنوز کاربری ساخته نشده", nomatch:"نتیجه‌ای برای این جستجو نیست",
    act_uuid:"UUID", act_pass:"رمز", act_sub:"اشتراک", act_clash:"Clash", act_sb:"Sing-box", act_qr:"QR",
    act_edit:"ویرایش", act_toggle:"وضعیت", act_reset:"ریست", act_del:"حذف"
  },
  en: {
    nav_users:"Users", nav_settings:"Settings", nav_security:"Security", nav_logout:"Sign out",
    stat_total:"Users", stat_active:"Active", stat_online:"Online", stat_usage:"Usage GB",
    add_user:"New user", add_help:"Username is required. Every other field is optional.", btn_add:"Add user",
    users_list:"Directory", ph_username:"Username *", ph_gb:"Traffic cap, GB", ph_days:"Validity, days",
    ph_devices:"Device limit", ph_reset:"Reset traffic every N days", ph_daily:"Daily request cap", ph_note:"Note",
    ph_search:"Search name...", opt_both:"Both", btn_refresh:"Refresh", btn_export:"Export JSON",
    bulk_enable:"Enable", bulk_disable:"Disable", bulk_reset:"Reset usage", bulk_delete:"Delete",
    th_user:"User", th_proto:"Protocol", th_status:"Status", th_usage:"Usage", th_online:"Online", th_actions:"Actions",
    set_clean:"Clean addresses", set_clean_h:"One address per line. Leave this empty if the connection does not come up.",
    set_proxy:"Fallback proxy address", set_proxy_h:"Optional. Used only after a direct connection fails.",
    set_frag:"Fragment", set_frag_h:"Applied to Sing-box subscriptions. /singbox-frag/ always enables it. The first interval number becomes the fragment delay in milliseconds.",
    frag_toggle:"On for the normal Sing-box subscription", btn_save_all:"Save settings",
    set_linkopt:"TLS options", set_linkopt_h:"Fingerprint and ALPN used in all generated links and subscriptions. For ws on Irancell choose http/1.1.", lbl_fp:"Fingerprint", lbl_alpn:"ALPN",
    set_warp:"Warp endpoints", set_camo:"Public site name", set_camo_h:"Shown on the public homepage, outside this panel.",
    set_links:"Subscription paths", warn_ban:"<strong>Operating notes:</strong> use your own domain, keep this panel at /panel, and leave Proxy IP empty unless a direct connection fails.",
    chg_pass:"Change panel password", ph_cur:"Current password", ph_new:"New password", btn_chg:"Change password",
    edit_user:"Edit user", btn_cancel:"Cancel", btn_save:"Save",
    toast_saved:"Saved", status_on:"Active", status_off:"Off",
    empty:"No users yet", nomatch:"No users match this search",
    act_uuid:"UUID", act_pass:"Pass", act_sub:"Sub", act_clash:"Clash", act_sb:"Sing-box", act_qr:"QR",
    act_edit:"Edit", act_toggle:"Status", act_reset:"Reset", act_del:"Delete"
  }
};
var lang = localStorage.getItem('lang') || 'fa';
var users = [];
var online = {};
function el(id){ return document.getElementById(id); }
function t(k){ return (I18N[lang] && I18N[lang][k]) || k; }
function esc(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){ return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]; }); }
function toast(m){ var n = el('toast'); n.textContent = m; n.classList.add('show'); setTimeout(function(){ n.classList.remove('show'); }, 2200); }
function applyI18n(){
  document.documentElement.lang = lang;
  document.body.classList.toggle('en', lang === 'en');
  document.querySelectorAll('[data-i18n]').forEach(function(node){
    var k = node.getAttribute('data-i18n');
    if (k === 'warn_ban') node.innerHTML = t(k); else node.textContent = t(k);
  });
  document.querySelectorAll('[data-i18n-ph]').forEach(function(node){ node.placeholder = t(node.getAttribute('data-i18n-ph')); });
  el('btn-fa').style.opacity = lang === 'fa' ? '1' : '.45';
  el('btn-en').style.opacity = lang === 'en' ? '1' : '.45';
  updateFragLabel();
  render();
}
function setLang(next){ lang = next; localStorage.setItem('lang', next); applyI18n(); }
function show(name){
  document.querySelectorAll('.section').forEach(function(s){ s.classList.remove('active'); });
  el('sec-' + name).classList.add('active');
  ['users','settings','security'].forEach(function(id){ el('nav-' + id).classList.toggle('onpage', id === name); });
}
function toggleTheme(){
  document.body.classList.toggle('light');
  var light = document.body.classList.contains('light');
  el('tb').textContent = light ? 'Day' : 'Night';
  localStorage.setItem('th', light ? 'l' : 'd');
}
if (localStorage.getItem('th') === 'l') { document.body.classList.add('light'); el('tb').textContent = 'Day'; }
function updateFragLabel(){
  var on = el('fragEn').checked;
  var lb = el('fragLabel');
  lb.textContent = on ? (lang === 'fa' ? 'روشن' : 'ON') : (lang === 'fa' ? 'خاموش' : 'OFF');
  lb.className = 'frag-status ' + (on ? 'on' : 'off');
}
el('fragEn').addEventListener('change', updateFragLabel);
async function load(){
  try {
    var res = await Promise.all([fetch('/api/users'), fetch('/api/online')]);
    if (res[0].status === 401 || res[1].status === 401) { location.reload(); return; }
    if (!res[0].ok || !res[1].ok) return;
    users = (await res[0].json()).users || [];
    var od = await res[1].json();
    online = od.online || {};
    render();
    var used = 0, active = 0;
    users.forEach(function(u){ used += Number(u.used_gb || 0); if (u.is_active) active++; });
    el('sT').textContent = String(users.length);
    el('sA').textContent = String(active);
    el('sO').textContent = String(od.total || 0);
    el('sU').textContent = used.toFixed(2);
  } catch (e) {}
}
function render(){
  var q = (el('search').value || '').toLowerCase();
  var rows = q ? users.filter(function(u){ return String(u.username).toLowerCase().indexOf(q) >= 0; }) : users;
  var tb = document.querySelector('#t tbody');
  el('chkAll').checked = false;
  if (!rows.length) {
    tb.innerHTML = '<tr><td colspan="7" class="empty">' + esc(users.length ? t('nomatch') : t('empty')) + '</td></tr>';
    return;
  }
  tb.innerHTML = rows.map(function(u){
    var name = esc(u.username);
    var used = Number(u.used_gb || 0);
    var lim = u.limit_gb == null || u.limit_gb === '' ? 0 : Number(u.limit_gb);
    var pct = lim > 0 ? Math.min(100, (used / lim) * 100) : 0;
    var tone = lim > 0 && used > lim ? 'bad' : (lim > 0 && pct >= 85 ? 'warn' : '');
    var proto = u.protocol || 'vless';
    var oc = (online[u.uuid] || []).length;
    var hasUuid = !!(u.uuid && String(u.uuid).length > 8);
    var uuidShort = hasUuid ? esc(String(u.uuid).slice(0, 8) + '…') : '—';
    var cap = lim > 0 ? lim : '∞';
    return '<tr>' +
      '<td><input type="checkbox" class="us" value="' + name + '"></td>' +
      '<td><strong>' + name + '</strong><div class="mono">' + uuidShort + '</div>' +
        (u.note ? '<div class="muted">' + esc(u.note) + '</div>' : '') + '</td>' +
      '<td><span class="badge ' + esc(proto) + '">' + esc(proto) + '</span></td>' +
      '<td><span class="pill ' + (u.is_active ? 'on' : 'off') + '">' + esc(u.is_active ? t('status_on') : t('status_off')) + '</span></td>' +
      '<td><div class="mono">' + used.toFixed(2) + ' / ' + cap + '</div>' +
        (lim > 0 ? '<div class="meter"><span class="' + tone + '" style="width:' + pct.toFixed(1) + '%"></span></div>' : '') + '</td>' +
      '<td>' + (oc ? '<span class="live">' + oc + '</span>' : '<span class="muted">—</span>') + '</td>' +
      '<td><div class="actions">' +
        '<button type="button" class="link" data-act="uuid" data-user="' + name + '">' + esc(t('act_uuid')) + '</button>' +
        '<button type="button" class="link" data-act="pass" data-user="' + name + '">' + esc(t('act_pass')) + '</button>' +
        '<button type="button" class="link" data-act="sub" data-user="' + name + '">' + esc(t('act_sub')) + '</button>' +
        '<button type="button" class="link" data-act="clash" data-user="' + name + '">' + esc(t('act_clash')) + '</button>' +
        '<button type="button" class="link" data-act="sb" data-user="' + name + '">' + esc(t('act_sb')) + '</button>' +
        '<button type="button" class="link" data-act="qr" data-user="' + name + '">' + esc(t('act_qr')) + '</button>' +
        '<button type="button" class="link" data-act="edit" data-user="' + name + '">' + esc(t('act_edit')) + '</button>' +
        '<button type="button" class="link" data-act="toggle" data-user="' + name + '">' + esc(t('act_toggle')) + '</button>' +
        '<button type="button" class="link" data-act="reset" data-user="' + name + '">' + esc(t('act_reset')) + '</button>' +
        '<button type="button" class="link danger" data-act="del" data-user="' + name + '">' + esc(t('act_del')) + '</button>' +
      '</div></td></tr>';
  }).join('');
}
function userByName(name){ return users.filter(function(u){ return u.username === name; })[0]; }
function subUrl(kind, name){ return location.origin + '/' + kind + '/' + encodeURIComponent(name); }
function copyText(value, label){
  if (!value) return;
  navigator.clipboard.writeText(value).then(function(){ toast(label); }).catch(function(){ prompt(label, value); });
}
el('t').addEventListener('click', function(ev){
  var btn = ev.target.closest('[data-act]');
  if (!btn) return;
  var name = btn.getAttribute('data-user');
  var user = userByName(name);
  var act = btn.getAttribute('data-act');
  if (act === 'uuid') { if (user && user.uuid && String(user.uuid).length > 8) copyText(user.uuid, 'UUID'); else regenUuid(name); }
  else if (act === 'pass') copyText((user && (user.trojan_pass || user.uuid)) || '', 'Pass');
  else if (act === 'sub') copyText(subUrl('sub', name), 'Sub');
  else if (act === 'clash') copyText(subUrl('clash', name), 'Clash');
  else if (act === 'sb') copyText(subUrl('singbox', name), 'Sing-box');
  else if (act === 'qr') window.open(subUrl('qr', name), '_blank', 'noopener');
  else if (act === 'edit') openE(name);
  else if (act === 'toggle') tog(name);
  else if (act === 'reset') rst(name);
  else if (act === 'del') del(name);
});
el('chkAll').addEventListener('change', function(){
  var on = this.checked;
  document.querySelectorAll('.us').forEach(function(box){ box.checked = on; });
});
el('search').addEventListener('input', render);
el('u').addEventListener('keydown', function(e){ if (e.key === 'Enter') addUser(); });
async function addUser(){
  var errBox = el('e');
  errBox.textContent = '';
  el('made').hidden = true;
  var username = (el('u').value || '').trim();
  if (!username) { errBox.textContent = lang === 'fa' ? 'نام کاربری را وارد کن' : 'Enter a username'; return; }
  var body = {
    username: username, protocol: el('proto').value,
    limit_gb: el('g').value.trim(), expiry_days: el('d').value.trim(),
    max_devices: el('md').value.trim(), reset_interval_days: el('ri').value.trim(),
    daily_request_limit: el('drl').value.trim(), note: el('note').value.trim()
  };
  try {
    var r = await fetch('/api/users', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
    var raw = await r.text();
    var data = {};
    try { data = JSON.parse(raw); } catch (e) { data = { error: raw || ('HTTP ' + r.status) }; }
    if (!r.ok || data.error) { errBox.textContent = data.error || ('Error ' + r.status); return; }
    ['u','g','d','md','ri','drl','note'].forEach(function(id){ el(id).value = ''; });
    var made = el('made');
    made.hidden = false;
    made.textContent = 'UUID: ' + data.uuid + (data.trojan_pass ? '   |   Trojan: ' + data.trojan_pass : '');
    copyText(data.uuid, 'UUID');
    toast(t('toast_saved'));
    await load();
  } catch (ex) {
    errBox.textContent = String(ex && ex.message ? ex.message : ex);
  }
}
async function regenUuid(name){
  if (!confirm(lang === 'fa' ? 'UUID و رمز Trojan این کاربر عوض شود؟' : 'Replace this user UUID and Trojan password?')) return;
  var r = await fetch('/api/users/' + encodeURIComponent(name), { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ regen_uuid:true }) });
  var data = await r.json();
  if (data.uuid) copyText(data.uuid, 'UUID');
  load();
}
async function tog(name){ await fetch('/api/users/' + encodeURIComponent(name), { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ toggle:true }) }); load(); }
async function rst(name){ await fetch('/api/users/' + encodeURIComponent(name), { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ reset_usage:true }) }); toast(t('toast_saved')); load(); }
async function del(name){
  if (!confirm(lang === 'fa' ? 'حذف ' + name + ' ؟' : 'Delete ' + name + '?')) return;
  await fetch('/api/users/' + encodeURIComponent(name), { method:'DELETE' });
  toast(t('toast_saved'));
  load();
}
async function bulk(action){
  var names = [].map.call(document.querySelectorAll('.us:checked'), function(box){ return box.value; });
  if (!names.length) { toast(lang === 'fa' ? 'کسی انتخاب نشده' : 'Nothing selected'); return; }
  if (action === 'delete' && !confirm(lang === 'fa' ? 'حذف ' + names.length + ' کاربر؟' : 'Delete ' + names.length + ' users?')) return;
  await fetch('/api/users/bulk', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ usernames: names, action: action }) });
  toast(t('toast_saved'));
  load();
}
function openE(name){
  var user = userByName(name);
  if (!user) return;
  el('eu').value = name;
  el('eg').value = user.limit_gb || '';
  el('edays').value = user.expiry_days || '';
  el('emd').value = user.max_devices || '';
  el('eri').value = user.reset_interval_days || '';
  el('edrl').value = user.daily_request_limit || '';
  el('enote').value = user.note || '';
  el('eproto').value = user.protocol || 'vless';
  el('em').classList.add('show');
}
function closeEdit(){ el('em').classList.remove('show'); }
async function saveEdit(){
  await fetch('/api/users/' + encodeURIComponent(el('eu').value), { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({
    limit_gb: el('eg').value, expiry_days: el('edays').value, max_devices: el('emd').value,
    reset_interval_days: el('eri').value, daily_request_limit: el('edrl').value,
    note: el('enote').value, protocol: el('eproto').value
  }) });
  closeEdit();
  toast(t('toast_saved'));
  load();
}
document.addEventListener('keydown', function(e){ if (e.key === 'Escape') closeEdit(); });
async function saveSet(){
  var r = await fetch('/api/settings', { method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify({
    clean_ips: el('cleanIps').value, proxy_ips: el('proxyIps').value, default_remark: el('remark').value,
    fragment_enabled: el('fragEn').checked, fragment_length: el('fragLen').value, fragment_interval: el('fragInt').value,
    camouflage_name: el('camName').value, warp_endpoints: el('warpEp').value,
    link_fp: el('linkFp').value, link_alpn: el('linkAlpn').value
  }) });
  if (r.status === 401) { location.reload(); return; }
  toast(t('toast_saved'));
  await loadSet();
}
async function loadSet(){
  var r = await fetch('/api/settings');
  if (r.status === 401) { location.reload(); return; }
  if (!r.ok) return;
  var d = await r.json();
  el('cleanIps').value = d.clean_ips || '';
  el('proxyIps').value = d.proxy_ips || '';
  el('remark').value = d.default_remark || 'Pro';
  el('fragEn').checked = d.fragment_enabled === true || d.fragment_enabled === '1' || d.fragment_enabled === 1;
  el('fragLen').value = d.fragment_length || '100-200';
  el('fragInt').value = d.fragment_interval || '10-20';
  el('camName').value = d.camouflage_name || 'Northline Cloud';
  el('warpEp').value = d.warp_endpoints || 'engage.cloudflareclient.com:2408';
  el('linkFp').value = d.link_fp || 'chrome';
  el('linkAlpn').value = d.link_alpn || 'h2,http/1.1';
  updateFragLabel();
}
async function chgPass(){
  var r = await fetch('/api/change-password', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ current: el('curP').value, next: el('newP').value }) });
  var data = await r.json();
  if (data.error) { el('pwE').textContent = data.error; return; }
  el('pwE').textContent = '';
  el('curP').value = '';
  el('newP').value = '';
  toast(t('toast_saved'));
}
async function exportU(){
  var data = await (await fetch('/api/export')).json();
  var a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type:'application/json' }));
  a.download = 'panel-backup.json';
  a.click();
}
async function logout(){ await fetch('/api/logout', { method:'POST' }); location.reload(); }
applyI18n();
show('users');
load();
loadSet();
setInterval(load, 45000);
</script></body></html>`;

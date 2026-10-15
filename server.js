// Railway / Node entry point. Loads worker-pro.js as-is and serves it over HTTP + WebSocket.
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { D1, completeHandshake } from "./runtime.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const runtimeUrl = pathToFileURL(path.join(here, "runtime.mjs")).href;

// Build a Node-compatible copy of the worker in memory (two small substitutions).
let src = fs.readFileSync(path.join(here, "worker-pro.js"), "utf8");
function swap(from, to) {
  if (src.split(from).length !== 2) throw new Error("worker-pro.js changed: cannot find " + from);
  src = src.replace(from, () => to);
}
swap('import { connect } from "cloudflare:sockets";', `import { connect, makeWsResponse } from ${JSON.stringify(runtimeUrl)};`);
swap('new Response(null, { status: 101, webSocket: client, headers })', "makeWsResponse(client, headers)");
const genFile = path.join(os.tmpdir(), `worker-node-${process.pid}.mjs`);
fs.writeFileSync(genFile, src);
const worker = (await import(pathToFileURL(genFile).href)).default;
fs.rmSync(genFile, { force: true });

const env = { DB: new D1(process.env.DB_PATH || path.join(here, "data", "panel.db")) };
const MAX_BODY = 8 * 1024 * 1024;

function clientIp(req) {
  const cf = req.headers["cf-connecting-ip"];
  if (cf) return String(cf);
  const xff = req.headers["x-forwarded-for"];
  if (xff) return String(xff).split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}
function toRequest(req, body) {
  const proto = String(req.headers["x-forwarded-proto"] || "https").split(",")[0].trim();
  const host = req.headers["x-forwarded-host"] || req.headers.host || "localhost";
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) {
    if (Array.isArray(v)) v.forEach((x) => headers.append(k, x)); else if (v != null) headers.set(k, String(v));
  }
  headers.set("cf-connecting-ip", clientIp(req));
  const init = { method: req.method, headers };
  if (body && body.length && req.method !== "GET" && req.method !== "HEAD") init.body = body;
  return new Request(`${proto}://${host}${req.url}`, init);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on("data", (c) => { n += c.length; if (n > MAX_BODY) { reject(new Error("body too large")); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  try {
    const body = await readBody(req);
    const resp = await worker.fetch(toRequest(req, body), env, {});
    res.statusCode = resp.status;
    for (const [k, v] of resp.headers) {
      if (["set-cookie", "content-encoding", "content-length", "transfer-encoding", "connection"].includes(k)) continue;
      res.setHeader(k, v);
    }
    const cookies = resp.headers.getSetCookie ? resp.headers.getSetCookie() : [];
    if (cookies.length) res.setHeader("set-cookie", cookies);
    const out = Buffer.from(await resp.arrayBuffer());
    res.setHeader("content-length", out.length);
    res.end(req.method === "HEAD" ? undefined : out);
  } catch (e) {
    if (!res.headersSent) { res.statusCode = 500; res.setHeader("content-type", "text/plain"); }
    res.end("Internal error");
    console.error("request error:", e && e.message);
  }
});

server.on("upgrade", async (req, socket, head) => {
  socket.on("error", () => {});
  try {
    const resp = await worker.fetch(toRequest(req, null), env, {});
    if (resp && resp.webSocket) { completeHandshake(req, socket, head, resp); return; }
    socket.end(`HTTP/1.1 ${resp.status || 400} Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
  } catch (e) {
    console.error("upgrade error:", e && e.message);
    socket.end("HTTP/1.1 500 Internal Server Error\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
  }
});

const port = Number(process.env.PORT) || 3000;
server.on("error", (e) => {
  if (e.code === "EAFNOSUPPORT" || e.code === "EADDRNOTAVAIL") server.listen(port, "0.0.0.0");
  else { console.error(e); process.exit(1); }
});
server.listen(port, "::", () => console.log(`Panel listening on :${port}`));
process.on("SIGTERM", () => process.exit(0));

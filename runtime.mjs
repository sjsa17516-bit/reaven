// Node.js runtime shims that let the Cloudflare Worker run unchanged on Railway:
//   - D1-compatible database on top of node:sqlite
//   - connect() from "cloudflare:sockets" on top of node:net
//   - WebSocketPair + a small RFC 6455 server (no dependencies)
import net from "node:net";
import dns from "node:dns/promises";
import crypto from "node:crypto";
import { Readable, Writable } from "node:stream";
import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------- D1 ----
function norm(v) {
  if (v === undefined) return null;
  if (typeof v === "boolean") return v ? 1 : 0;
  return v;
}
class Stmt {
  constructor(db, sql) { this.db = db; this.sql = sql; this.args = []; }
  bind(...a) { this.args = a.map(norm); return this; }
  _prep() { return this.db.prepare(this.sql); } // lazy: SQL errors become rejections, like D1
  async run() {
    const r = this._prep().run(...this.args);
    return { success: true, meta: { last_row_id: Number(r.lastInsertRowid), changes: Number(r.changes) } };
  }
  async first() {
    const r = this._prep().get(...this.args);
    return r ? { ...r } : null;
  }
  async all() {
    return { results: this._prep().all(...this.args).map((r) => ({ ...r })) };
  }
}
export class D1 {
  constructor(file) {
    fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;");
  }
  prepare(sql) { return new Stmt(this.db, sql); }
}

// ------------------------------------------------------------ sockets ----
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
  }
  const x = ip.toLowerCase();
  if (x.startsWith("::ffff:")) return isPrivate(x.slice(7));
  return x === "::" || x === "::1" || x.startsWith("fc") || x.startsWith("fd") || x.startsWith("fe8") ||
    x.startsWith("fe9") || x.startsWith("fea") || x.startsWith("feb");
}
export async function connect({ hostname, port }) {
  let host = hostname;
  if (!net.isIP(host)) {
    const r = await dns.lookup(host, { all: true });
    if (!r.length) throw new Error("dns failed");
    host = r[0].address;
  }
  if (process.env.ALLOW_PRIVATE !== "1" && isPrivate(host)) throw new Error("private address blocked");
  const sock = net.connect({ host, port });
  sock.setNoDelay(true);
  await new Promise((resolve, reject) => {
    const t = setTimeout(() => { sock.destroy(); reject(new Error("connect timeout")); }, 10000);
    sock.once("connect", () => { clearTimeout(t); resolve(); });
    sock.once("error", (e) => { clearTimeout(t); reject(e); });
  });
  sock.on("error", () => {});
  return {
    readable: Readable.toWeb(sock),
    writable: Writable.toWeb(sock),
    close() { sock.destroy(); },
  };
}

// ---------------------------------------------------------- WebSocket ----
const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_MSG = 16 * 1024 * 1024;

function frame(op, payload) {
  const len = payload.length;
  let head;
  if (len < 126) { head = Buffer.alloc(2); head[1] = len; }
  else if (len < 65536) { head = Buffer.alloc(4); head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  head[0] = 0x80 | op;
  return Buffer.concat([head, payload]);
}
function toBuf(d) {
  if (typeof d === "string") return Buffer.from(d);
  if (d instanceof ArrayBuffer) return Buffer.from(d);
  if (ArrayBuffer.isView(d)) return Buffer.from(d.buffer, d.byteOffset, d.byteLength);
  return Buffer.from(String(d));
}

class WsEnd {
  constructor() { this.l = { message: [], close: [], error: [] }; this.sock = null; this.closed = false; this.pending = []; this.timer = null; }
  accept() {}
  addEventListener(type, fn) { (this.l[type] ||= []).push(fn); }
  _emit(type, ev) { for (const fn of this.l[type] || []) { try { fn(ev); } catch { /* listener error */ } } }
  _write(buf) {
    if (this.closed) return;
    if (!this.sock) { this.pending.push(buf); return; }
    this.sock.write(buf);
  }
  send(data) { this._write(frame(typeof data === "string" ? 1 : 2, toBuf(data))); }
  close(code = 1000, reason = "") {
    if (this.closed) return;
    const r = Buffer.from(String(reason || "")).subarray(0, 120);
    const p = Buffer.alloc(2 + r.length);
    p.writeUInt16BE(code >= 1000 && code < 5000 && code !== 1005 && code !== 1006 ? code : 1000, 0);
    r.copy(p, 2);
    this._write(frame(8, p));
    this._finish(code);
    const s = this.sock;
    if (s) { s.end(); setTimeout(() => s.destroy(), 2000).unref(); }
  }
  _finish(code) {
    if (this.closed) return;
    this.closed = true;
    clearInterval(this.timer);
    this._emit("close", { code, wasClean: code === 1000 });
  }
  attach(sock, head) {
    this.sock = sock;
    sock.setNoDelay(true);
    sock.on("error", () => {});
    sock.on("close", () => this._finish(1006));
    this.timer = setInterval(() => { if (!this.closed) sock.write(frame(9, Buffer.alloc(0))); }, 25000);
    this.timer.unref();
    for (const b of this.pending.splice(0)) sock.write(b);
    if (this.closed) { sock.end(); return; }
    let buf = Buffer.alloc(0);
    let frag = []; let fragLen = 0; let fragOp = 0;
    const fail = (code) => this.close(code);
    const onData = (d) => {
      buf = buf.length ? Buffer.concat([buf, d]) : d;
      while (buf.length >= 2 && !this.closed) {
        const fin = !!(buf[0] & 0x80), op = buf[0] & 0x0f, masked = !!(buf[1] & 0x80);
        let len = buf[1] & 0x7f, off = 2;
        if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
        else if (len === 127) {
          if (buf.length < 10) return;
          const big = buf.readBigUInt64BE(2);
          if (big > BigInt(MAX_MSG)) return fail(1009);
          len = Number(big); off = 10;
        }
        if (!masked) return fail(1002);
        if (len > MAX_MSG) return fail(1009);
        if (buf.length < off + 4 + len) return;
        const mask = buf.subarray(off, off + 4);
        const payload = Buffer.allocUnsafe(len);
        const src = buf.subarray(off + 4, off + 4 + len);
        for (let i = 0; i < len; i++) payload[i] = src[i] ^ mask[i & 3];
        buf = buf.subarray(off + 4 + len);
        if (op === 8) { this.close(payload.length >= 2 ? payload.readUInt16BE(0) : 1000); return; }
        if (op === 9) { this._write(frame(10, payload)); continue; }
        if (op === 10) continue;
        if (op === 1 || op === 2) { frag = []; fragLen = 0; fragOp = op; }
        else if (op !== 0) return fail(1002);
        frag.push(payload); fragLen += len;
        if (fragLen > MAX_MSG) return fail(1009);
        if (fin) {
          const msg = frag.length === 1 ? frag[0] : Buffer.concat(frag);
          frag = []; fragLen = 0;
          const data = fragOp === 1 ? msg.toString("utf8")
            : msg.buffer.slice(msg.byteOffset, msg.byteOffset + msg.byteLength);
          this._emit("message", { data });
        }
      }
    };
    sock.on("data", onData);
    if (head && head.length) onData(Buffer.from(head));
  }
}
class WebSocketPairShim {
  constructor() {
    const server = new WsEnd();
    this[0] = { _server: server };
    this[1] = server;
  }
}
globalThis.WebSocketPair = WebSocketPairShim;

export function makeWsResponse(client, headers) {
  return { status: 101, headers: headers || {}, webSocket: client };
}

export function completeHandshake(req, socket, head, response) {
  const key = req.headers["sec-websocket-key"];
  if (!key) { socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"); return; }
  const accept = crypto.createHash("sha1").update(key + GUID).digest("base64");
  const lines = [
    "HTTP/1.1 101 Switching Protocols", "Upgrade: websocket", "Connection: Upgrade",
    `Sec-WebSocket-Accept: ${accept}`,
  ];
  const proto = response.headers["Sec-WebSocket-Protocol"];
  if (proto && /^[\x21-\x7e]+$/.test(proto)) lines.push(`Sec-WebSocket-Protocol: ${proto}`);
  socket.write(lines.join("\r\n") + "\r\n\r\n");
  response.webSocket._server.attach(socket, head);
}

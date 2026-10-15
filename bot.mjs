// Telegram management bot for the panel. Runs inside the same Node process (no dependencies).
// Env: BOT_TOKEN (from @BotFather), ADMIN_IDS (comma-separated numeric Telegram IDs),
//      PANEL_URL (optional, e.g. https://xxx.up.railway.app; defaults to RAILWAY_PUBLIC_DOMAIN)
import crypto from "node:crypto";

const API = process.env.TELEGRAM_API || "https://api.telegram.org";
const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function sqlTime(s) { return Date.parse(String(s).replace(" ", "T") + "Z"); }
function fmtGb(n) { return (Math.round(Number(n || 0) * 100) / 100).toString(); }
function daysLeft(u) {
  if (!u.expiry_days || !u.created_at) return null;
  const end = sqlTime(u.created_at) + Number(u.expiry_days) * 86400000;
  return Number.isNaN(end) ? null : Math.ceil((end - Date.now()) / 86400000);
}
function statusIcon(u) {
  if (!u.is_active) return "⛔";
  const d = daysLeft(u);
  if (d !== null && d <= 0) return "⌛";
  if (u.limit_gb && Number(u.used_gb || 0) >= Number(u.limit_gb)) return "🚫";
  return "🟢";
}
function usageLine(u) {
  const d = daysLeft(u);
  return `${statusIcon(u)} <b>${esc(u.username)}</b> — ${fmtGb(u.used_gb)}/${u.limit_gb ? fmtGb(u.limit_gb) + " GB" : "∞"}` +
    (d === null ? "" : d > 0 ? ` — ${d} روز` : " — منقضی");
}

export function startBot({ env, worker }) {
  const token = process.env.BOT_TOKEN;
  if (!token) return;
  const admins = new Set(String(process.env.ADMIN_IDS || "").split(",").map((s) => s.trim()).filter(Boolean));
  const db = env.DB;

  async function tg(method, body) {
    const res = await fetch(`${API}/bot${token}/${method}`, {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body || {}),
    });
    return res.json();
  }
  const send = (chat, text, extra = {}) => tg("sendMessage", { chat_id: chat, text, parse_mode: "HTML", disable_web_page_preview: true, ...extra });
  async function sendLong(chat, lines) {
    let buf = "";
    for (const l of lines) {
      if (buf.length + l.length + 1 > 3800) { await send(chat, buf); buf = ""; }
      buf += l + "\n";
    }
    if (buf) await send(chat, buf);
  }
  function base() {
    const p = process.env.PANEL_URL || (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : "");
    return p.replace(/\/+$/, "");
  }
  async function getUser(name) { return db.prepare("SELECT * FROM users WHERE username=?").bind(name).first(); }
  function links(u) {
    const b = base();
    if (!b) return "آدرس پنل مشخص نیست. متغیر PANEL_URL را در Railway تنظیم کن.";
    const n = encodeURIComponent(u.username);
    return `🔗 <b>اشتراک</b>\n<code>${esc(b)}/sub/${n}</code>\n\n<b>Clash</b>\n<code>${esc(b)}/clash/${n}</code>\n\n<b>Sing-box</b>\n<code>${esc(b)}/singbox/${n}</code>\n\n<b>QR</b>\n${esc(b)}/qr/${n}`;
  }
  const num = (v) => { if (v === undefined || v === "-" || v === "0") return null; const n = Number(v); return Number.isFinite(n) && n > 0 ? n : NaN; };

  const HELP = [
    "<b>دستورها</b>",
    "/users — لیست کاربران",
    "/add <code>نام [گیگ] [روز] [vless|trojan|both]</code> — ساخت کاربر",
    "/info <code>نام</code> — جزئیات و لینک‌ها",
    "/link <code>نام</code> — لینک‌های اشتراک",
    "/toggle <code>نام</code> — فعال/غیرفعال",
    "/reset <code>نام</code> — صفر کردن مصرف",
    "/newuuid <code>نام</code> — ساخت UUID جدید",
    "/del <code>نام</code> — حذف کاربر",
    "/stats — آمار کلی",
    "برای نامحدود، گیگ یا روز را <code>-</code> بگذار.",
  ].join("\n");

  async function handleCommand(chat, text) {
    const [cmdRaw, ...args] = text.trim().split(/\s+/);
    const cmd = cmdRaw.split("@")[0].toLowerCase();
    const name = args[0];
    const need = async () => {
      if (!name) { await send(chat, "نام کاربر را بنویس. مثال: <code>" + esc(cmd) + " ali</code>"); return null; }
      const u = await getUser(name);
      if (!u) { await send(chat, "کاربری با این نام نیست."); return null; }
      return u;
    };
    switch (cmd) {
      case "/start": case "/help": return send(chat, HELP);
      case "/users": {
        const { results } = await db.prepare("SELECT * FROM users ORDER BY id DESC LIMIT 60").all();
        if (!results.length) return send(chat, "هنوز کاربری نیست. با /add بساز.");
        return sendLong(chat, results.map(usageLine));
      }
      case "/stats": {
        const t = await db.prepare("SELECT COUNT(*) c, SUM(is_active) a, SUM(used_gb) g FROM users").first();
        await db.prepare("DELETE FROM active_connections WHERE connected_at < datetime('now','-30 minutes')").run();
        const o = await db.prepare("SELECT COUNT(*) c FROM active_connections").first();
        return send(chat, `کاربران: <b>${t.c || 0}</b> (فعال: ${t.a || 0})\nاتصال‌های آنلاین: <b>${o.c || 0}</b>\nمصرف کل: <b>${fmtGb(t.g)} GB</b>`);
      }
      case "/add": {
        if (!name) return send(chat, "مثال: <code>/add ali 10 30</code> (۱۰ گیگ، ۳۰ روز)");
        if (name.length < 2 || name.length > 32 || /[\u0000-\u001f/\\]/.test(name)) return send(chat, "نام باید ۲ تا ۳۲ نویسه و بدون / و \\ باشد.");
        if (await getUser(name)) return send(chat, "این نام قبلاً وجود دارد.");
        const gb = num(args[1]), days = num(args[2]);
        if (Number.isNaN(gb) || Number.isNaN(days)) return send(chat, "گیگ و روز باید عدد مثبت یا <code>-</code> باشند.");
        const proto = ["vless", "trojan", "both"].includes((args[3] || "").toLowerCase()) ? args[3].toLowerCase() : "vless";
        const uuid = crypto.randomUUID();
        await db.prepare("INSERT INTO users (username, uuid, trojan_pass, limit_gb, expiry_days, max_devices, reset_interval_days, daily_request_limit, note, protocol, used_gb, is_active) VALUES (?,?,?,?,?,0,NULL,0,'',?,0,1)")
          .bind(name, uuid, uuid.replace(/-/g, "").slice(0, 16), gb, days, proto).run();
        const u = await getUser(name);
        return send(chat, `✅ ساخته شد\n${usageLine(u)}\nپروتکل: ${proto}\nUUID: <code>${uuid}</code>\n\n${links(u)}`);
      }
      case "/info": {
        const u = await need(); if (!u) return;
        return send(chat, `${usageLine(u)}\nپروتکل: ${esc(u.protocol)}\nUUID: <code>${esc(u.uuid)}</code>\nدرخواست‌ها: ${u.request_count || 0}\nساخته‌شده: ${esc(u.created_at)}\n\n${links(u)}`);
      }
      case "/link": { const u = await need(); if (!u) return; return send(chat, links(u)); }
      case "/toggle": {
        const u = await need(); if (!u) return;
        await db.prepare("UPDATE users SET is_active=CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE username=?").bind(u.username).run();
        return send(chat, usageLine(await getUser(u.username)));
      }
      case "/reset": {
        const u = await need(); if (!u) return;
        await db.prepare("UPDATE users SET used_gb=0, request_count=0, last_reset_at=CURRENT_TIMESTAMP, is_active=1 WHERE username=?").bind(u.username).run();
        return send(chat, "مصرف صفر شد.\n" + usageLine(await getUser(u.username)));
      }
      case "/newuuid": {
        const u = await need(); if (!u) return;
        const nu = crypto.randomUUID();
        await db.prepare("UPDATE users SET uuid=?, trojan_pass=? WHERE username=?").bind(nu, nu.replace(/-/g, "").slice(0, 16), u.username).run();
        return send(chat, `UUID جدید: <code>${nu}</code>\nکانفیگ‌های قبلی این کاربر از کار می‌افتند.`);
      }
      case "/del": {
        const u = await need(); if (!u) return;
        return send(chat, `کاربر <b>${esc(u.username)}</b> حذف شود؟`, {
          reply_markup: { inline_keyboard: [[{ text: "بله، حذف کن", callback_data: "del:" + u.username }, { text: "انصراف", callback_data: "no" }]] },
        });
      }
      default: return send(chat, "دستور نامعتبر. /help");
    }
  }

  async function handleUpdate(up) {
    if (up.callback_query) {
      const q = up.callback_query, from = String(q.from.id), chat = q.message && q.message.chat.id;
      await tg("answerCallbackQuery", { callback_query_id: q.id });
      if (!admins.has(from) || !chat) return;
      if (q.data && q.data.startsWith("del:")) {
        const n = q.data.slice(4);
        await db.prepare("DELETE FROM users WHERE username=?").bind(n).run();
        await send(chat, `🗑 <b>${esc(n)}</b> حذف شد.`);
      } else await send(chat, "انصراف داده شد.");
      return;
    }
    const m = up.message;
    if (!m || !m.text || !m.chat) return;
    const from = String(m.from && m.from.id);
    if (!admins.has(from)) {
      if (m.text.startsWith("/start")) await send(m.chat.id, `دسترسی نداری.\nشناسه‌ی تلگرام تو: <code>${esc(from)}</code>\nاگر ادمین هستی، این عدد را در متغیر ADMIN_IDS بگذار.`);
      return;
    }
    if (!m.text.startsWith("/")) return;
    try { await handleCommand(m.chat.id, m.text); }
    catch (e) { console.error("bot command error:", e && e.message); await send(m.chat.id, "خطا: " + esc(e && e.message)); }
  }

  (async () => {
    try { await worker.fetch(new Request("http://localhost/"), env, {}); } catch { /* warm up schema */ }
    if (!admins.size) console.warn("Bot: ADMIN_IDS is empty. Send /start to the bot to see your Telegram ID.");
    console.log("Telegram bot started");
    let offset = 0, backoff = 1000;
    for (;;) {
      try {
        const r = await tg("getUpdates", { offset, timeout: 30, allowed_updates: ["message", "callback_query"] });
        if (!r.ok) throw new Error(r.description || "getUpdates failed");
        backoff = 1000;
        for (const up of r.result) { offset = up.update_id + 1; handleUpdate(up).catch((e) => console.error("bot error:", e && e.message)); }
      } catch (e) {
        console.error("bot poll error:", e && e.message);
        await sleep(backoff); backoff = Math.min(backoff * 2, 30000);
      }
    }
  })();
}

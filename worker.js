// language: JavaScript, file: src/index.js, runtime: Cloudflare Workers

const FALLBACK = {
  BOT_TOKEN: "9269369506:AAEAnh9ctvpS4QVXTRThXIKBmNZhRSS0GXk",
  ADMIN_TG_ID: "9269369506",
  TG_SECRET: "PRIIMExSH9DOW",
  ADMIN_SECRET: "PRIIMExSH9DOW"
};

function cfg(env, name) {
  const v = env[name];
  if (v && typeof v === "string" && !v.startsWith("PASTE_")) return v;
  return FALLBACK[name];
}

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function generateKey() {
  const seg = () => Array.from({ length: 4 }, () =>
    ALPHABET[Math.floor(Math.random() * ALPHABET.length)]
  ).join("");
  return `${seg()}-${seg()}-${seg()}-${seg()}`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
  });
}

async function readForm(request) {
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("form")) {
    const form = await request.formData();
    const body = {};
    for (const [k, v] of form.entries()) body[k] = v;
    return body;
  }
  try { return await request.json(); } catch { return {}; }
}

async function verifyKey(env, key) {
  const raw = await env.LICENSES.get(`license:${key}`);
  if (!raw) return { valid: false, error: "invalid_key" };
  const lic = JSON.parse(raw);
  if (lic.revoked) return { valid: false, error: "key_revoked" };
  if (Date.now() > lic.expiresAt) return { valid: false, error: "key_expired" };
  return { valid: true, expires_at: lic.expiresAt, lic };
}

async function createKey(env, days, maxDevices) {
  const key = generateKey();
  const lic = {
    key, createdAt: Date.now(),
    expiresAt: Date.now() + days * 86400000,
    maxDevices, revoked: false, devices: []
  };
  await env.LICENSES.put(`license:${key}`, JSON.stringify(lic));
  return lic;
}

async function registerDevice(env, key, deviceUid) {
  const v = await verifyKey(env, key);
  if (!v.valid) return { ok: false, error: v.error };
  const lic = v.lic;
  if (lic.devices.includes(deviceUid)) return { ok: true, expires_at: lic.expiresAt };
  if (lic.devices.length >= lic.maxDevices) return { ok: false, error: "device_limit" };
  lic.devices.push(deviceUid);
  await env.LICENSES.put(`license:${key}`, JSON.stringify(lic));
  return { ok: true, expires_at: lic.expiresAt };
}

async function tgApi(env, method, payload) {
  const token = cfg(env, "BOT_TOKEN");
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  return res.json();
}

async function reply(env, chatId, text) {
  return tgApi(env, "sendMessage", {
    chat_id: chatId, text,
    parse_mode: "HTML",
    disable_web_page_preview: true
  });
}

const HELP_TEXT =
`<b>♛ KeyGen Bot</b>

<b>Generate</b>
<code>/gen [days] [maxdev] [count]</code>
Defaults: 30d · 1 dev · 1 key
Example: <code>/gen 7 2 5</code>

<b>Manage</b>
<code>/list</code> — all licenses
<code>/info KEY</code> — details
<code>/revoke KEY</code> — disable
<code>/reset KEY</code> — clear devices
<code>/delete KEY</code> — remove
<code>/stats</code> — summary`;

async function handleTelegram(request, env) {
  const expected = cfg(env, "TG_SECRET");
  const secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  if (!expected || secret !== expected) {
    return new Response("forbidden", { status: 403 });
  }

  const update = await request.json();
  const msg = update.message;
  if (!msg || !msg.text) return new Response("ok");

  const chatId = msg.chat.id;
  const userId = String(msg.from.id);
  const adminId = String(cfg(env, "ADMIN_TG_ID"));

  if (userId !== adminId) {
    await reply(env, chatId, "⛔ Unauthorized.");
    return new Response("ok");
  }

  const text = msg.text.trim();
  const [cmd, ...args] = text.split(/\s+/);

  if (cmd === "/start" || cmd === "/help") {
    await reply(env, chatId, HELP_TEXT);
    return new Response("ok");
  }

  if (cmd === "/gen") {
    const days = Math.min(Math.max(parseInt(args[0]) || 30, 1), 3650);
    const max = Math.min(Math.max(parseInt(args[1]) || 1, 1), 100);
    const count = Math.min(Math.max(parseInt(args[2]) || 1, 1), 20);
    const lines = [];
    for (let i = 0; i < count; i++) {
      const lic = await createKey(env, days, max);
      lines.push(`<code>${lic.key}</code> · ${days}d · ${max} dev`);
    }
    await reply(env, chatId, `<b>✓ ${count} key(s)</b>\n\n${lines.join("\n")}`);
    return new Response("ok");
  }

  if (cmd === "/list") {
    const list = await env.LICENSES.list({ prefix: "license:" });
    if (!list.keys.length) {
      await reply(env, chatId, "No keys yet. Try <code>/gen</code>.");
      return new Response("ok");
    }
    const rows = [];
    for (const k of list.keys) {
      const raw = await env.LICENSES.get(k.name);
      if (!raw) continue;
      const lic = JSON.parse(raw);
      const status = lic.revoked ? "🔴" : (Date.now() > lic.expiresAt ? "⏰" : "🟢");
      const exp = new Date(lic.expiresAt).toISOString().slice(0, 10);
      rows.push(`${status} <code>${lic.key}</code> ${lic.devices.length}/${lic.maxDevices} · ${exp}`);
    }
    await reply(env, chatId, `<b>${rows.length} license(s)</b>\n\n${rows.join("\n")}`);
    return new Response("ok");
  }

  if (cmd === "/info") {
    const key = (args[0] || "").toUpperCase();
    if (!key) { await reply(env, chatId, "Usage: <code>/info KEY-XXXX</code>"); return new Response("ok"); }
    const raw = await env.LICENSES.get(`license:${key}`);
    if (!raw) { await reply(env, chatId, "❌ Key not found."); return new Response("ok"); }
    const lic = JSON.parse(raw);
    const info =
      `<b>Key:</b> <code>${lic.key}</code>\n` +
      `<b>Status:</b> ${lic.revoked ? "REVOKED" : (Date.now() > lic.expiresAt ? "EXPIRED" : "ACTIVE")}\n` +
      `<b>Expires:</b> ${new Date(lic.expiresAt).toISOString()}\n` +
      `<b>Devices:</b> ${lic.devices.length}/${lic.maxDevices}\n` +
      `<b>Bound:</b> ${lic.devices.length ? lic.devices.map(d => `<code>${d}</code>`).join(", ") : "none"}`;
    await reply(env, chatId, info);
    return new Response("ok");
  }

  if (cmd === "/revoke") {
    const key = (args[0] || "").toUpperCase();
    if (!key) { await reply(env, chatId, "Usage: <code>/revoke KEY-XXXX</code>"); return new Response("ok"); }
    const raw = await env.LICENSES.get(`license:${key}`);
    if (!raw) { await reply(env, chatId, "❌ Key not found."); return new Response("ok"); }
    const lic = JSON.parse(raw);
    lic.revoked = true;
    await env.LICENSES.put(`license:${key}`, JSON.stringify(lic));
    await reply(env, chatId, `🔴 Revoked <code>${key}</code>`);
    return new Response("ok");
  }

  if (cmd === "/reset") {
    const key = (args[0] || "").toUpperCase();
    if (!key) { await reply(env, chatId, "Usage: <code>/reset KEY-XXXX</code>"); return new Response("ok"); }
    const raw = await env.LICENSES.get(`license:${key}`);
    if (!raw) { await reply(env, chatId, "❌ Key not found."); return new Response("ok"); }
    const lic = JSON.parse(raw);
    lic.devices = [];
    await env.LICENSES.put(`license:${key}`, JSON.stringify(lic));
    await reply(env, chatId, `✓ Device slots cleared for <code>${key}</code>`);
    return new Response("ok");
  }

  if (cmd === "/delete") {
    const key = (args[0] || "").toUpperCase();
    if (!key) { await reply(env, chatId, "Usage: <code>/delete KEY-XXXX</code>"); return new Response("ok"); }
    await env.LICENSES.delete(`license:${key}`);
    await reply(env, chatId, `🗑 Deleted <code>${key}</code>`);
    return new Response("ok");
  }

  if (cmd === "/stats") {
    const list = await env.LICENSES.list({ prefix: "license:" });
    let active = 0, revoked = 0, expired = 0, devices = 0;
    for (const k of list.keys) {
      const raw = await env.LICENSES.get(k.name);
      if (!raw) continue;
      const lic = JSON.parse(raw);
      if (lic.revoked) revoked++;
      else if (Date.now() > lic.expiresAt) expired++;
      else active++;
      devices += lic.devices.length;
    }
    await reply(env, chatId,
      `<b>License Stats</b>\n\n` +
      `🟢 Active: ${active}\n` +
      `🔴 Revoked: ${revoked}\n` +
      `⏰ Expired: ${expired}\n` +
      `📱 Device bindings: ${devices}\n` +
      `🔑 Total keys: ${list.keys.length}`
    );
    return new Response("ok");
  }

  await reply(env, chatId, "Unknown command. /help dekho.");
  return new Response("ok");
}

const ADMIN_HTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key Admin</title>
<style>
body{font-family:system-ui;background:#0a0a0a;color:#eee;padding:16px;margin:0;max-width:600px;margin:auto}
h1{color:#f5c518;font-size:20px}
input,button{font-size:16px;padding:12px;border-radius:6px;border:1px solid #333;background:#111;color:#eee;width:100%;box-sizing:border-box;margin-bottom:8px}
button{background:#f5c518;color:#000;font-weight:bold;border:0}
.out{background:#111;padding:12px;border-radius:6px;white-space:pre-wrap;font-family:monospace;font-size:13px;min-height:80px;word-break:break-all}
</style></head><body>
<h1>♛ KEY ADMIN</h1>
<input id="secret" type="password" placeholder="ADMIN_SECRET">
<input id="days" type="number" value="30" placeholder="days">
<input id="max" type="number" value="1" placeholder="max devices">
<button onclick="create()">GENERATE</button>
<button onclick="list()">LIST</button>
<div class="out" id="out">Ready.</div>
<script>
const $=id=>document.getElementById(id);
const out=x=>{$("out").textContent=typeof x==="string"?x:JSON.stringify(x,null,2)};
async function call(p){const s=$("secret").value;if(!s){out("Enter secret");return}localStorage.setItem("adm",s);
try{const r=await fetch(location.origin+p+(p.includes("?")?"&":"?")+"secret="+encodeURIComponent(s));return r.json()}catch(e){out("Error "+e.message)}}
async function create(){const j=await call("/admin/create?days="+$("days").value+"&max="+$("max").value);out(j)}
async function list(){const j=await call("/admin/list");out(j)}
const s=localStorage.getItem("adm");if(s)$("secret").value=s;
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    if (path === "/tg/webhook" && request.method === "POST") {
      return handleTelegram(request, env);
    }

    if (request.method === "GET" && path === "/admin") {
      return new Response(ADMIN_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    if (request.method === "GET" && path.startsWith("/admin/")) {
      const secret = url.searchParams.get("secret") || "";
      const expected = cfg(env, "ADMIN_SECRET");
      if (!expected || secret !== expected) {
        return json({ error: "unauthorized" }, 401);
      }
      if (path === "/admin/create") {
        const days = parseInt(url.searchParams.get("days")) || 30;
        const max = parseInt(url.searchParams.get("max")) || 1;
        const lic = await createKey(env, days, max);
        return json({ success: true, key: lic.key, expires_at: lic.expiresAt });
      }
      if (path === "/admin/list") {
        const list = await env.LICENSES.list({ prefix: "license:" });
        const out = [];
        for (const k of list.keys) {
          const raw = await env.LICENSES.get(k.name);
          if (raw) out.push(JSON.parse(raw));
        }
        return json({ success: true, licenses: out });
      }
      return json({ error: "not_found" }, 404);
    }

    if (request.method === "GET" && url.searchParams.has("key")) {
      const key = url.searchParams.get("key").toUpperCase();
      const v = await verifyKey(env, key);
      if (!v.valid) return json({ valid: false, error: v.error });
      return json({ valid: true, expires_at: v.expires_at });
    }

    if (request.method === "POST") {
      const body = await readForm(request);
      const key = (body.key || "").toUpperCase();
      if (body.action === "register_device") {
        if (!key) return json({ ok: false, error: "key_required" });
        return json(await registerDevice(env, key, body.device_uid || "unknown"));
      }
      if (!key) return json({ valid: false, error: "key_required" });
      const v = await verifyKey(env, key);
      if (!v.valid) return json({ valid: false, error: v.error });
      return json({ valid: true, expires_at: v.expires_at });
    }

    return json({ error: "method_not_allowed" }, 405);
  }
};

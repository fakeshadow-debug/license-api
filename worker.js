// language: JavaScript, file: worker.js, target: Cloudflare Workers
// Naya Heavy Admin Panel + Mod Verify System

const ADMIN_SECRET = "PRIIMExSH9DOW";

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
  const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const seg = () => Array.from({ length: 4 }, () => ALPHABET[Math.floor(Math.random() * ALPHABET.length)]).join("");
  const key = `${seg()}-${seg()}-${seg()}-${seg()}`;
  const lic = { key, createdAt: Date.now(), expiresAt: Date.now() + days * 86400000, maxDevices, revoked: false, devices: [] };
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

const ADMIN_HTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Premium Admin Panel</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; background: #0a0a0a; color: #eee; padding: 16px; margin: 0; max-width: 800px; margin: auto; }
  h1, h2 { color: #f5c518; }
  input, button { font-size: 16px; padding: 12px; border-radius: 8px; border: 1px solid #333; background: #111; color: #eee; width: 100%; box-sizing: border-box; margin-bottom: 12px; }
  button { background: #f5c518; color: #000; font-weight: bold; border: 0; cursor: pointer; transition: 0.2s; }
  button:hover { background: #e0b000; }
  .row { display: flex; gap: 10px; margin-bottom: 12px; }
  .row > * { flex: 1; margin-bottom: 0; }
  .card { background: #151515; border: 1px solid #222; padding: 16px; border-radius: 12px; margin-bottom: 20px; }
  .out { background: #000; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 14px; min-height: 100px; white-space: pre-wrap; word-break: break-all; border: 1px solid #333; }
  .key-item { background: #1a1a1a; padding: 10px; margin-bottom: 8px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; border-left: 4px solid #f5c518; }
  .key-item.revoked { border-left-color: #f00; opacity: 0.7; }
  .key-item span { font-family: monospace; font-size: 14px; }
  .actions { display: flex; gap: 8px; }
  .actions button { padding: 6px 10px; font-size: 12px; width: auto; margin: 0; }
  .btn-danger { background: #f00; color: #fff; }
  .btn-danger:hover { background: #c00; }
</style></head><body>
<h1>♛ Admin Control</h1>

<div class="card">
  <input id="secret" type="password" placeholder="Enter Admin Secret to unlock panel..." oninput="checkAuth()">
</div>

<div id="panel" style="display:none;">
  <div class="card">
    <h2>Generate Keys</h2>
    <div class="row">
      <input id="days" type="number" value="30" placeholder="Days">
      <input id="max" type="number" value="1" placeholder="Max Devices">
      <input id="count" type="number" value="1" placeholder="How many keys?">
    </div>
    <button onclick="generate()">Generate New Key(s)</button>
  </div>

  <div class="card">
    <h2>Manage Keys</h2>
    <button onclick="loadList()">Refresh Key List</button>
    <div id="list" style="margin-top: 16px;"></div>
  </div>
</div>

<div class="out" id="out">Panel locked. Enter secret above.</div>

<script>
const $ = id => document.getElementById(id);
const out = (x) => { $("out").textContent = typeof x === "string" ? x : JSON.stringify(x, null, 2); };
let currentSecret = "";

function checkAuth() {
  currentSecret = $("secret").value;
  localStorage.setItem("admin_secret", currentSecret);
  if (currentSecret.length > 3) $("panel").style.display = "block";
  else $("panel").style.display = "none";
}

async function api(path) {
  if (!currentSecret) return out("Enter secret first.");
  try {
    const res = await fetch(location.origin + path + (path.includes("?") ? "&" : "?") + "secret=" + encodeURIComponent(currentSecret));
    return await res.json();
  } catch (e) {
    out("Error: " + e.message);
  }
}

async function generate() {
  const d = $("days").value, m = $("max").value, c = $("count").value;
  out("Generating...");
  const res = await api("/admin/create?days=" + d + "&max=" + m + "&count=" + c);
  if (res && res.keys) {
    out("Successfully generated:\\n\\n" + res.keys.map(k => k.key).join("\\n"));
    loadList();
  } else out(res);
}

async function loadList() {
  out("Loading list...");
  const res = await api("/admin/list");
  if (res && res.licenses) {
    const html = res.licenses.map(l => {
      const statusClass = l.revoked ? "revoked" : "";
      const statusText = l.revoked ? "REVOKED" : (Date.now() > l.expiresAt ? "EXPIRED" : "ACTIVE");
      const exp = new Date(l.expiresAt).toLocaleDateString();
      return \`<div class="key-item \${statusClass}">
        <div>
          <span>\${l.key}</span><br>
          <small>\${statusText} | \${l.devices.length}/\${l.maxDevices} devs | Exp: \${exp}</small>
        </div>
        <div class="actions">
          <button class="btn-danger" onclick="action('revoke', '\${l.key}')" style="display:\${l.revoked?'none':'block'}">Revoke</button>
          <button class="btn-danger" onclick="action('reset', '\${l.key}')">Reset Devs</button>
          <button class="btn-danger" onclick="action('delete', '\${l.key}')">Delete</button>
        </div>
      </div>\`;
    }).join("");
    $("list").innerHTML = html || "<p>No keys found.</p>";
    out("List loaded successfully.");
  } else {
    $("list").innerHTML = "";
    out(res);
  }
}

async function action(type, key) {
  if(!confirm("Are you sure you want to " + type + " this key?")) return;
  out("Processing " + type + "...");
  const res = await api("/admin/" + type + "?key=" + key);
  out(res);
  if(res.success) loadList();
}

const saved = localStorage.getItem("admin_secret");
if (saved) { $("secret").value = saved; checkAuth(); loadList(); }
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization" } });
    }

    // Admin Panel HTML
    if (request.method === "GET" && path === "/admin") {
      return new Response(ADMIN_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
    }

    // Admin API
    if (request.method === "GET" && path.startsWith("/admin/")) {
      const secret = url.searchParams.get("secret") || "";
      if (secret !== ADMIN_SECRET) return json({ error: "unauthorized" }, 401);

      if (path === "/admin/create") {
        const days = parseInt(url.searchParams.get("days")) || 30;
        const max = parseInt(url.searchParams.get("max")) || 1;
        const count = parseInt(url.searchParams.get("count")) || 1;
        const keys = [];
        for (let i = 0; i < count; i++) {
          const lic = await createKey(env, days, max);
          keys.push({ key: lic.key, expires_at: lic.expiresAt });
        }
        return json({ success: true, keys });
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

      if (path === "/admin/revoke") {
        const key = url.searchParams.get("key") || "";
        const raw = await env.LICENSES.get(`license:${key}`);
        if (!raw) return json({ success: false, error: "Key not found" });
        const lic = JSON.parse(raw);
        lic.revoked = true;
        await env.LICENSES.put(`license:${key}`, JSON.stringify(lic));
        return json({ success: true });
      }

      if (path === "/admin/reset") {
        const key = url.searchParams.get("key") || "";
        const raw = await env.LICENSES.get(`license:${key}`);
        if (!raw) return json({ success: false, error: "Key not found" });
        const lic = JSON.parse(raw);
        lic.devices = [];
        await env.LICENSES.put(`license:${key}`, JSON.stringify(lic));
        return json({ success: true });
      }

      if (path === "/admin/delete") {
        const key = url.searchParams.get("key") || "";
        await env.LICENSES.delete(`license:${key}`);
        return json({ success: true });
      }

      return json({ error: "not_found" }, 404);
    }

    // Mod Verification (GET fallback)
    if (request.method === "GET" && url.searchParams.has("key")) {
      const key = url.searchParams.get("key").toUpperCase();
      const v = await verifyKey(env, key);
      if (!v.valid) return json({ valid: false, error: v.error });
      return json({ valid: true, expires_at: v.expires_at });
    }

    // Mod Verification (POST)
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

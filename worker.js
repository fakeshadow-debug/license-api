// PREMIUM LICENSE WORKER — KV-only, compatible with existing LICENSES KV binding
// Required Cloudflare secret: ADMIN_SECRET
// No Durable Object binding or wrangler.toml migration is required.

const HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8"
};
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: HEADERS });
const normKey = value => String(value ?? "").trim().toUpperCase();

async function readBody(request) {
  try {
    const type = request.headers.get("content-type") || "";
    if (type.includes("application/json")) return await request.json();
    if (type.includes("application/x-www-form-urlencoded") || type.includes("multipart/form-data")) {
      const form = await request.formData();
      return Object.fromEntries(form.entries());
    }
  } catch (_) {}
  return {};
}
function isAdmin(request, url, env) {
  if (!env.ADMIN_SECRET) return false;
  const header = request.headers.get("Authorization") || "";
  const token = header.match(/^Bearer\s+(.+)$/i)?.[1] || url.searchParams.get("secret") || "";
  return token === env.ADMIN_SECRET;
}
function normalizeRecord(raw, fallbackKey) {
  if (!raw) return null;
  let value;
  try { value = typeof raw === "string" ? JSON.parse(raw) : raw; } catch (_) { return null; }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const expiry = Number(value.expiresAt ?? value.expires_at ?? value.expiry ?? value.expiration);
  if (!Number.isFinite(expiry)) return null;
  const rawDevices = value.devices ?? value.deviceIds ?? value.hwids ?? [];
  const devices = Array.isArray(rawDevices) ? rawDevices : [];
  const key = normKey(value.key ?? value.licenseKey ?? fallbackKey);
  if (!key) return null;
  return {
    ...value,
    key,
    createdAt: Number(value.createdAt ?? value.created_at ?? Date.now()),
    expiresAt: expiry,
    maxDevices: Math.max(1, Number(value.maxDevices ?? value.max_devices ?? 1) || 1),
    revoked: value.revoked === true || value.banned === true,
    devices: [...new Set(devices.filter(x => typeof x === "string").map(x => x.trim()).filter(Boolean))]
  };
}
async function listRawEntries(env) {
  const entries = [];
  let cursor;
  do {
    const page = await env.LICENSES.list({ limit: 1000, ...(cursor ? { cursor } : {}) });
    for (const item of page.keys || []) entries.push(item.name);
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return entries;
}
async function findLicense(env, key) {
  key = normKey(key);
  if (!key) return null;
  const aliases = [`license:${key}`, key, `key:${key}`, `licenses:${key}`, `license_${key}`];
  for (const name of aliases) {
    const record = normalizeRecord(await env.LICENSES.get(name), key);
    if (record && record.key === key) return { name, lic: record };
  }
  for (const name of await listRawEntries(env)) {
    if (aliases.includes(name)) continue;
    const record = normalizeRecord(await env.LICENSES.get(name), name);
    if (record && record.key === key) return { name, lic: record };
  }
  return null;
}
async function allLicenses(env) {
  const output = [];
  const seen = new Set();
  for (const name of await listRawEntries(env)) {
    const record = normalizeRecord(await env.LICENSES.get(name), name);
    if (!record || seen.has(record.key)) continue;
    seen.add(record.key);
    output.push(record);
  }
  output.sort((a, b) => b.createdAt - a.createdAt);
  return output;
}
function generateKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const chars = Array.from(bytes, byte => alphabet[byte % alphabet.length]);
  return `${chars.slice(0,5).join("")}-${chars.slice(5,10).join("")}-${chars.slice(10,15).join("")}-${chars.slice(15,20).join("")}`;
}
async function createLicense(env, days, maxDevices) {
  days = Number(days); maxDevices = Number(maxDevices);
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error("Duration must be between 1 and 3650 days.");
  if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100) throw new Error("Device limit must be between 1 and 100.");
  let key;
  do { key = generateKey(); } while (await findLicense(env, key));
  const now = Date.now();
  const license = { key, createdAt: now, expiresAt: now + days * 86400000, maxDevices, revoked: false, devices: [] };
  await env.LICENSES.put(`license:${key}`, JSON.stringify(license));
  return license;
}
async function verifyLicense(env, key) {
  key = normKey(key);
  if (!key) return { valid: false, error: "key_required" };
  const found = await findLicense(env, key);
  if (!found) return { valid: false, error: "invalid_key" };
  if (found.lic.revoked) return { valid: false, error: "key_revoked" };
  if (Date.now() > found.lic.expiresAt) return { valid: false, error: "key_expired" };
  return { valid: true, expires_at: found.lic.expiresAt };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: HEADERS });
    if (!env.LICENSES) return json({ success: false, error: "missing_KV_binding_LICENSES" }, 500);

    if (request.method === "GET" && path === "/admin") {
      return new Response(ADMIN_HTML, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });
    }

    if (path.startsWith("/admin/")) {
      if (!isAdmin(request, url, env)) return json({ success: false, error: "unauthorized" }, 401);
      const action = path.slice("/admin/".length).toLowerCase();
      if (action === "list" && (request.method === "GET" || request.method === "POST")) {
        return json({ success: true, licenses: await allLicenses(env) });
      }
      if (action === "create" && (request.method === "GET" || request.method === "POST")) {
        const body = request.method === "POST" ? await readBody(request) : {};
        const days = url.searchParams.get("days") ?? body.days ?? 30;
        const max = url.searchParams.get("max") ?? body.maxDevices ?? body.max ?? 1;
        const count = Number(url.searchParams.get("count") ?? body.count ?? 1);
        if (!Number.isInteger(count) || count < 1 || count > 100) return json({ success: false, error: "count_must_be_1_to_100" }, 400);
        try {
          const keys = [];
          for (let i = 0; i < count; i++) {
            const license = await createLicense(env, days, max);
            keys.push({ key: license.key, expires_at: license.expiresAt });
          }
          return json({ success: true, keys });
        } catch (error) { return json({ success: false, error: String(error.message || error) }, 400); }
      }
      if (["delete", "reset", "revoke"].includes(action) && (request.method === "GET" || request.method === "POST")) {
        const body = request.method === "POST" ? await readBody(request) : {};
        const key = normKey(url.searchParams.get("key") ?? body.key ?? body.license_key ?? body.licenseKey);
        if (!key) return json({ success: false, error: "key_required" }, 400);
        const found = await findLicense(env, key);
        if (!found) return json({ success: false, error: "key_not_found", key }, 404);
        if (action === "delete") {
          // Delete every stored copy of this license, including legacy aliases.
          const names = new Set([found.name, `license:${key}`, key, `key:${key}`, `licenses:${key}`, `license_${key}`]);
          for (const name of await listRawEntries(env)) {
            const record = normalizeRecord(await env.LICENSES.get(name), name);
            if (record?.key === key) names.add(name);
          }
          await Promise.all([...names].map(name => env.LICENSES.delete(name)));
          return json({ success: true, action, key, deleted_records: names.size });
        }
        if (action === "reset") found.lic.devices = [];
        if (action === "revoke") found.lic.revoked = true;
        await env.LICENSES.put(found.name, JSON.stringify(found.lic));
        return json({ success: true, action, key });
      }
      return json({ success: false, error: "admin_endpoint_not_found" }, 404);
    }

    if (request.method === "GET" && url.searchParams.has("key")) {
      return json(await verifyLicense(env, url.searchParams.get("key")));
    }
    if (request.method === "POST") {
      const body = await readBody(request);
      const key = normKey(body.key ?? body.license_key ?? body.licenseKey);
      if (body.action === "register_device") {
        if (!key) return json({ ok: false, error: "key_required" }, 400);
        const device = typeof body.device_uid === "string" ? body.device_uid.trim() : "";
        if (device.length < 8 || device.length > 200 || /^(unknown|null|undefined)$/i.test(device)) return json({ ok: false, error: "invalid_device_id" }, 400);
        const found = await findLicense(env, key);
        if (!found) return json({ ok: false, error: "invalid_key" });
        const license = found.lic;
        if (license.revoked) return json({ ok: false, error: "key_revoked" });
        if (Date.now() > license.expiresAt) return json({ ok: false, error: "key_expired" });
        const already = license.devices.includes(device);
        if (!already) {
          if (license.devices.length >= license.maxDevices) return json({ ok: false, error: "device_limit", devices_used: license.devices.length, max_devices: license.maxDevices });
          license.devices.push(device);
          await env.LICENSES.put(found.name, JSON.stringify(license));
        }
        return json({ ok: true, already_registered: already, expires_at: license.expiresAt, devices_used: license.devices.length, max_devices: license.maxDevices });
      }
      return json(await verifyLicense(env, key));
    }
    return json({ success: false, error: "not_found" }, 404);
  }
};

const ADMIN_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#090b10"><title>PRIME License Console</title>
<style>
:root{color-scheme:dark;--bg:#080a0f;--panel:#11151e;--panel2:#171d28;--line:#273142;--gold:#e8bd58;--gold2:#f7d98c;--text:#f4f6fb;--muted:#98a3b5;--red:#e05b63;--green:#55c69a;--blue:#79a9ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% -20%,#263247 0%,transparent 48%),var(--bg);color:var(--text);font:15px/1.5 Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}.wrap{width:min(100% - 28px,1040px);margin:0 auto;padding:34px 0 60px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:26px}.brand{display:flex;align-items:center;gap:13px}.logo{width:46px;height:46px;border:1px solid #846b36;border-radius:14px;display:grid;place-items:center;color:var(--gold2);font-size:22px;background:linear-gradient(145deg,#292315,#11151e);box-shadow:0 8px 30px #0008}.brand h1{font-size:19px;letter-spacing:.13em;margin:0}.brand p{margin:2px 0 0;color:var(--muted);font-size:12px;letter-spacing:.12em;text-transform:uppercase}.pill{border:1px solid var(--line);border-radius:999px;padding:7px 11px;color:var(--muted);font-size:12px}.grid{display:grid;grid-template-columns:340px minmax(0,1fr);gap:18px;align-items:start}.card{background:linear-gradient(160deg,#151b26,#0f131b);border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 18px 50px #0004}.card h2{font-size:14px;letter-spacing:.1em;text-transform:uppercase;margin:0 0 17px;color:var(--gold2)}.field{margin:0 0 13px}.field label{display:block;color:var(--muted);font-size:12px;margin:0 0 6px}.field input{width:100%;background:#090d14;border:1px solid #303b4e;border-radius:10px;padding:12px;color:var(--text);font:inherit;outline:none}.field input:focus{border-color:var(--gold);box-shadow:0 0 0 3px #e8bd581c}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}.btn{border:0;border-radius:10px;padding:12px 15px;font:700 13px inherit;cursor:pointer;transition:.18s;min-height:43px}.btn:hover{filter:brightness(1.09);transform:translateY(-1px)}.primary{background:linear-gradient(110deg,#d5a83f,#f2d27d);color:#17130a;width:100%}.subtle{background:#222b3a;border:1px solid #344157;color:#e8edf7}.danger{background:#3a1c23;border:1px solid #71323d;color:#ffb2b7}.success{background:#153329;border:1px solid #28614c;color:#9ce8c8}.login{max-width:430px;margin:8vh auto}.login .btn{margin-top:5px}.hidden{display:none!important}.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:13px}.toolbar h2{margin:0}.search{width:min(100%,260px);background:#090d14;border:1px solid #303b4e;border-radius:10px;padding:10px 12px;color:var(--text);font:inherit}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-bottom:16px}.stat{padding:12px;background:#0b1018;border:1px solid #253044;border-radius:12px}.stat b{display:block;font-size:21px;color:var(--gold2)}.stat span{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}.keylist{display:grid;gap:11px}.key{padding:15px;background:linear-gradient(145deg,#1a2230,#121822);border:1px solid #2b374a;border-radius:13px}.keyhead{display:flex;justify-content:space-between;align-items:flex-start;gap:10px}.keycode{font-size:15px;font-weight:800;letter-spacing:.055em;overflow-wrap:anywhere}.status{font-size:10px;letter-spacing:.08em;text-transform:uppercase;border-radius:999px;padding:4px 8px;white-space:nowrap;background:#17372e;color:#8ee0bd}.status.revoked{background:#402128;color:#ffabb1}.status.expired{background:#40351c;color:#f0d18b}.meta{color:var(--muted);font-size:12px;margin-top:7px}.actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:13px}.actions .btn{flex:1;min-width:90px;padding:9px 10px;min-height:37px;font-size:12px}.empty{padding:30px 15px;text-align:center;color:var(--muted);border:1px dashed #344157;border-radius:12px}.output{margin-top:16px;padding:12px 14px;background:#080b10;border:1px solid #273142;border-radius:11px;color:#c3cddd;font:12px/1.6 ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere;max-height:180px;overflow:auto}.output:empty{display:none}.muted{color:var(--muted)}.foot{text-align:center;color:#677386;font-size:11px;margin-top:22px}@media(max-width:760px){.grid{grid-template-columns:1fr}.wrap{padding-top:22px}.top{align-items:flex-start}.pill{font-size:10px}.card{padding:16px}}@media(max-width:390px){.two{grid-template-columns:1fr}.stats{gap:6px}.stat{padding:9px}.stat b{font-size:18px}.keyhead{display:block}.status{display:inline-block;margin-top:8px}}
</style></head><body><main class="wrap">
<header class="top"><div class="brand"><div class="logo">✦</div><div><h1>PRIME CONSOLE</h1><p>License management system</p></div></div><div class="pill">SECURE ADMIN ACCESS</div></header>
<section id="login" class="card login"><h2>Administrator Login</h2><div class="field"><label for="secret">ADMIN SECRET</label><input id="secret" type="password" autocomplete="current-password" placeholder="Enter your admin secret"></div><button class="btn primary" id="loginBtn">Unlock console&nbsp; →</button><div id="loginError" class="meta"></div></section>
<section id="app" class="hidden"><div class="grid"><aside class="card"><h2>Create licenses</h2><div class="field"><label for="days">VALIDITY (DAYS)</label><input id="days" type="number" min="1" max="3650" value="30"></div><div class="two"><div class="field"><label for="max">DEVICE LIMIT</label><input id="max" type="number" min="1" max="100" value="1"></div><div class="field"><label for="count">QUANTITY</label><input id="count" type="number" min="1" max="100" value="1"></div></div><button class="btn primary" id="generateBtn">＋ Generate keys</button><div class="output" id="generated"></div><div class="output" id="output"></div></aside>
<div class="card"><div class="toolbar"><h2>License inventory</h2><button class="btn subtle" id="refreshBtn">↻ Refresh</button></div><div class="stats"><div class="stat"><b id="total">—</b><span>Total keys</span></div><div class="stat"><b id="active">—</b><span>Active</span></div><div class="stat"><b id="revoked">—</b><span>Revoked</span></div></div><input class="search" id="search" type="search" placeholder="Search license key…" aria-label="Search license key"><div class="keylist" id="list" style="margin-top:13px"><div class="empty">Unlock the console to load licenses.</div></div></div></div></section>
<div class="foot">PRIME LICENSE CONSOLE · KV STORAGE</div></main>
<script>
const $=id=>document.getElementById(id);let secret="",licenses=[];
function showOutput(value){$("output").textContent=typeof value==="string"?value:JSON.stringify(value,null,2)}
async function api(action,body){const response=await fetch(location.origin+"/admin/"+action,{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+secret},body:JSON.stringify(body||{})});let data;try{data=await response.json()}catch(_){throw new Error("Worker returned a non-JSON response (HTTP "+response.status+")")}if(!response.ok||data.success===false)throw new Error(data.error||("Request failed: HTTP "+response.status));return data}
async function login(){secret=$("secret").value.trim();if(!secret){$("loginError").textContent="Please enter your admin secret.";return}$("loginError").textContent="Checking access…";try{await api("list");$("login").classList.add("hidden");$("app").classList.remove("hidden");$("loginError").textContent="";await loadList()}catch(e){secret="";$("loginError").textContent=e.message}}
function statusOf(l){if(l.revoked)return ["Revoked","revoked"];if(Date.now()>Number(l.expiresAt))return ["Expired","expired"];return ["Active",""]}
function render(){const q=$("search").value.trim().toUpperCase();const active=licenses.filter(l=>!l.revoked&&Date.now()<=Number(l.expiresAt)).length;$("total").textContent=licenses.length;$("active").textContent=active;$("revoked").textContent=licenses.filter(l=>l.revoked).length;const root=$("list");root.replaceChildren();const filtered=licenses.filter(l=>String(l.key||"").toUpperCase().includes(q));if(!filtered.length){const empty=document.createElement("div");empty.className="empty";empty.textContent=q?"No matching licenses found.":"No licenses have been created yet.";root.append(empty);return}for(const lic of filtered){const item=document.createElement("article");item.className="key";const head=document.createElement("div");head.className="keyhead";const key=document.createElement("div");key.className="keycode";key.textContent=lic.key;const [label,cls]=statusOf(lic);const badge=document.createElement("span");badge.className="status "+cls;badge.textContent=label;head.append(key,badge);const meta=document.createElement("div");meta.className="meta";meta.textContent=(lic.devices||[]).length+" / "+lic.maxDevices+" devices · Expires "+new Date(Number(lic.expiresAt)).toLocaleDateString();const actions=document.createElement("div");actions.className="actions";const add=(text,kind,fn)=>{const b=document.createElement("button");b.className="btn "+kind;b.textContent=text;b.addEventListener("click",fn);actions.append(b)};add("Copy key","subtle",()=>{navigator.clipboard?.writeText(lic.key).then(()=>showOutput("Copied: "+lic.key)).catch(()=>showOutput(lic.key))});add("Reset devices","subtle",()=>doAction("reset",lic.key));if(!lic.revoked)add("Revoke","danger",()=>doAction("revoke",lic.key));add("Delete","danger",()=>doAction("delete",lic.key));item.append(head,meta,actions);root.append(item)}}
async function loadList(){showOutput("Loading licenses…");try{const data=await api("list");licenses=Array.isArray(data.licenses)?data.licenses:[];render();showOutput("License list loaded · "+licenses.length+" key(s)")}catch(e){showOutput("Could not load licenses: "+e.message)}}
async function generate(){const body={days:Number($("days").value),maxDevices:Number($("max").value),count:Number($("count").value)};showOutput("Generating licenses…");$("generated").textContent="";try{const data=await api("create",body);const keys=(data.keys||[]).map(x=>x.key);$("generated").textContent=keys.join("\n");showOutput("Successfully generated "+keys.length+" key(s).");await loadList()}catch(e){showOutput("Generation failed: "+e.message)}}
async function doAction(action,key){const confirmText=action==="delete"?"Permanently delete this license? This cannot be undone.":action==="revoke"?"Revoke this license?":"Reset all registered devices for this license?";if(!window.confirm(confirmText+"\n\n"+key))return;showOutput(action+" in progress…");try{const result=await api(action,{key});showOutput(action.toUpperCase()+" successful · "+key+(result.deleted_records?" · "+result.deleted_records+" stored record(s) removed":""));await loadList()}catch(e){showOutput(action.toUpperCase()+" failed · "+e.message)}}
$("loginBtn").addEventListener("click",login);$("secret").addEventListener("keydown",e=>{if(e.key==="Enter")login()});$("generateBtn").addEventListener("click",generate);$("refreshBtn").addEventListener("click",loadList);$("search").addEventListener("input",render);
</script></body></html>`;

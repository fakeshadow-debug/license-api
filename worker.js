// PREMIUM 4.7 LICENSE WORKER — KV-only admin operations
// Required binding: LICENSES (your existing KV namespace)
// Required secret: ADMIN_SECRET
// Durable Object binding is NOT required by this version.

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8"
};
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: CORS });
const normKey = v => String(v ?? "").trim().toUpperCase();
const validDevice = v => typeof v === "string" && v.trim().length >= 8 &&
  v.trim().length <= 200 && !/^(unknown|null|undefined)$/i.test(v.trim());

async function readBody(req) {
  const ct = req.headers.get("content-type") || "";
  try {
    if (ct.includes("application/json")) return await req.json();
    if (ct.includes("application/x-www-form-urlencoded") || ct.includes("multipart/form-data")) {
      const fd = await req.formData();
      return Object.fromEntries(fd.entries());
    }
  } catch {}
  return {};
}
function adminOK(req, url, env) {
  if (!env.ADMIN_SECRET) return false;
  const auth = req.headers.get("Authorization") || "";
  const supplied = auth.match(/^Bearer\s+(.+)$/i)?.[1] || url.searchParams.get("secret") || "";
  return supplied === env.ADMIN_SECRET;
}
function normalizeRecord(raw, key) {
  if (!raw) return null;
  let x;
  try { x = typeof raw === "string" ? JSON.parse(raw) : raw; } catch { return null; }
  if (!x || typeof x !== "object") return null;
  // Accept the current schema and common legacy field aliases without discarding data.
  const expiry = Number(x.expiresAt ?? x.expires_at ?? x.expiry ?? x.expiration);
  if (!Number.isFinite(expiry)) return null;
  const devices = Array.isArray(x.devices) ? x.devices :
    Array.isArray(x.deviceIds) ? x.deviceIds :
    Array.isArray(x.hwids) ? x.hwids : [];
  return {
    ...x,
    key: normKey(x.key || x.licenseKey || key),
    createdAt: Number(x.createdAt ?? x.created_at ?? Date.now()),
    expiresAt: expiry,
    maxDevices: Math.max(1, Number(x.maxDevices ?? x.max_devices ?? 1) || 1),
    revoked: x.revoked === true || x.banned === true,
    devices: devices.filter(v => typeof v === "string").map(v => v.trim()).filter(Boolean)
  };
}
async function findLicense(env, key) {
  const candidates = [`license:${key}`, key, `key:${key}`, `licenses:${key}`, `license_${key}`];
  for (const name of candidates) {
    const raw = await env.LICENSES.get(name);
    const lic = normalizeRecord(raw, key);
    if (lic && lic.key === key) return { name, lic };
  }
  // Compatibility fallback: find records saved under a different KV key name.
  let cursor;
  do {
    const page = await env.LICENSES.list({ limit: 1000, ...(cursor ? { cursor } : {}) });
    for (const item of page.keys || []) {
      if (candidates.includes(item.name)) continue;
      const raw = await env.LICENSES.get(item.name);
      const lic = normalizeRecord(raw, item.name);
      if (lic && lic.key === key) return { name: item.name, lic };
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return null;
}
async function allLicenses(env) {
  const out = [], seen = new Set();
  let cursor;
  do {
    const page = await env.LICENSES.list({ limit: 1000, ...(cursor ? { cursor } : {}) });
    for (const item of page.keys || []) {
      const raw = await env.LICENSES.get(item.name);
      const lic = normalizeRecord(raw, item.name);
      if (!lic || !lic.key || seen.has(lic.key)) continue;
      seen.add(lic.key);
      out.push(lic);
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  out.sort((a,b) => (b.createdAt || 0) - (a.createdAt || 0));
  return out;
}
function makeKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  const s = Array.from(bytes, b => chars[b % chars.length]);
  return `${s.slice(0,5).join("")}-${s.slice(5,10).join("")}-${s.slice(10,15).join("")}-${s.slice(15,20).join("")}`;
}
async function createLicense(env, days, maxDevices) {
  days = Number(days); maxDevices = Number(maxDevices);
  if (!Number.isInteger(days) || days < 1 || days > 3650) throw new Error("Duration must be 1–3650 days");
  if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100) throw new Error("Device limit must be 1–100");
  let key;
  do { key = makeKey(); } while (await findLicense(env, key));
  const now = Date.now();
  const lic = { key, createdAt: now, expiresAt: now + days * 86400000, maxDevices, revoked: false, devices: [] };
  await env.LICENSES.put(`license:${key}`, JSON.stringify(lic));
  return lic;
}
async function verify(env, key) {
  key = normKey(key);
  if (!key) return { valid: false, error: "key_required" };
  const found = await findLicense(env, key);
  if (!found) return { valid: false, error: "invalid_key" };
  const l = found.lic;
  if (l.revoked) return { valid: false, error: "key_revoked" };
  if (Date.now() > l.expiresAt) return { valid: false, error: "key_expired" };
  return { valid: true, expires_at: l.expiresAt };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url), path = url.pathname;
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (!env.LICENSES) return json({ ok:false, error:"missing_kv_binding_LICENSES" }, 500);

    if (request.method === "GET" && path === "/admin") {
      return new Response(ADMIN_HTML, { headers: { "Content-Type":"text/html; charset=utf-8" } });
    }
    if (path.startsWith("/admin/")) {
      if (request.method !== "GET") return json({ success:false, error:"method_not_allowed" }, 405);
      if (!adminOK(request, url, env)) return json({ success:false, error:"unauthorized" }, 401);
      if (path === "/admin/create") {
        const days = Number(url.searchParams.get("days") || 30);
        const max = Number(url.searchParams.get("max") || 1);
        const count = Number(url.searchParams.get("count") || 1);
        if (!Number.isInteger(count) || count < 1 || count > 100) return json({success:false,error:"count_must_be_1_to_100"},400);
        try {
          const keys=[];
          for(let i=0;i<count;i++){ const l=await createLicense(env,days,max); keys.push({key:l.key,expires_at:l.expiresAt}); }
          return json({success:true,keys});
        } catch(e) { return json({success:false,error:String(e.message || e)},400); }
      }
      if (path === "/admin/list") return json({success:true,licenses:await allLicenses(env)});
      const action = path.slice("/admin/".length);
      if (!["delete","reset","revoke"].includes(action)) return json({success:false,error:"not_found"},404);
      const key = normKey(url.searchParams.get("key"));
      if (!key) return json({success:false,error:"key_required"},400);
      const found = await findLicense(env,key);
      if (!found) return json({success:false,error:"key_not_found"},404);
      if (action === "delete") {
        await env.LICENSES.delete(found.name);
        // Also clear known aliases if present, to avoid a stale duplicate record.
        for (const alias of [`license:${key}`,key,`key:${key}`,`licenses:${key}`,`license_${key}`]) {
          if (alias !== found.name) await env.LICENSES.delete(alias);
        }
        return json({success:true,action,key});
      }
      if (action === "reset") found.lic.devices = [];
      if (action === "revoke") found.lic.revoked = true;
      await env.LICENSES.put(found.name,JSON.stringify(found.lic));
      return json({success:true,action,key});
    }

    if (request.method === "GET" && url.searchParams.has("key")) {
      const r=await verify(env,url.searchParams.get("key")); return json(r);
    }
    if (request.method === "POST") {
      const body=await readBody(request), key=normKey(body.key);
      if (body.action === "register_device") {
        if (!key) return json({ok:false,error:"key_required"},400);
        if (!validDevice(body.device_uid)) return json({ok:false,error:"invalid_device_id"},400);
        const found=await findLicense(env,key);
        if (!found) return json({ok:false,error:"invalid_key"});
        const l=found.lic;
        if (l.revoked) return json({ok:false,error:"key_revoked"});
        if (Date.now()>l.expiresAt) return json({ok:false,error:"key_expired"});
        l.devices=[...new Set(l.devices)];
        const uid=body.device_uid.trim();
        const alreadyRegistered = l.devices.includes(uid);
        if (!alreadyRegistered) {
          if (l.devices.length>=l.maxDevices) return json({ok:false,error:"device_limit",devices_used:l.devices.length,max_devices:l.maxDevices});
          l.devices.push(uid);
          await env.LICENSES.put(found.name,JSON.stringify(l));
        }
        return json({ok:true,already_registered:alreadyRegistered,expires_at:l.expiresAt,devices_used:l.devices.length,max_devices:l.maxDevices});
      }
      return json(await verify(env,key));
    }
    return json({error:"not_found"},404);
  }
};

const ADMIN_HTML = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Premium Admin Panel</title><style>
*{box-sizing:border-box}body{font-family:system-ui;background:#090909;color:#eee;padding:16px;margin:auto;max-width:850px}h1,h2{color:#f5c518}.card{background:#151515;border:1px solid #292929;padding:16px;border-radius:12px;margin-bottom:18px}input,button{width:100%;padding:12px;margin:5px 0 10px;border-radius:8px;border:1px solid #333;background:#101010;color:#eee;font-size:15px}button{background:#f5c518;color:#000;font-weight:700;cursor:pointer;border:0}.row{display:flex;gap:10px}.row>*{min-width:0;flex:1}.item{background:#202020;padding:12px;margin:10px 0;border-left:4px solid #f5c518;border-radius:7px}.item.revoked{border-left-color:#d22}.actions{display:flex;gap:7px;margin-top:10px}.actions button{font-size:12px}.danger{background:#bd2525;color:white}.out{background:#000;border:1px solid #333;padding:12px;border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere}small{color:#aaa}@media(max-width:520px){.row{flex-direction:column;gap:0}.actions{flex-wrap:wrap}}
</style></head><body><h1>♛ Premium Admin Panel</h1>
<div class="card"><input id="secret" type="password" placeholder="Admin secret"><button onclick="login()">Unlock</button></div>
<div id="panel" style="display:none"><div class="card"><h2>Generate Keys</h2><div class="row"><input id="days" type="number" min="1" value="30" placeholder="Days"><input id="max" type="number" min="1" value="1" placeholder="Device limit"><input id="count" type="number" min="1" value="1" placeholder="Quantity"></div><button onclick="generate()">Generate key(s)</button></div>
<div class="card"><h2>Manage Keys</h2><button onclick="loadList()">Refresh</button><div id="list"></div></div></div><div class="out" id="out">Panel locked.</div>
<script>
const $=id=>document.getElementById(id);let secret="";function out(v){$("out").textContent=typeof v==="string"?v:JSON.stringify(v,null,2)}
async function api(path){try{const r=await fetch(location.origin+path,{headers:{Authorization:"Bearer "+secret}});const j=await r.json();if(!r.ok)out(j);return j}catch(e){out("Network error: "+e.message);return null}}
function login(){secret=$("secret").value.trim();if(!secret){out("Enter admin secret");return}$("panel").style.display="block";loadList()}
async function generate(){out("Generating...");const r=await api("/admin/create?days="+encodeURIComponent($("days").value)+"&max="+encodeURIComponent($("max").value)+"&count="+encodeURIComponent($("count").value));if(r&&r.success&&Array.isArray(r.keys)){out("Generated keys:\n\n"+r.keys.map(x=>x.key).join("\n"));await loadList()}else out(r||"Request failed")}
async function loadList(){out("Loading...");const r=await api("/admin/list");if(!r||!r.success||!Array.isArray(r.licenses)){out(r||"Could not load list");return}const root=$("list");root.replaceChildren();for(const lic of r.licenses){const item=document.createElement("div");item.className="item"+(lic.revoked?" revoked":"");const title=document.createElement("strong");title.textContent=lic.key;const detail=document.createElement("small");detail.textContent=(lic.revoked?"REVOKED":Date.now()>lic.expiresAt?"EXPIRED":"ACTIVE")+" | "+lic.devices.length+"/"+lic.maxDevices+" devices | Exp: "+new Date(lic.expiresAt).toLocaleDateString();item.append(title,document.createElement("br"),detail);const actions=document.createElement("div");actions.className="actions";for(const [label,action] of [["Reset Devices","reset"],["Revoke","revoke"],["Delete","delete"]]){if(action==="revoke"&&lic.revoked)continue;const b=document.createElement("button");b.textContent=label;b.className="danger";b.onclick=()=>doAction(action,lic.key);actions.append(b)}item.append(actions);root.append(item)}out("License list loaded. Total: "+r.licenses.length)}
async function doAction(action,key){if(!confirm("Are you sure you want to "+action+" this key?"))return;const r=await api("/admin/"+action+"?key="+encodeURIComponent(key));if(r&&r.success){out(action+" successful: "+key);await loadList()}else out(r||"Action failed")}
</script></body></html>`;
    

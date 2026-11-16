
// PREMIUM 4.7 LICENSE WORKER
// Required bindings:
//   KV namespace: LICENSES
//   Durable Object binding: LICENSE_DEVICE -> LicenseDeviceDO
// Required secret:
//   ADMIN_SECRET
//
// Durable Object serializes all registration/reset/revoke/delete operations
// for a given license key. This avoids KV read-modify-write races.

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json; charset=utf-8"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: CORS });
}

function normalizeKey(value) {
  return String(value || "").trim().toUpperCase();
}

function normalizeDeviceId(value) {
  if (typeof value !== "string") return null;
  const id = value.trim();
  if (
    id.length < 8 ||
    id.length > 200 ||
    /^(unknown|null|undefined)$/i.test(id)
  ) return null;
  return id;
}

async function readBody(request) {
  const type = request.headers.get("content-type") || "";
  try {
    if (type.includes("application/json")) return await request.json();
    if (type.includes("form")) {
      const form = await request.formData();
      const body = {};
      for (const [key, value] of form.entries()) body[key] = value;
      return body;
    }
  } catch {}
  return {};
}

function validLicense(lic) {
  return !!(
    lic &&
    typeof lic === "object" &&
    typeof lic.expiresAt === "number" &&
    Number.isInteger(lic.maxDevices) &&
    lic.maxDevices >= 1 &&
    Array.isArray(lic.devices)
  );
}

async function readLicense(env, key) {
  const raw = await env.LICENSES.get("license:" + key);
  if (!raw) return { lic: null, error: "invalid_key" };
  let lic;
  try {
    lic = JSON.parse(raw);
  } catch {
    return { lic: null, error: "license_data_error" };
  }
  if (!validLicense(lic)) return { lic: null, error: "license_data_error" };
  return { lic };
}

async function verifyKey(env, key) {
  key = normalizeKey(key);
  if (!key) return { valid: false, error: "key_required" };

  const result = await readLicense(env, key);
  if (!result.lic) return { valid: false, error: result.error };

  const lic = result.lic;
  if (lic.revoked === true) return { valid: false, error: "key_revoked" };
  if (Date.now() > lic.expiresAt) return { valid: false, error: "key_expired" };

  return { valid: true, expires_at: lic.expiresAt };
}

function makeKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const segment = () => {
    const bytes = crypto.getRandomValues(new Uint8Array(4));
    return Array.from(bytes, b => alphabet[b % alphabet.length]).join("");
  };
  return `${segment()}-${segment()}-${segment()}-${segment()}`;
}

async function createKey(env, days, maxDevices) {
  days = Number(days);
  maxDevices = Number(maxDevices);

  if (!Number.isInteger(days) || days < 1 || days > 3650) {
    throw new Error("Invalid duration (1-3650 days)");
  }
  if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100) {
    throw new Error("Invalid device limit (1-100)");
  }

  let key;
  do {
    key = makeKey();
  } while (await env.LICENSES.get("license:" + key));

  const now = Date.now();
  const lic = {
    key,
    createdAt: now,
    expiresAt: now + days * 86400000,
    maxDevices,
    revoked: false,
    devices: []
  };

  await env.LICENSES.put("license:" + key, JSON.stringify(lic));
  return lic;
}

function authorizedAdmin(request, url, env) {
  if (!env.ADMIN_SECRET) return false;
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.replace(/^Bearer\s+/i, "");
  const supplied = bearer || url.searchParams.get("secret") || "";
  return supplied === env.ADMIN_SECRET;
}

async function doLicenseAction(env, action, key, deviceUID) {
  key = normalizeKey(key);
  if (!key) return json({ ok: false, error: "key_required" }, 400);

  const id = env.LICENSE_DEVICE.idFromName(key);
  const stub = env.LICENSE_DEVICE.get(id);

  return stub.fetch("https://license-device.internal/action", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ action, key, device_uid: deviceUID })
  });
}

async function listLicenses(env) {
  const result = await env.LICENSES.list({ prefix: "license:" });
  const licenses = [];

  for (const item of result.keys) {
    const raw = await env.LICENSES.get(item.name);
    if (!raw) continue;
    try {
      licenses.push(JSON.parse(raw));
    } catch {}
  }

  return licenses;
}

const ADMIN_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Premium License Admin</title>
<style>
*{box-sizing:border-box}body{font-family:system-ui;background:#0a0a0a;color:#eee;padding:16px;margin:auto;max-width:850px}
h1,h2{color:#f5c518}.card{background:#151515;border:1px solid #292929;padding:16px;border-radius:12px;margin-bottom:18px}
input,button{width:100%;padding:12px;margin-bottom:10px;border-radius:8px;border:1px solid #333;background:#111;color:#eee;font-size:15px}
button{background:#f5c518;color:#000;font-weight:bold;cursor:pointer;border:0}.row{display:flex;gap:10px}.row>*{flex:1;min-width:0}
.item{background:#202020;padding:12px;margin:10px 0;border-left:4px solid #f5c518;border-radius:7px}.item.revoked{border-left-color:#d22}
.actions{display:flex;gap:7px;margin-top:10px}.actions button{font-size:12px}.danger{background:#bd2525;color:white}
small{color:#aaa}.out{background:#000;border:1px solid #333;padding:14px;border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere}
@media(max-width:520px){.row{flex-direction:column;gap:0}.actions{flex-wrap:wrap}}
</style></head><body>
<h1>♛ Premium Admin Panel</h1>
<div class="card"><input id="secret" type="password" placeholder="Admin secret"><button onclick="login()">Unlock</button></div>
<div id="panel" style="display:none">
<div class="card"><h2>Generate Keys</h2><div class="row">
<input id="days" type="number" min="1" value="30"><input id="max" type="number" min="1" value="1"><input id="count" type="number" min="1" value="1">
</div><button onclick="generate()">Generate key(s)</button></div>
<div class="card"><h2>Manage Keys</h2><button onclick="loadList()">Refresh</button><div id="list"></div></div>
</div>
<div class="out" id="out">Panel locked.</div>
<script>
const $=id=>document.getElementById(id);let secret="";
function out(v){$("out").textContent=typeof v==="string"?v:JSON.stringify(v,null,2)}
async function api(path){
 try{const r=await fetch(location.origin+path,{headers:{Authorization:"Bearer "+secret}});return await r.json()}
 catch(e){out("Network error: "+e.message);return null}
}
function login(){secret=$("secret").value.trim();if(!secret){out("Enter admin secret");return}$("panel").style.display="block";loadList()}
async function generate(){
 out("Generating...");
 const r=await api("/admin/create?days="+encodeURIComponent($("days").value)+"&max="+encodeURIComponent($("max").value)+"&count="+encodeURIComponent($("count").value));
 if(r&&r.keys){out("Generated keys:\\n\\n"+r.keys.map(x=>x.key).join("\\n"));loadList()}else out(r||"Request failed")
}
async function loadList(){
 out("Loading...");
 const r=await api("/admin/list");
 if(!r||!r.licenses){out(r||"Could not load list");return}
 $("list").innerHTML="";
 for(const lic of r.licenses){
  const item=document.createElement("div");item.className="item"+(lic.revoked?" revoked":"");
  const title=document.createElement("strong");title.textContent=lic.key;
  const detail=document.createElement("small");
  detail.textContent=(lic.revoked?"REVOKED":Date.now()>lic.expiresAt?"EXPIRED":"ACTIVE")+" | "+lic.devices.length+"/"+lic.maxDevices+" devices | Exp: "+new Date(lic.expiresAt).toLocaleDateString();
  item.append(title,document.createElement("br"),detail);
  const actions=document.createElement("div");actions.className="actions";
  for(const [label,action] of [["Reset Devs","reset"],["Revoke","revoke"],["Delete","delete"]]){
   if(action==="revoke"&&lic.revoked)continue;
   const b=document.createElement("button");b.textContent=label;b.className="danger";b.onclick=()=>doAction(action,lic.key);actions.appendChild(b);
  }
  item.appendChild(actions);$("list").appendChild(item);
 }
 out("License list loaded.");
}
async function doAction(action,key){
 if(!confirm("Are you sure you want to "+action+" this key?"))return;
 const r=await api("/admin/"+action+"?key="+encodeURIComponent(key));out(r||"Request failed");if(r&&r.success)loadList()
}
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (!env.LICENSES) return json({ error: "missing_kv_binding" }, 500);
    if (!env.LICENSE_DEVICE) return json({ error: "missing_durable_object_binding" }, 500);

    if (request.method === "GET" && path === "/admin") {
      return new Response(ADMIN_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    if (path.startsWith("/admin/")) {
      if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
      if (!authorizedAdmin(request, url, env)) return json({ error: "unauthorized" }, 401);

      if (path === "/admin/create") {
        const days = Number(url.searchParams.get("days") || 30);
        const max = Number(url.searchParams.get("max") || 1);
        const count = Number(url.searchParams.get("count") || 1);
        if (!Number.isInteger(count) || count < 1 || count > 100) {
          return json({ success: false, error: "invalid_count" }, 400);
        }

        try {
          const keys = [];
          for (let i = 0; i < count; i++) {
            const lic = await createKey(env, days, max);
            keys.push({ key: lic.key, expires_at: lic.expiresAt });
          }
          return json({ success: true, keys });
        } catch (e) {
          return json({ success: false, error: e.message }, 400);
        }
      }

      if (path === "/admin/list") {
        return json({ success: true, licenses: await listLicenses(env) });
      }

      const action = path.slice("/admin/".length);
      if (!["reset", "revoke", "delete"].includes(action)) {
        return json({ error: "not_found" }, 404);
      }

      const key = normalizeKey(url.searchParams.get("key"));
      if (!key) return json({ success: false, error: "key_required" }, 400);

      const response = await doLicenseAction(env, action, key);
      const result = await response.json();
      return json({ success: result.ok === true, error: result.error });
    }

    if (request.method === "GET" && url.searchParams.has("key")) {
      const result = await verifyKey(env, url.searchParams.get("key"));
      return json(result.valid
        ? { valid: true, expires_at: result.expires_at }
        : { valid: false, error: result.error });
    }

    if (request.method === "POST") {
      const body = await readBody(request);
      const key = normalizeKey(body.key);

      if (body.action === "register_device") {
        const response = await doLicenseAction(
          env, "register", key, body.device_uid
        );
        return new Response(response.body, {
          status: response.status,
          headers: CORS
        });
      }

      const result = await verifyKey(env, key);
      return json(result.valid
        ? { valid: true, expires_at: result.expires_at }
        : { valid: false, error: result.error });
    }

    return json({ error: "method_not_allowed" }, 405);
  }
};

// One Durable Object instance per license key. All mutations for that key
// are serialized here, including registration and admin resets/revokes/deletes.
export class LicenseDeviceDO {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;
  }

  async fetch(request) {
    return this.ctx.blockConcurrencyWhile(async () => {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "invalid_request" }, 400);
      }

      const action = body.action;
      const key = normalizeKey(body.key);
      if (!key) return json({ ok: false, error: "key_required" }, 400);

      const result = await readLicense(this.env, key);
      if (!result.lic) return json({ ok: false, error: result.error }, 404);

      const lic = result.lic;

      if (action === "register") {
        const deviceUID = normalizeDeviceId(body.device_uid);
        if (!deviceUID) {
          return json({ ok: false, error: "invalid_device_id" }, 400);
        }
        if (lic.revoked === true) {
          return json({ ok: false, error: "key_revoked" });
        }
        if (Date.now() > lic.expiresAt) {
          return json({ ok: false, error: "key_expired" });
        }

        lic.devices = [...new Set(
          lic.devices
            .filter(x => typeof x === "string")
            .map(x => x.trim())
            .filter(Boolean)
        )];

        if (lic.devices.includes(deviceUID)) {
          return json({
            ok: true,
            already_registered: true,
            expires_at: lic.expiresAt,
            devices_used: lic.devices.length,
            max_devices: lic.maxDevices
          });
        }

        if (lic.devices.length >= lic.maxDevices) {
          return json({
            ok: false,
            error: "device_limit",
            devices_used: lic.devices.length,
            max_devices: lic.maxDevices
          });
        }

        lic.devices.push(deviceUID);
        await this.env.LICENSES.put(
          "license:" + key,
          JSON.stringify(lic)
        );

        return json({
          ok: true,
          already_registered: false,
          expires_at: lic.expiresAt,
          devices_used: lic.devices.length,
          max_devices: lic.maxDevices
        });
      }

      if (action === "reset") {
        lic.devices = [];
        await this.env.LICENSES.put("license:" + key, JSON.stringify(lic));
        return json({ ok: true });
      }

      if (action === "revoke") {
        lic.revoked = true;
        await this.env.LICENSES.put("license:" + key, JSON.stringify(lic));
        return json({ ok: true });
      }

      if (action === "delete") {
        await this.env.LICENSES.delete("license:" + key);
        return json({ ok: true });
      }

      return json({ ok: false, error: "unknown_action" }, 400);
    });
  }
};
  

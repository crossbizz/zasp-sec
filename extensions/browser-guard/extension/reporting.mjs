import { controlOrigin } from "./reporting-config.mjs";
const allowed = new Set(["https://claude.ai", "https://chatgpt.com"]);
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const encoder = new TextEncoder();

function b64(data) {
  return btoa(String.fromCharCode(...new Uint8Array(data)));
}

function db() {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open("zasp.profile.v1", 1);
    open.onupgradeneeded = () => open.result.createObjectStore("profile");
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

async function access(mode, task) {
  const database = await db();
  try {
    return await new Promise((resolve, reject) => {
      const tx = database.transaction("profile", mode);
      const request = task(tx.objectStore("profile"));
      tx.oncomplete = () => resolve(request.result);
      tx.onabort = () => reject(tx.error ?? Error("Storage unavailable"));
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    database.close();
  }
}

const storage = {
  load() { return access("readonly", (store) => store.get("bound")); },
  save(value) { return access("readwrite", (store) => store.put(value, "bound")); },
  clear() { return access("readwrite", (store) => store.delete("bound")); },
};

export function signInput(id, issued, nonce, days) {
  return encoder.encode(JSON.stringify(["zasp.browser-profile.v1", id, issued, nonce, days.map(({ origin, day }) => [origin, day])]));
}

export function createReporting({ origin = controlOrigin, store = storage, cryptoApi = crypto, request = fetch, now = () => new Date() } = {}) {
  const subtle = cryptoApi.subtle;
  async function identity() {
    const local = await store.load();
    if (local) return local;
    const signer = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    const vault = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const state = { signer, vault, key: b64(await subtle.exportKey("raw", signer.publicKey)), pending: [], state: "awaiting_registration" };
    await store.save(state);
    return state;
  }
  async function status(policy) {
    if (!origin || !policy.remoteEnabled) return { state: "local_only" };
    const local = await identity();
    return { state: local.state, control: origin, publicKey: local.key, id: local.id, environment: local.environment, lastSync: local.lastSync };
  }
  async function enroll(policy, id, environment, token) {
    if (!origin || !policy.remoteEnabled || !productID.test(id) || !productID.test(environment) ||
        typeof token !== "string" || !/^[!-~]{16,8192}$/.test(token)) throw Error("Invalid enrollment");
    const local = await identity();
    if (local.id && (local.id !== id || local.environment !== environment)) throw Error("Remove previous enrollment first");
    const iv = cryptoApi.getRandomValues(new Uint8Array(12));
    const encrypted = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(origin + "/" + id) }, local.vault, encoder.encode(token));
    await store.save({ ...local, id, environment, iv, encrypted, state: "awaiting_acknowledgment" });
    return sync(policy);
  }
  async function observe(policy, day) {
    if (!origin || !policy.remoteEnabled || !day || !allowed.has(day.origin) || !/^\d{4}-\d{2}-\d{2}$/.test(day.day) || !policy.origins.includes(day.origin)) return;
    const local = await store.load();
    if (!local?.id || local.state === "authorization_required") return;
    if (local.pending.some((v) => v.day === day.day && v.origin === day.origin)) return;
    local.pending = [...local.pending, { origin: day.origin, day: day.day }].slice(-60);
    await store.save(local);
  }
  async function sync(policy) {
    if (!origin) return { state: "local_only" };
    if (!policy.remoteEnabled) {
      // Turning central collection off also removes the private key and queued facts.
      await store.clear();
      return { state: "local_only" };
    }
    const local = await store.load();
    if (!local?.id || local.state === "authorization_required") return status(policy);
    const clock = now();
    const issued = Math.floor(clock.getTime() / 1000);
    const earliest = new Date(clock.getTime() - (policy.retentionDays - 1) * 86400000).toISOString().slice(0, 10);
    const days = local.pending.filter((v) => policy.origins.includes(v.origin) && v.day >= earliest && v.day <= clock.toISOString().slice(0, 10));
    local.pending = days;
    const nonce = [...cryptoApi.getRandomValues(new Uint8Array(16))].map((n) => n.toString(16).padStart(2, "0")).join("");
    const signature = b64(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, local.signer.privateKey, signInput(local.id, issued, nonce, days)));
    const credential = new TextDecoder().decode(await subtle.decrypt({ name: "AES-GCM", iv: local.iv, additionalData: encoder.encode(origin + "/" + local.id) }, local.vault, local.encrypted));
    try {
      const response = await request(origin + "/api/v1/browser-profiles/" + local.id + "/observations", {
        method: "POST", credentials: "omit", redirect: "error", cache: "no-store", referrerPolicy: "no-referrer", signal: AbortSignal.timeout(15000),
        headers: { "Content-Type": "application/json", Authorization: "Bearer " + credential },
        body: JSON.stringify({ issued_at: issued, nonce, days, signature }),
      });
      if ([401, 403, 404].includes(response.status)) {
        local.state = "authorization_required";
        local.pending = [];
      }
      else {
        if (!response.ok) throw Error("Service unavailable");
        const ack = await response.json();
        if (ack?.accepted !== true || ack.credential_id !== local.id || ack.environment_id !== local.environment) {
          local.state = "authorization_required";
          local.pending = [];
        } else {
          local.pending = [];
          local.state = "reporting";
          local.lastSync = clock.toISOString();
        }
      }
    } catch { local.state = "offline"; }
    await store.save(local);
    return status(policy);
  }
  async function remove() { await store.clear(); return { state: "removed" }; }
  return { enroll, status, sync, observe, remove };
}

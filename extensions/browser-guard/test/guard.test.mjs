import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createGuard, parsePolicy } from "../extension/guard.mjs";

const claude = "https://claude.ai";
const chatGPT = "https://chatgpt.com";
const read = (name) => readFile(new URL("../extension/" + name, import.meta.url), "utf8");

function fixture() {
  const state = { policy: {}, local: {}, scripts: new Map(), now: new Date("2026-03-01T23:55:00Z") };
  const api = {
    runtime: { id: "test-extension" },
    storage: {
      managed: { get: async () => state.policy },
      local: {
        get: async () => ({ ...state.local }),
        remove: async (keys) => { for (const key of keys) delete state.local[key]; },
        set: async (values) => Object.assign(state.local, values),
      }
    },
    scripting: {
      getRegisteredContentScripts: async () => [...state.scripts.values()],
      unregisterContentScripts: async ({ ids }) => ids.forEach((id) => state.scripts.delete(id)),
      registerContentScripts: async (scripts) => scripts.forEach((s) => state.scripts.set(s.id, s)),
    },
  };
  return { state, api, guard: createGuard(api, () => state.now) };
}
function sender(origin, extra = {}) {
  return { id: "test-extension", origin, tab: { id: 10, incognito: false }, frameId: 0, ...extra };
}

test("package grants exact origins, isolates scripts and forbids remote connections", async () => {
  const manifest = JSON.parse(await read("manifest.json"));
  assert.equal(manifest.incognito, "not_allowed");
  assert.deepEqual(manifest.permissions.toSorted(), ["alarms", "scripting", "storage"]);
  assert.deepEqual(manifest.host_permissions.toSorted(), [chatGPT + "/*", claude + "/*"]);
  assert.match(manifest.content_security_policy.extension_pages, /connect-src 'none'/);
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.externally_connectable, undefined);
  const observer = await read("observe.js");
  assert.doesNotMatch(observer, /\b(document|window|location|fetch|XMLHttpRequest|WebSocket|storage)\b/);
});

test("requires a valid scoped admin opt-in and removes registrations on disable", async () => {
  const { guard, state } = fixture();
  assert.equal((await guard.refresh()).policy.status, "unconfigured");
  assert.equal(parsePolicy({ Enabled: false }).status, "disabled");
  for (const AllowedOrigins of [null, [], ["*"], [claude + "/private"], ["https://example.test"], [chatGPT, 42]]) {
    assert.equal(parsePolicy({ Enabled: true, AllowedOrigins }).status, "invalid");
  }
  for (const RetentionDays of [0, 31, "7", 1.5]) {
    assert.equal(parsePolicy({ Enabled: true, AllowedOrigins: [claude], RetentionDays }).status, "invalid");
  }
  state.policy = { Enabled: true, AllowedOrigins: [claude, claude] };
  await guard.refresh();
  assert.equal(state.scripts.size, 1);
  const [script] = state.scripts.values();
  assert.deepEqual(script.matches, [claude + "/*"]);
  assert.equal(script.allFrames, false);
  assert.equal(script.world, "ISOLATED");
  await guard.observe(sender(claude));
  state.policy = { Enabled: false };
  await guard.observe(sender(chatGPT));
  const result = await guard.refresh();
  assert.equal(result.policy.status, "disabled");
  assert.deepEqual(state.local, {});
  assert.equal(state.scripts.size, 0);
});

test("only top-level allowed origins reach local storage and retain one UTC date per app", async () => {
  const { guard, state } = fixture();
  state.policy = { Enabled: true, AllowedOrigins: [claude] };
  for (const candidate of [
    sender(chatGPT), sender(claude + "/private"), sender(claude, { frameId: 1 }),
    sender(claude, { id: "external" }), sender(claude, { tab: { id: 10, incognito: true } }),
    sender(claude, { tab: undefined }), sender("null"),
  ]) await guard.observe(candidate);
  assert.deepEqual(state.local, {});
  const event = sender(claude);
  for (const field of ["url", "documentId", "title"]) {
    Object.defineProperty(event, field, { get() { throw new Error("unexpected field access"); } });
  }
  Object.defineProperty(event.tab, "url", { get() { throw new Error("path read"); } });
  await guard.observe(event);
  await guard.observe(event);
  assert.deepEqual(state.local, { "usage/claude/2026-03-01": true });
  state.policy = { Enabled: true, AllowedOrigins: [chatGPT] };
  await guard.observe(event); // stale content script still loaded after policy changed
  const status = await guard.refresh();
  assert.deepEqual(status.observations, []);
  assert.deepEqual(state.local, {});
});

test("retention expires old facts and clears local usage when management is unavailable", async () => {
  const { state, api, guard } = fixture();
  state.policy = { Enabled: true, AllowedOrigins: [claude], RetentionDays: 2 };
  await guard.observe(sender(claude));
  state.now = new Date("2026-03-02T00:00:00Z");
  await guard.observe(sender(claude));
  assert.equal((await guard.refresh()).observations.length, 2);
  state.now = new Date("2026-03-03T04:00:00Z");
  assert.deepEqual((await guard.refresh()).observations, [{ origin: claude, day: "2026-03-02" }]);
  api.storage.managed.get = async () => { throw new Error("policy unavailable"); };
  assert.equal((await guard.refresh()).policy.status, "unavailable");
  assert.deepEqual(state.local, {});
});

test("managed package pins the control plane and a nonextractable profile key verifies only minimal day receipts", async (t) => {
  const { mkdtemp, readFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { webcrypto } = await import("node:crypto");
  const { packageManaged } = await import("../package-managed.mjs");
  const { createReporting, signInput } = await import("../extension/reporting.mjs");
  const tmp = await mkdtemp(join(tmpdir(), "zasp-browser-"));
  t.after(() => rm(tmp, { recursive: true, force: true }));
  await assert.rejects(packageManaged("https://example.test/a", join(tmp, "reject")));
  await packageManaged("https://pilot.test", join(tmp, "pilot"));
  const manifest = JSON.parse(await readFile(join(tmp, "pilot/manifest.json"), "utf8"));
  assert.deepEqual(manifest.host_permissions.sort(), [chatGPT + "/*", claude + "/*", "https://pilot.test/*"].sort());
  assert.match(manifest.content_security_policy.extension_pages, /connect-src https:\/\/pilot\.test;/);
  let bound;
  const store = { async save(x) { bound = structuredClone(x); }, async load() { return structuredClone(bound); }, async clear() { bound = undefined; } };
  const ids = ["pid_00000000-0000-4000-8000-000000000001", "pid_00000000-0000-4000-8000-000000000002"];
  const policy = { status: "enabled", remoteEnabled: true, origins: [claude], retentionDays: 7 };
  const credential = "zasp_test_dedicated_token";
  let revoke = false;
  const requests = [];
  const client = createReporting({ origin: "https://pilot.test", cryptoApi: webcrypto, store, now: () => new Date("2026-03-03T14:00:00Z"),
    request: async (url, init) => {
      assert.equal(url, "https://pilot.test/api/v1/browser-profiles/" + ids[0] + "/observations");
      assert.equal(init.credentials, "omit");
      assert.equal(init.redirect, "error");
      assert.equal(init.headers.Authorization, "Bearer " + credential);
      const body = JSON.parse(init.body);
      assert.deepEqual(Object.keys(body).sort(), ["issued_at","nonce","days","signature"].sort());
      const verified = await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, bound.signer.publicKey,
        Buffer.from(body.signature, "base64"), signInput(ids[0], body.issued_at, body.nonce, body.days));
      assert.equal(verified, true); requests.push(body.days);
      return { ok: !revoke, status: revoke ? 403 : 200, json: async () => ({ accepted: true, credential_id: ids[0], environment_id: ids[1] }) };
    },
  });
  assert.equal((await client.status({})).state, "local_only");
  await client.observe(policy, { origin: claude, day: "2026-03-03" });
  const initial = await client.status(policy);
  assert.equal(initial.state, "awaiting_registration");
  const enrolled = await client.enroll(policy, ...ids, credential);
  assert.deepEqual(requests, [[]]); assert.equal(enrolled.state, "reporting");
  assert.equal(bound.signer.privateKey.extractable, false); assert.equal(bound.vault.extractable, false);
  assert.ok(!JSON.stringify(bound).includes(credential));
  assert.ok(!JSON.stringify(enrolled).includes(credential));
  await client.observe(policy, { origin: chatGPT, day: "2026-03-03" });
  await client.observe(policy, { origin: claude, day: "2026-03-03" });
  await client.observe(policy, { origin: claude, day: "2026-03-03" });
  await client.sync(policy); assert.deepEqual(requests[1], [{ origin: claude, day: "2026-03-03" }]);
  revoke = true;
  assert.equal((await client.sync(policy)).state, "authorization_required");
  await client.sync(policy); assert.equal(requests.length, 3);
  await client.sync({}); assert.equal(bound, undefined);
});

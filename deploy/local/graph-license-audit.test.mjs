import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  GRAPH_LICENSE_SUCCESS_LINE,
  auditGraphLicenses,
  parseGraphLicenseInventory,
  runMain,
} from "./graph-license-audit.mjs";
import * as graphLicenseModule from "./graph-license-audit.mjs";

const inventoryPath = new URL("./graph-licenses.json", import.meta.url);
const exactArtifacts = Object.freeze([
  ["https://raw.githubusercontent.com/neo4j/neo4j/09de4c547ee24f69400c75df8428685e27a9cffc/pom.xml", "288ac5913d95557ab36b1139ed7854aadcdd4cbf5ca2d3cf1c86a4afcd743067"],
  ["https://raw.githubusercontent.com/neo4j/neo4j/09de4c547ee24f69400c75df8428685e27a9cffc/LICENSE.txt", "8e1bb72dd89711d9612ea2749c906e4b17760245f4ffdfcc237219f4df48e440"],
  ["https://raw.githubusercontent.com/kubernetes/kubernetes/22d90ebde235edec3541f728b37a01285bdd8b1b/test/images/busybox/Dockerfile", "b1a06c7718262b6de2aebb822093dbc4215f980500024ca65d2206341a7a3838"],
  ["https://raw.githubusercontent.com/kubernetes/kubernetes/22d90ebde235edec3541f728b37a01285bdd8b1b/LICENSE", "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"],
  ["https://busybox.net/downloads/busybox-1.36.1.tar.bz2", "b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314"],
  ["https://raw.githubusercontent.com/mirror/busybox/1_36_1/LICENSE", "bbfc9843646d483c334664f651c208b9839626891d8f17604db2146962f43548"],
]);

async function inventoryText() {
  return readFile(inventoryPath, "utf8");
}

function artifactReader(inventory, driftUrl) {
  const hashes = new Map(inventory.components.flatMap((component) => [
    [component.source_url, component.source_sha256],
    [component.license_url, component.license_sha256],
  ]));
  return async (url) => driftUrl === url ? "0".repeat(64) : hashes.get(url);
}

function fetchResponse(reads, overrides = {}) {
  const events = [];
  let index = 0;
  const reader = {
    async cancel() { events.push("cancel"); },
    async read() {
      events.push("read");
      return reads[index++] ?? { done: true, value: undefined };
    },
    releaseLock() { events.push("release"); },
  };
  return {
    events,
    response: {
      body: { getReader: () => { events.push("reader"); return reader; } },
      headers: {
        get: (name) => name.toLowerCase() === "content-length"
          ? overrides.contentLength ?? null
          : null,
      },
      ok: overrides.ok ?? true,
      redirected: overrides.redirected ?? false,
      status: overrides.status ?? 200,
    },
  };
}

test("records exact immutable Neo4j and BusyBox image, platform, source, and license evidence", async () => {
  const inventory = parseGraphLicenseInventory(await inventoryText());
  assert.equal(inventory.schema_version, 1);
  assert.deepEqual(inventory.scope, {
    use: "opt-in-local-development",
    redistribution_approved: false,
    production_packaging_approved: false,
  });
  assert.deepEqual(inventory.allowed_licenses, ["Apache-2.0", "GPL-2.0-only", "GPL-3.0-only"]);
  assert.deepEqual(inventory.images.neo4j, {
    name: "neo4j-community-server",
    version: "5.26.28-community",
    reference: "neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357",
    index_digest: "sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357",
    platforms: {
      "linux/amd64": {
        manifest_digest: "sha256:77a7a788aa3348c66a4c12a07930bc12232f22535b0e1a2a043df80bbfa823bd",
        config_digest: "sha256:534fe13ef23432459f04f65e1fa4c25876bb981f147d96b1b3896278d23e7552",
      },
      "linux/arm64": {
        manifest_digest: "sha256:5bed6b3adb938c45722e3639b853ecbc948b2e51cd5599d45fcd23f6d49b2d89",
        config_digest: "sha256:db03e618d0cd04bbabeb4bf5296c91108f4be5185456565bb4046a33b226fcd2",
      },
    },
  });
  assert.deepEqual(inventory.images.busybox, {
    name: "kubernetes-e2e-busybox",
    version: "1.36.1-1",
    reference: "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
    index_digest: "sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
    platforms: {
      "linux/amd64": {
        manifest_digest: "sha256:caec39cad3b12c26600baf6e67ba811ac15d28a9288d0ccdfffb4b318992c3bb",
        config_digest: "sha256:3e0d9138669908f438c06993e9a6815bbd8c05411b8e9acfc297b3c8b017c28c",
      },
      "linux/arm64": {
        manifest_digest: "sha256:55c89c6d9404d6668eb237dda92f28a99eb14e640f1c177a55cc9d738c53c303",
        config_digest: "sha256:6d0099de92b2a095017ed32499154f16eec2df38f0d2e9192bcf6ae7d241ac75",
      },
    },
  });
  assert.deepEqual(inventory.components.map(({ name, version, license, source_commit }) => ({ name, version, license, source_commit })), [
    { name: "Neo4j Community server", version: "5.26.28", license: "GPL-3.0-only", source_commit: "09de4c547ee24f69400c75df8428685e27a9cffc" },
    { name: "Kubernetes e2e BusyBox image packaging", version: "1.36.1-1", license: "Apache-2.0", source_commit: "22d90ebde235edec3541f728b37a01285bdd8b1b" },
    { name: "BusyBox runtime", version: "1.36.1", license: "GPL-2.0-only", source_commit: "release-tarball-busybox-1.36.1" },
  ]);
});

test("audits all six bounded source and license artifacts without packaging approval", async () => {
  const inventory = parseGraphLicenseInventory(await inventoryText());
  const result = await auditGraphLicenses({
    inventoryText: await inventoryText(),
    fingerprintArtifact: artifactReader(inventory),
  });
  assert.deepEqual(result, { components: 3, artifacts: 6, prohibited: 0, redistributionApproved: false });
});

test("calls the exact six immutable artifacts once and in inventory order", async () => {
  const calls = [];
  const result = await auditGraphLicenses({
    inventoryText: await inventoryText(),
    fingerprintArtifact: async (url) => {
      calls.push(url);
      const expected = exactArtifacts[calls.length - 1];
      if (expected?.[0] !== url) throw new Error("unexpected artifact order");
      return expected[1];
    },
  });
  assert.deepEqual(calls, exactArtifacts.map(([url]) => url));
  assert.deepEqual(result, { components: 3, artifacts: 6, prohibited: 0, redistributionApproved: false });
});

test("the production audit aborts and cancels an invalid provider response", async () => {
  const subject = fetchResponse([{ done: true, value: undefined }], { ok: false, status: 503 });
  const source = await inventoryText();
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (_url, options) => {
    options.signal.addEventListener("abort", () => subject.events.push("abort"), { once: true });
    return subject.response;
  };
  try {
    await assert.rejects(() => auditGraphLicenses({ inventoryText: source }));
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.deepEqual(subject.events, ["reader", "abort", "cancel", "release"]);
});

test("fingerprints bounded chunked bytes through the exact production fetch policy", async () => {
  const subject = fetchResponse([
    { done: false, value: Uint8Array.from([0x61]) },
    { done: false, value: Uint8Array.from([0x62, 0x63]) },
    { done: true, value: undefined },
  ]);
  let request;
  const actual = await graphLicenseModule.fingerprintUrl("https://example.test/artifact", {
    fetchImpl: async (url, options) => {
      request = {
        headers: options.headers,
        redirect: options.redirect,
        signal: options.signal,
        url,
      };
      options.signal.addEventListener("abort", () => subject.events.push("abort"), { once: true });
      return subject.response;
    },
  });
  assert.equal(actual, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.deepEqual({ headers: request.headers, redirect: request.redirect, url: request.url }, {
    headers: {
      Accept: "application/octet-stream",
      "Accept-Encoding": "identity",
      "User-Agent": "zasp-local-graph-license-audit/1",
    },
    redirect: "error",
    url: "https://example.test/artifact",
  });
  assert.equal(request.signal.aborted, false);
  assert.deepEqual(subject.events, ["reader", "read", "read", "read", "release"]);
});

test("requires an exact declared content length when the provider sends one", async () => {
  const subject = fetchResponse([
    { done: false, value: Uint8Array.from([0x61, 0x62, 0x63]) },
    { done: true, value: undefined },
  ], { contentLength: "3" });
  const actual = await graphLicenseModule.fingerprintUrl("https://example.test/artifact", {
    fetchImpl: async () => subject.response,
  });
  assert.equal(actual, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assert.deepEqual(subject.events, ["reader", "read", "read", "release"]);
});

test("aborts and cancels before release on every rejected artifact body", async () => {
  const oversized = new Uint8Array(8 * 1024 * 1024 + 1);
  const cases = [
    ["status", [{ done: true, value: undefined }], { ok: false, status: 404 }],
    ["redirect", [{ done: true, value: undefined }], { redirected: true }],
    ["malformed length", [{ done: false, value: Uint8Array.from([1, 2, 3]) }], { contentLength: "03" }],
    ["length mismatch", [
      { done: false, value: Uint8Array.from([1, 2, 3]) }, { done: true, value: undefined },
    ], { contentLength: "4" }],
    ["declared oversize", [{ done: true, value: undefined }], { contentLength: "8388609" }],
    ["empty", [{ done: true, value: undefined }], {}],
    ["malformed chunk", [{ done: false, value: "bytes" }], {}],
    ["oversize", [{ done: false, value: oversized }], {}],
  ];
  for (const [name, reads, overrides] of cases) {
    const subject = fetchResponse(reads, overrides);
    await assert.rejects(() => graphLicenseModule.fingerprintUrl("https://example.test/artifact", {
      cleanupTimeoutMilliseconds: 10,
      fetchImpl: async (_url, options) => {
        options.signal.addEventListener("abort", () => subject.events.push("abort"), { once: true });
        return subject.response;
      },
    }), undefined, name);
    assert.ok(subject.events.indexOf("abort") >= 0, name);
    assert.ok(subject.events.indexOf("cancel") > subject.events.indexOf("abort"), name);
    assert.ok(subject.events.indexOf("release") > subject.events.indexOf("cancel"), name);
  }
});

test("bounds timeout and a reader that never settles cancellation", async () => {
  const events = [];
  let signal;
  const reader = {
    cancel() { events.push("cancel"); return new Promise(() => {}); },
    read() {
      events.push("read");
      signal.addEventListener("abort", () => {
        events.push("abort");
      }, { once: true });
      return new Promise(() => {});
    },
    releaseLock() { events.push("release"); },
  };
  const result = await Promise.race([
    graphLicenseModule.fingerprintUrl("https://example.test/artifact", {
      cleanupTimeoutMilliseconds: 5,
      fetchImpl: async (_url, options) => {
        signal = options.signal;
        return {
          body: { getReader: () => reader },
          headers: { get: () => null },
          ok: true,
          redirected: false,
          status: 200,
        };
      },
      timeoutMilliseconds: 5,
    }).then(() => "resolved", () => "rejected"),
    new Promise((resolve) => setTimeout(() => resolve("unbounded"), 250)),
  ]);
  assert.equal(result, "rejected");
  assert.deepEqual(events, ["read", "abort", "cancel", "release"]);
});

test("rejects missing, prohibited, mutable, duplicate, and drifted inventory evidence", async () => {
  const source = await inventoryText();
  const inventory = parseGraphLicenseInventory(source);
  const mutate = (callback) => {
    const value = structuredClone(inventory);
    callback(value);
    return JSON.stringify(value);
  };
  const cases = [
    ["missing", mutate((value) => { delete value.images.neo4j.index_digest; })],
    ["license", mutate((value) => { value.components[0].license = "proprietary"; })],
    ["mutable image", mutate((value) => { value.images.neo4j.reference = "neo4j:5.26.28-community"; })],
    ["scope", mutate((value) => { value.scope.use = "production"; })],
    ["redistribution", mutate((value) => { value.scope.redistribution_approved = true; })],
    ["version", mutate((value) => { value.components[2].version = "latest"; })],
    ["platform", mutate((value) => { value.images.busybox.platforms["linux/arm64"].config_digest = `sha256:${"0".repeat(64)}`; })],
    ["source", mutate((value) => { value.components[1].source_sha256 = "0".repeat(64); })],
    ["unknown", mutate((value) => { value.extra = true; })],
    ["duplicate JSON", source.replace('"schema_version": 1', '"schema_version": 1,\n  "schema_version": 1')],
  ];
  for (const [name, value] of cases) assert.throws(() => parseGraphLicenseInventory(value), undefined, name);

  await assert.rejects(() => auditGraphLicenses({
    inventoryText: source,
    fingerprintArtifact: artifactReader(inventory, inventory.components[0].license_url),
  }));
  await assert.rejects(() => auditGraphLicenses({ inventoryText: source, fingerprintArtifact: async () => undefined }));
});

test("emits one fixed summary and suppresses raw artifact failures", async () => {
  const inventory = parseGraphLicenseInventory(await inventoryText());
  const output = [];
  const error = [];
  assert.equal(await runMain({
    writeOutput: (value) => output.push(value),
    writeError: (value) => error.push(value),
    inventoryText: await inventoryText(),
    fingerprintArtifact: artifactReader(inventory),
  }), 0);
  assert.deepEqual(output, [`${GRAPH_LICENSE_SUCCESS_LINE}\n`]);
  assert.deepEqual(error, []);

  output.length = 0;
  assert.equal(await runMain({
    writeOutput: (value) => output.push(value),
    writeError: (value) => error.push(value),
    inventoryText: await inventoryText(),
    fingerprintArtifact: async () => { throw new Error("raw provider response"); },
  }), 1);
  assert.deepEqual(output, []);
  assert.deepEqual(error, ["Local graph license audit failed.\n"]);
  assert.doesNotMatch(error.join(""), /provider|response/);
});

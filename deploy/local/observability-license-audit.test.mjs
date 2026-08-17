import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  OBSERVABILITY_LICENSE_SUCCESS_LINE,
  auditObservabilityLicenses,
  fingerprintObservabilityArtifact,
  parseObservabilityLicenseInventory,
  runMain,
} from "./observability-license-audit.mjs";

const inventoryText = await readFile(new URL("./observability-licenses.json", import.meta.url), "utf8");

function response({ body = [new TextEncoder().encode("artifact")], contentLength = null, ok = true, redirected = false, status = 200 } = {}, events = []) {
  let index = 0;
  return {
    body: {
      getReader() {
        return {
          async cancel() { events.push("cancel"); },
          async read() {
            if (index >= body.length) return { done: true, value: undefined };
            const value = body[index];
            index += 1;
            return { done: false, value };
          },
          releaseLock() { events.push("release"); },
        };
      },
    },
    headers: { get(name) { return name === "content-length" ? contentLength : null; } },
    ok,
    redirected,
    status,
  };
}

test("binds exact Collector and reused BusyBox immutable license evidence", async () => {
  const inventory = parseObservabilityLicenseInventory(inventoryText);
  assert.equal(inventory.images.collector.reference, "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5");
  assert.equal(inventory.images.collector.index_digest, "sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5");
  assert.deepEqual(inventory.images.collector.platforms, {
    "linux/amd64": {
      manifest_digest: "sha256:e290476fa9a75f7a84a28798832bde7068d27825745de67bc38957e22949a64c",
      config_digest: "sha256:837606a793453fd0c2eef9a6d4ee47ecc970d228ede7bc0c15d32ea9324c9e80",
    },
    "linux/arm64": {
      manifest_digest: "sha256:51e1afc9d762a359387723170be5cecccad2c09e73a5a2061361c62c60855ccf",
      config_digest: "sha256:e4ed3985c0db662ed2f0be81ac3b10110aefd379b0be24c780e2803571997c93",
    },
  });
  assert.equal(inventory.images.collector.image_revision, "1400269f8ace841f8d0492f4f9c6c7f305f95268");
  assert.equal(inventory.components[0].source_commit, "821a9d9c2c1623c4a0ceba5d47b57c48879c3f84");
  assert.equal(inventory.components[0].license, "Apache-2.0");
  assert.equal(inventory.busybox_reuse.graph_inventory_sha256, "b4bfd72f704a86d812a056c3fd153a8d8e384b6e81e53f5ac327c5d3844a8323");
  assert.equal(inventory.scope.redistribution_approved, false);
  assert.equal(inventory.scope.production_packaging_approved, false);
  assert.ok(Object.isFrozen(inventory));

  const seen = [];
  const result = await auditObservabilityLicenses({
    inventoryText,
    fingerprintArtifact: async (url) => {
      seen.push(url);
      const artifact = inventory.artifacts.find(({ url: candidate }) => candidate === url);
      assert.ok(artifact);
      return artifact.sha256;
    },
  });
  assert.deepEqual(seen, inventory.artifacts.map(({ url }) => url));
  assert.deepEqual(result, { components: 2, artifacts: 3, prohibited: 0, redistributionApproved: false });
});

test("rejects inventory drift, duplicate keys, prohibited licenses, and mutable evidence", () => {
  const mutations = [
    inventoryText.replace('"version": "0.158.0"', '"version": "latest"'),
    inventoryText.replace('"license": "Apache-2.0"', '"license": "Proprietary"'),
    inventoryText.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
    inventoryText.replace('"redistribution_approved": false', '"redistribution_approved": true'),
    `${inventoryText}\n{}`,
  ];
  for (const value of mutations) assert.throws(() => parseObservabilityLicenseInventory(value), TypeError);
  assert.throws(() => parseObservabilityLicenseInventory({ toString() { throw new Error("coercion"); } }), TypeError);
});

test("fingerprints the real bounded fetch boundary and cleans every rejection", async () => {
  const events = [];
  const artifact = new TextEncoder().encode("artifact");
  const digest = await fingerprintObservabilityArtifact("https://example.invalid/artifact", {
    fetchImpl: async (url, options) => {
      assert.equal(url, "https://example.invalid/artifact");
      assert.deepEqual(options, {
        signal: options.signal,
        redirect: "error",
        headers: {
          Accept: "application/octet-stream",
          "Accept-Encoding": "identity",
          "User-Agent": "zasp-local-observability-license-audit/1",
        },
      });
      assert.equal(options.signal.aborted, false);
      return response({ body: [artifact.subarray(0, 3), artifact.subarray(3)], contentLength: String(artifact.byteLength) }, events);
    },
    timeoutMilliseconds: 100,
    cleanupTimeoutMilliseconds: 20,
  });
  assert.equal(digest, "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c");
  assert.deepEqual(events, ["release"]);

  for (const invalidResponse of [
    response({ status: 302, ok: false }),
    response({ redirected: true }),
    response({ contentLength: "01" }),
    response({ contentLength: "2", body: [artifact] }),
    response({ body: [] }),
    response({ body: [new Uint8Array(8 * 1024 * 1024 + 1)] }),
  ]) {
    const cleanup = [];
    const wrapped = { ...invalidResponse, body: { getReader() {
      const reader = invalidResponse.body.getReader();
      return {
        ...reader,
        cancel() { cleanup.push("cancel"); return Promise.resolve(); },
        releaseLock() { cleanup.push("release"); },
      };
    } } };
    await assert.rejects(() => fingerprintObservabilityArtifact("https://example.invalid/artifact", {
      fetchImpl: async (_url, { signal }) => {
        signal.addEventListener("abort", () => cleanup.push("abort"), { once: true });
        return wrapped;
      },
      timeoutMilliseconds: 100,
      cleanupTimeoutMilliseconds: 5,
    }), TypeError);
    assert.deepEqual(cleanup, ["abort", "cancel", "release"]);
  }
});

test("bounds a cancellation promise that never settles and emits fixed CLI output", async () => {
  const events = [];
  await assert.rejects(() => fingerprintObservabilityArtifact("https://example.invalid/artifact", {
    fetchImpl: async (_url, { signal }) => {
      signal.addEventListener("abort", () => events.push("abort"), { once: true });
      return {
        ...response({ status: 500, ok: false }),
        body: { getReader() { return {
          cancel() { events.push("cancel"); return new Promise(() => {}); },
          read() { return new Promise(() => {}); },
          releaseLock() { events.push("release"); },
        }; } },
      };
    },
    timeoutMilliseconds: 50,
    cleanupTimeoutMilliseconds: 5,
  }), TypeError);
  assert.deepEqual(events, ["abort", "cancel", "release"]);

  let stdout = "";
  let stderr = "";
  const inventory = parseObservabilityLicenseInventory(inventoryText);
  const code = await runMain({
    inventoryText,
    fingerprintArtifact: async (url) => inventory.artifacts.find((artifact) => artifact.url === url).sha256,
    writeOutput: (value) => { stdout += value; },
    writeError: (value) => { stderr += value; },
  });
  assert.equal(code, 0);
  assert.equal(stdout, `${OBSERVABILITY_LICENSE_SUCCESS_LINE}\n`);
  assert.equal(stderr, "");
});

test("rejects forged options before fetch and aborts reader and deadline failures", async () => {
  let called = false;
  await assert.rejects(() => fingerprintObservabilityArtifact("https://example.invalid/artifact", {
    [Symbol("forged")]: true,
    fetchImpl: async () => {
      called = true;
      return response();
    },
  }), TypeError);
  assert.equal(called, false);

  const readEvents = [];
  await assert.rejects(() => fingerprintObservabilityArtifact("https://example.invalid/artifact", {
    fetchImpl: async (_url, { signal }) => {
      signal.addEventListener("abort", () => readEvents.push("abort"), { once: true });
      return {
        ...response(),
        body: { getReader() { return {
          cancel() { readEvents.push("cancel"); },
          async read() { throw new Error("reader failure"); },
          releaseLock() { readEvents.push("release"); },
        }; } },
      };
    },
    timeoutMilliseconds: 100,
    cleanupTimeoutMilliseconds: 5,
  }), TypeError);
  assert.deepEqual(readEvents, ["abort", "cancel", "release"]);

  const timeoutEvents = [];
  await assert.rejects(() => fingerprintObservabilityArtifact("https://example.invalid/artifact", {
    fetchImpl: async (_url, { signal }) => {
      signal.addEventListener("abort", () => timeoutEvents.push("abort"), { once: true });
      return new Promise(() => {});
    },
    timeoutMilliseconds: 5,
    cleanupTimeoutMilliseconds: 5,
  }), TypeError);
  assert.deepEqual(timeoutEvents, ["abort"]);
});

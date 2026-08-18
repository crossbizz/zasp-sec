import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import {
  AWS_EMULATOR_LICENSE_SUCCESS_LINE,
  auditAwsEmulatorLicenses,
  fingerprintAwsEmulatorArtifact,
  parseAwsEmulatorLicenseInventory,
  runMain,
} from "./aws-emulator-license-audit.mjs";

const inventoryText = await readFile(new URL("./aws-emulator-licenses.json", import.meta.url), "utf8");

function response({ body = [new TextEncoder().encode("artifact")], contentLength = null, ok = true, redirected = false, status = 200 } = {}, events = []) {
  let index = 0;
  return {
    ok,
    redirected,
    status,
    headers: { get(name) { return name.toLowerCase() === "content-length" ? contentLength : null; } },
    body: { getReader() { return {
      async cancel() { events.push("cancel"); },
      async read() { return index < body.length ? { done: false, value: body[index++] } : { done: true, value: undefined }; },
      releaseLock() { events.push("release"); },
    }; } },
  };
}

test("binds the exact LocalStack Community image, source, terms, and artifact hashes", async () => {
  const inventory = parseAwsEmulatorLicenseInventory(inventoryText);
  assert.deepEqual(inventory.allowed_licenses, ["Apache-2.0"]);
  assert.deepEqual(inventory.image, {
    component: "localstack-community",
    reference: "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    repo_digest: "localstack/localstack@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
    environment_sha256: "1e4fe2995cc9b2339761b690070d16ababb619a51bf41a49d5148ddac7517092",
    environment_count: 10,
    entrypoint: ["docker-entrypoint.sh"],
    command: null,
    user: "",
    working_directory: "/opt/code/localstack/",
    labels: {
      authors: "LocalStack Contributors",
      description: "LocalStack Docker image",
      maintainer: "LocalStack Team (info@localstack.cloud)",
    },
  });
  assert.equal(inventory.component.version, "4.7.0");
  assert.equal(inventory.component.license, "Apache-2.0");
  assert.equal(inventory.component.source_tag_object, "dff59755581d7c1832e4e9e985362b6062b88a08");
  assert.equal(inventory.component.source_commit, "82de91e30b0185a6792dd5047168b29d69bbb1f9");
  assert.deepEqual(inventory.component.artifacts.map(({ kind, sha256 }) => ({ kind, sha256 })), [
    { kind: "license", sha256: "dcf0bef59ebd52c34046e43df3480d47f26c2f1f2ebcc8dd1ba0bb71ce0b058b" },
    { kind: "supplemental-terms", sha256: "5df76f56494d8cdbfb56a1d8e4c4c53cbe25281a4a09f4e8e9c63041dbe55a61" },
    { kind: "manifest", sha256: "48995e124a42ce9a20d2856eaab5123b257f3cbe3218705d6f17cff1e7c86f50" },
  ]);
  assert.equal(inventory.scope.redistribution_approved, false);
  assert.equal(inventory.scope.production_packaging_approved, false);
  assert.ok(Object.isFrozen(inventory));

  const seen = [];
  const result = await auditAwsEmulatorLicenses({
    inventoryText,
    fingerprintArtifact: async (url) => {
      seen.push(url);
      return inventory.component.artifacts.find((artifact) => artifact.url === url).sha256;
    },
  });
  assert.deepEqual(seen, inventory.component.artifacts.map(({ url }) => url));
  assert.deepEqual(result, { components: 1, artifacts: 3, prohibited: 0, redistributionApproved: false });
});

test("rejects inventory drift, duplicate keys, prohibited licenses, and mutable evidence", () => {
  for (const value of [
    inventoryText.replace('"version": "4.7.0"', '"version": "latest"'),
    inventoryText.replace('"license": "Apache-2.0"', '"license": "Proprietary"'),
    inventoryText.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
    inventoryText.replace('"redistribution_approved": false', '"redistribution_approved": true'),
    `${inventoryText}\n{}`,
  ]) assert.throws(() => parseAwsEmulatorLicenseInventory(value), TypeError);
  assert.throws(() => parseAwsEmulatorLicenseInventory({ toString() { throw new Error("coercion"); } }), TypeError);
});

test("fingerprints the bounded production fetch and terminates rejected readers", async () => {
  const artifact = new TextEncoder().encode("artifact");
  const events = [];
  const digest = await fingerprintAwsEmulatorArtifact("https://example.invalid/artifact", {
    fetchImpl: async (_url, options) => {
      assert.equal(options.redirect, "error");
      assert.equal(options.signal.aborted, false);
      return response({ body: [artifact.subarray(0, 3), artifact.subarray(3)], contentLength: "8" }, events);
    },
    timeoutMilliseconds: 100,
    cleanupTimeoutMilliseconds: 20,
  });
  assert.equal(digest, "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c");
  assert.deepEqual(events, ["release"]);

  for (const invalid of [
    response({ status: 302, ok: false }),
    response({ redirected: true }),
    response({ contentLength: "01" }),
    response({ contentLength: "2", body: [artifact] }),
    response({ body: [] }),
    response({ body: [new Uint8Array(8 * 1024 * 1024 + 1)] }),
  ]) {
    const cleanup = [];
    const original = invalid.body.getReader.bind(invalid.body);
    invalid.body = { getReader() {
      const reader = original();
      return {
        cancel() { cleanup.push("cancel"); return Promise.resolve(); },
        read: reader.read.bind(reader),
        releaseLock() { cleanup.push("release"); },
      };
    } };
    await assert.rejects(() => fingerprintAwsEmulatorArtifact("https://example.invalid/artifact", {
      fetchImpl: async (_url, { signal }) => {
        signal.addEventListener("abort", () => cleanup.push("abort"), { once: true });
        return invalid;
      },
      timeoutMilliseconds: 100,
      cleanupTimeoutMilliseconds: 5,
    }), TypeError);
    assert.deepEqual(cleanup, ["abort", "cancel", "release"]);
  }
});

test("emits only fixed audit output", async () => {
  const inventory = parseAwsEmulatorLicenseInventory(inventoryText);
  let stdout = "";
  let stderr = "";
  const code = await runMain({
    inventoryText,
    fingerprintArtifact: async (url) => inventory.component.artifacts.find((artifact) => artifact.url === url).sha256,
    writeOutput: (value) => { stdout += value; },
    writeError: (value) => { stderr += value; },
  });
  assert.equal(code, 0);
  assert.equal(stdout, `${AWS_EMULATOR_LICENSE_SUCCESS_LINE}\n`);
  assert.equal(stderr, "");
});

test("uses one shared deadline and bounds cancellation that never settles", async () => {
  const inventory = parseAwsEmulatorLicenseInventory(inventoryText);
  const calls = [];
  const started = Date.now();
  await assert.rejects(() => auditAwsEmulatorLicenses({
    inventoryText,
    timeoutMilliseconds: 25,
    fingerprintArtifact: async (url, { signal }) => {
      calls.push(url);
      await new Promise((resolve, rejectPromise) => {
        const timer = setTimeout(resolve, 15);
        signal.addEventListener("abort", () => {
          clearTimeout(timer);
          rejectPromise(new Error("audit deadline"));
        }, { once: true });
      });
      return inventory.component.artifacts.find((artifact) => artifact.url === url).sha256;
    },
  }), TypeError);
  assert.deepEqual(calls, inventory.component.artifacts.slice(0, 2).map(({ url }) => url));
  assert.ok(Date.now() - started < 150);

  const events = [];
  await assert.rejects(() => fingerprintAwsEmulatorArtifact("https://example.invalid/artifact", {
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
});

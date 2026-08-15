import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  auditAdapterLicense,
  fingerprintURL,
  loadLicenseInventory,
  parseLicenseInventory,
  runMain,
} from "./license-audit.mjs";

const commit = "64a3625d33bc6ad8e7c40df03b76ce2fb3ab4d21";
const moduleSum = "h1:TMm6bCyb3CEL4wjXsXn1d/kBSBbjF+5sEIyzQvbJiEw=";
const goModSum = "h1:lcuZYSlqQpXFzsA6EJCELmfR5+nNOpZYX+eo7xaIIlk=";
const licenseSha256 = "c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08";

function validInventory() {
  return {
    schema_version: 1,
    allowed_licenses: ["Apache-2.0"],
    component: {
      name: "Open Policy Agent",
      module: "github.com/open-policy-agent/opa",
      version: "v1.17.0",
      license: "Apache-2.0",
      source_repository: "https://github.com/open-policy-agent/opa",
      source_tag: "v1.17.0",
      source_commit: commit,
      module_sum: moduleSum,
      go_mod_sum: goModSum,
      module_time: "2026-05-28T14:48:35Z",
      license_url: `https://raw.githubusercontent.com/open-policy-agent/opa/${commit}/LICENSE`,
      license_sha256: licenseSha256,
      boundary: "Prepared in-process Rego query used only by the local OPA SDK proof.",
    },
  };
}

function validDependencies() {
  return {
    readGoMod: async () => "module github.com/zasp-ai/zasp-sec/proofs/opa-sdk\n\ngo 1.25.0\n\ntoolchain go1.26.5\n\nrequire github.com/open-policy-agent/opa v1.17.0\n",
    readGoSum: async () => `github.com/open-policy-agent/opa v1.17.0 ${moduleSum}\ngithub.com/open-policy-agent/opa v1.17.0/go.mod ${goModSum}\n`,
    resolveTag: async () => commit,
    moduleInfo: async () => ({
      Version: "v1.17.0",
      Time: "2026-05-28T14:48:35Z",
      Origin: { VCS: "git", URL: "https://github.com/open-policy-agent/opa", Hash: commit, Ref: "refs/tags/v1.17.0" },
    }),
    fingerprintUrl: async () => licenseSha256,
  };
}

test("loads the tracked exact OPA license inventory", async () => {
  const inventory = await loadLicenseInventory();
  assert.deepEqual(inventory, validInventory());
});

test("audits exact tag, module, sums, metadata, and license", async () => {
  const result = await auditAdapterLicense(validInventory(), validDependencies());
  assert.deepEqual(result, { components: 1, artifacts: 3, prohibited: 0 });
});

test("rejects every immutable authority drift", async (t) => {
  const cases = {
    "source tag": (inventory) => { inventory.component.source_tag = "v1.16.0"; },
    "source commit": (inventory) => { inventory.component.source_commit = "0".repeat(40); },
    "module version": (inventory) => { inventory.component.version = "v1.16.0"; },
    "module sum": (inventory) => { inventory.component.module_sum = `h1:${"A".repeat(44)}`; },
    "go.mod sum": (inventory) => { inventory.component.go_mod_sum = `h1:${"B".repeat(44)}`; },
    repository: (inventory) => { inventory.component.source_repository = "https://example.invalid/opa"; },
    license: (inventory) => { inventory.component.license = "MIT"; },
    "license hash": (inventory) => { inventory.component.license_sha256 = "0".repeat(64); },
    "unknown key": (inventory) => { inventory.component.extra = true; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    await t.test(name, async () => {
      const inventory = validInventory();
      mutate(inventory);
      await assert.rejects(auditAdapterLicense(inventory, validDependencies()), /rejected/);
    });
  }
});

test("rejects fetched authority and local module drift", async (t) => {
  const cases = {
    "tag resolution": (dependencies) => { dependencies.resolveTag = async () => "0".repeat(40); },
    "module metadata": (dependencies) => { dependencies.moduleInfo = async () => ({ Version: "v1.16.0" }); },
    "license bytes": (dependencies) => { dependencies.fingerprintUrl = async () => "0".repeat(64); },
    "go.mod": (dependencies) => { dependencies.readGoMod = async () => "module wrong.example/module\n"; },
    "go.sum": (dependencies) => { dependencies.readGoSum = async () => ""; },
  };
  for (const [name, mutate] of Object.entries(cases)) {
    await t.test(name, async () => {
      const dependencies = validDependencies();
      mutate(dependencies);
      await assert.rejects(auditAdapterLicense(validInventory(), dependencies), /rejected/);
    });
  }
});

function responseFrom(chunks, overrides = {}) {
  return {
    ok: true,
    status: 200,
    redirected: false,
    body: new ReadableStream({
      start(controller) {
        for (const chunk of chunks) controller.enqueue(Buffer.from(chunk));
        controller.close();
      },
    }),
    ...overrides,
  };
}

test("rejects redirects, timeouts, and oversized fetched artifacts", async (t) => {
  await t.test("redirect", async () => {
    await assert.rejects(fingerprintURL("https://example.invalid/license", {
      fetchImpl: async () => responseFrom(["license"], { redirected: true }),
    }), /rejected/);
  });
  await t.test("timeout", async () => {
    await assert.rejects(fingerprintURL("https://example.invalid/license", {
      timeoutMilliseconds: 5,
      fetchImpl: async (_url, options) => new Promise((_resolve, reject) => {
        options.signal.addEventListener("abort", () => reject(options.signal.reason), { once: true });
      }),
    }), /rejected/);
  });
  await t.test("oversized", async () => {
    await assert.rejects(fingerprintURL("https://example.invalid/license", {
      limit: 4,
      fetchImpl: async () => responseFrom(["12345"]),
    }), /rejected/);
  });
});

test("rejects malformed and duplicate-key inventory text", () => {
  assert.throws(() => parseLicenseInventory("{"), /rejected/);
  const duplicate = JSON.stringify(validInventory()).replace('"schema_version":1', '"schema_version":1,"schema_version":1');
  assert.throws(() => parseLicenseInventory(duplicate), /rejected/);
});

test("writes only fixed count output", async () => {
  let output = "";
  let error = "";
  const code = await runMain(
    { write: (value) => { output += value; } },
    { write: (value) => { error += value; } },
    {
      loadInventory: async () => validInventory(),
      audit: async () => ({ components: 1, artifacts: 3, prohibited: 0 }),
    },
  );
  assert.equal(code, 0);
  assert.equal(output, "OPA SDK license audit passed: components=1 artifacts=3 prohibited=0.\n");
  assert.equal(error, "");
});

test("tracked inventory is bounded", async () => {
  const bytes = await readFile(new URL("./adapter-license.json", import.meta.url));
  assert.ok(bytes.byteLength > 0 && bytes.byteLength <= 8_192);
});

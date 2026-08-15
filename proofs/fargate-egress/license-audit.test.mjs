import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { auditAdapterLicense, parseLicenseInventory } from "./license-audit.mjs";

const inventorySource = await readFile(new URL("./adapter-license.json", import.meta.url), "utf8");

test("immutable BusyBox image packaging and runtime licenses audit exactly", async () => {
  const inventory = parseLicenseInventory(inventorySource);
  const result = await auditAdapterLicense(inventory, {
    inspectImage: async () => ({
      repo_digest: `registry.k8s.io/e2e-test-images/busybox@${inventory.image.index_digest}`,
      architecture: "arm64",
      os: "linux",
      image_id: inventory.image.platforms["linux/arm64"].config_digest,
      labels: {
        commit_id: inventory.image.source_commit,
        git_url: `https://github.com/kubernetes/kubernetes/tree/${inventory.image.source_commit}/test/images/busybox`,
        image_version: inventory.image.version,
      },
    }),
    inspectIndex: async () => ({
      digest: inventory.image.index_digest,
      platforms: Object.entries(inventory.image.platforms).map(([platform, value]) => ({ platform, digest: value.manifest_digest })),
    }),
    fingerprintUrl: async (url) => {
      for (const component of inventory.components) {
        if (url === component.source_url) return component.source_sha256;
        if (url === component.license_url) return component.license_sha256;
      }
      throw new Error("unexpected URL");
    },
  });
  assert.deepEqual(result, { components: 2, artifacts: 7, prohibited: 0 });
});

test("audit rejects platform source license and image metadata drift", async () => {
  const inventory = parseLicenseInventory(inventorySource);
  const baseDependencies = {
    inspectImage: async () => ({
      repo_digest: `registry.k8s.io/e2e-test-images/busybox@${inventory.image.index_digest}`,
      architecture: "arm64", os: "linux", image_id: inventory.image.platforms["linux/arm64"].config_digest,
      labels: { commit_id: inventory.image.source_commit, git_url: `https://github.com/kubernetes/kubernetes/tree/${inventory.image.source_commit}/test/images/busybox`, image_version: inventory.image.version },
    }),
    inspectIndex: async () => ({ digest: inventory.image.index_digest, platforms: Object.entries(inventory.image.platforms).map(([platform, value]) => ({ platform, digest: value.manifest_digest })) }),
    fingerprintUrl: async (url) => inventory.components.flatMap((component) => [[component.source_url, component.source_sha256], [component.license_url, component.license_sha256]]).find(([candidate]) => candidate === url)?.[1],
  };
  await assert.rejects(auditAdapterLicense(inventory, { ...baseDependencies, inspectIndex: async () => ({ digest: inventory.image.index_digest, platforms: [] }) }));
  await assert.rejects(auditAdapterLicense(inventory, { ...baseDependencies, fingerprintUrl: async () => "0".repeat(64) }));
  await assert.rejects(auditAdapterLicense(inventory, { ...baseDependencies, inspectImage: async () => ({ ...(await baseDependencies.inspectImage()), labels: { commit_id: "0".repeat(40) } }) }));
});

test("inventory parser rejects duplicate keys and unknown licenses", () => {
  assert.throws(() => parseLicenseInventory('{"schema_version":1,"schema_version":1}'));
  assert.throws(() => parseLicenseInventory(inventorySource.replace('"GPL-2.0-only"', '"Proprietary"')));
});

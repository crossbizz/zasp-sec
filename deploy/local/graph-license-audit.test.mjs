import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  GRAPH_LICENSE_SUCCESS_LINE,
  auditGraphLicenses,
  parseGraphLicenseInventory,
  runMain,
} from "./graph-license-audit.mjs";

const inventoryPath = new URL("./graph-licenses.json", import.meta.url);

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

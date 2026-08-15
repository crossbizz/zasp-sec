import assert from "node:assert/strict";
import { test } from "node:test";

const api = await import("./license-audit.mjs").catch(() => undefined);

function requireExport(name) {
  assert.notEqual(api, undefined, "license-audit.mjs production module is absent");
  assert.equal(typeof api[name], "function", `${name} production API is absent`);
  return api[name];
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test("audits one exact Promptfoo image and both immutable source artifacts", async () => {
  const inventory = await requireExport("loadLicenseInventory")();
  const image = inventory.images[0];
  const requested = [];
  const result = await requireExport("auditAdapterLicense")(inventory, {
    inspectImage: async () => ({
      identifier: `sha256:${"a".repeat(64)}`,
      repo_digests: image.repo_digests,
      environment_sha256: image.environment_sha256,
      environment_count: image.environment_count,
      entrypoint: image.entrypoint,
      command: image.command,
      user: image.user,
      working_directory: image.working_directory,
      labels: image.labels,
    }),
    fingerprintUrl: async (url) => {
      requested.push(url);
      return inventory.components[0].artifacts.find((artifact) => artifact.url === url)?.sha256;
    },
  });
  assert.deepEqual(result, { images: 1, components: 1, artifacts: 2, prohibited: 0 });
  assert.equal(new Set(requested).size, 2);
  assert.equal(requested.every((url) => url.startsWith("https://raw.githubusercontent.com/promptfoo/promptfoo/")), true);
});

test("rejects license, source, package, image, and fingerprint drift", async () => {
  const exact = await requireExport("loadLicenseInventory")();
  const imageResult = () => ({
    identifier: `sha256:${"b".repeat(64)}`,
    repo_digests: exact.images[0].repo_digests,
    environment_sha256: exact.images[0].environment_sha256,
    environment_count: exact.images[0].environment_count,
    entrypoint: exact.images[0].entrypoint,
    command: exact.images[0].command,
    user: exact.images[0].user,
    working_directory: exact.images[0].working_directory,
    labels: exact.images[0].labels,
  });
  const cases = [
    (value) => { value.allowed_licenses = ["GPL-3.0-only"]; },
    (value) => { value.components[0].source_commit = "0".repeat(40); },
    (value) => { value.components[0].source_tree = "0".repeat(40); },
    (value) => { value.components[0].npm_integrity = "other"; },
    (value) => { value.images[0].labels.extra = "drift"; },
    (value) => { value.images[0].reference = "other"; },
  ];
  for (const mutate of cases) {
    const candidate = clone(exact);
    mutate(candidate);
    await assert.rejects(requireExport("auditAdapterLicense")(candidate, {
      inspectImage: async () => imageResult(),
      fingerprintUrl: async (url) => exact.components[0].artifacts.find((artifact) => artifact.url === url)?.sha256,
    }));
  }
  await assert.rejects(requireExport("auditAdapterLicense")(exact, {
    inspectImage: async () => imageResult(),
    fingerprintUrl: async () => "0".repeat(64),
  }));
});

test("uses one bounded Docker image tuple and rejects malformed output", () => {
  const reference = `example:1@sha256:${"c".repeat(64)}`;
  const arguments_ = requireExport("buildImageInspectArguments")(reference);
  assert.deepEqual(arguments_.slice(0, 3), ["image", "inspect", reference]);
  assert.equal(arguments_[3], "--format");
  assert.match(arguments_[4], /^\[\{\{json \.Id\}\},/);
  const parsed = requireExport("parseImageInspectResult")({
    status: 0,
    signal: null,
    stderr: "",
    overflow: false,
    timedOut: false,
    thrown: false,
    stdout: JSON.stringify([
      `sha256:${"d".repeat(64)}`,
      [`example@sha256:${"e".repeat(64)}`],
      ["PATH=/usr/bin"],
      ["entrypoint"],
      ["command"],
      "user",
      "/work",
      { license: "MIT" },
    ]) + "\n",
  });
  assert.equal(parsed.environment_count, 1);
  assert.equal(parsed.user, "user");
  assert.throws(() => requireExport("parseImageInspectResult")({
    status: 0,
    signal: null,
    stderr: "warning",
    stdout: "[]",
    overflow: false,
    timedOut: false,
    thrown: false,
  }));
});

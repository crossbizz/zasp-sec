import assert from "node:assert/strict";
import test from "node:test";

const api = await import("./license-audit.mjs").catch(() => undefined);

function requireExport(name) {
  assert.notEqual(api, undefined, "license-audit.mjs production module is absent");
  assert.equal(typeof api[name], "function", `${name} production API is absent`);
  return api[name];
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

test("audits the exact local images and every immutable tagged license fingerprint", async () => {
  const inventory = await requireExport("loadLicenseInventory")();
  assert.equal(inventory.images.every((image) =>
    image.environment === undefined && /^[a-f0-9]{64}$/.test(image.environment_sha256) &&
    Number.isInteger(image.environment_count) && image.environment_count > 0), true);
  const inspected = new Map(inventory.images.map((image) => [image.reference, {
    identifier: `sha256:${"a".repeat(64)}`,
    repo_digests: image.repo_digests,
    environment_sha256: image.environment_sha256,
    environment_count: image.environment_count,
    entrypoint: image.entrypoint,
    command: image.command,
    user: image.user,
    working_directory: image.working_directory,
    labels: image.labels,
  }]));
  const requested = [];
  const result = await requireExport("auditAdapterLicenses")(inventory, {
    inspectImage: async (reference) => inspected.get(reference),
    fingerprintUrl: async (url) => {
      requested.push(url);
      return inventory.components.flatMap((component) => component.artifacts)
        .find((artifact) => artifact.url === url)?.sha256;
    },
  });
  assert.deepEqual(result, { images: 2, components: 3, artifacts: 7, prohibited: 0 });
  assert.equal(new Set(requested).size, 7);
  assert.equal(requested.every((url) => url.startsWith("https://raw.githubusercontent.com/")), true);
});

test("fails closed on missing, prohibited, image-metadata, or source-fingerprint drift", async () => {
  const exact = await requireExport("loadLicenseInventory")();
  const inspection = (inventory) => new Map(inventory.images.map((image) => [image.reference, {
    identifier: `sha256:${"b".repeat(64)}`,
    repo_digests: image.repo_digests,
    environment_sha256: image.environment_sha256,
    environment_count: image.environment_count,
    entrypoint: image.entrypoint,
    command: image.command,
    user: image.user,
    working_directory: image.working_directory,
    labels: image.labels,
  }]));
  const cases = [
    (inventory) => { delete inventory.components[0].artifacts; },
    (inventory) => { inventory.components[0].license = "GPL-3.0-only"; },
    (inventory) => { inventory.images[0].labels.extra = "forbidden"; },
    (inventory) => { inventory.images[0].reference = inventory.images[1].reference; },
  ];
  for (const mutate of cases) {
    const inventory = clone(exact);
    const images = inspection(exact);
    mutate(inventory);
    await assert.rejects(requireExport("auditAdapterLicenses")(inventory, {
      inspectImage: async (reference) => images.get(reference),
      fingerprintUrl: async (url) => exact.components.flatMap((component) => component.artifacts)
        .find((artifact) => artifact.url === url)?.sha256,
    }));
  }

  await assert.rejects(requireExport("auditAdapterLicenses")(exact, {
    inspectImage: async (reference) => inspection(exact).get(reference),
    fingerprintUrl: async () => "0".repeat(64),
  }));
});

test("uses a Docker-supported bounded image-inspect template and parses its exact tuple", () => {
  const args = requireExport("buildImageInspectArguments")("example/image:1@sha256:" + "c".repeat(64));
  assert.deepEqual(args.slice(0, 3), ["image", "inspect", "example/image:1@sha256:" + "c".repeat(64)]);
  assert.equal(args[3], "--format");
  assert.equal(args[4].startsWith("[{{json .Id}},"), true);
  assert.equal(args[4].includes("list"), false);
  assert.equal(args[4].includes("{{json (index .Config \"Cmd\")}}"), true);
  assert.equal(args[4].includes("{{json (index .Config \"User\")}}"), true);

  const parsed = requireExport("parseImageInspectResult")({
    status: 0,
    signal: null,
    stderr: "",
    stdout: JSON.stringify([
      `sha256:${"d".repeat(64)}`,
      ["example/image@sha256:" + "e".repeat(64)],
      ["PATH=/usr/bin"],
      ["/entrypoint"],
      null,
      "user",
      "/work",
      { license: "Apache-2.0" },
    ]) + "\n",
  });
  assert.deepEqual(parsed, {
    identifier: `sha256:${"d".repeat(64)}`,
    repo_digests: ["example/image@sha256:" + "e".repeat(64)],
    environment_sha256: "2e6d1dda5a89b680605ba44b5517b2293437d6833ba5b505c6465c8c4849e10c",
    environment_count: 1,
    entrypoint: ["/entrypoint"],
    command: null,
    user: "user",
    working_directory: "/work",
    labels: { license: "Apache-2.0" },
  });
  assert.throws(() => requireExport("parseImageInspectResult")({
    status: 0, signal: null, stderr: "warning\n", stdout: "[]\n",
  }));
});

test("streams source fingerprints under one strict byte bound", async () => {
  const fingerprintUrl = requireExport("fingerprintUrl");
  const response = (chunks, declaredLength = null) => ({
    ok: true,
    headers: { get: (name) => name === "content-length" ? declaredLength : null },
    body: {
      getReader: () => {
        let index = 0;
        return {
          read: async () => index < chunks.length
            ? { done: false, value: Uint8Array.from(chunks[index++]) }
            : { done: true },
          cancel: async () => undefined,
        };
      },
    },
  });
  assert.equal(
    await fingerprintUrl("https://example.invalid/license", {
      fetchImpl: async (_url, options) => {
        assert.equal(options.headers["Accept-Encoding"], "identity");
        return response([[1, 2], [3]]);
      },
      limit: 3,
      timeoutMilliseconds: 100,
    }),
    "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
  );
  await assert.rejects(fingerprintUrl("https://example.invalid/oversized", {
    fetchImpl: async () => response([[1, 2], [3, 4]]), limit: 3, timeoutMilliseconds: 100,
  }));
  await assert.rejects(fingerprintUrl("https://example.invalid/declared", {
    fetchImpl: async () => response([[1]], "4"), limit: 3, timeoutMilliseconds: 100,
  }));
});

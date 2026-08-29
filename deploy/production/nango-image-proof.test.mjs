import assert from "node:assert/strict";
import { rm, stat } from "node:fs/promises";
import test from "node:test";

import * as proof from "./nango-image-proof.mjs";

const { nangoImage, runNangoImageProof } = proof;

test("TLS proof directory is traversable by the non-root container", async () => {
  assert.equal(typeof proof.createTLSProofDirectory, "function");
  const directory = await proof.createTLSProofDirectory();
  try {
    assert.equal((await stat(directory)).mode & 0o777, 0o755);
  } finally {
    await rm(directory, { force: true, recursive: true });
  }
});

test("pinned Nango image contains the migration entrypoint and preserves verify-full TLS", { timeout: 300_000 }, async () => {
  assert.deepEqual(await runNangoImageProof(), {
    image: nangoImage,
    migrationEntrypoint: "packages/server/dist/migrate.js",
    databaseTLS: "verify-full",
    oauthCallback: "product-bound",
    connectURL: "private-service",
    authEnabled: true,
    gracefulShutdown: true,
    readOnlyRoot: true,
    runtimeUser: "1000:1000",
    verified: true,
  });
});

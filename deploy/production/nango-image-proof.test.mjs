import assert from "node:assert/strict";
import test from "node:test";

import { nangoImage, runNangoImageProof } from "./nango-image-proof.mjs";

test("pinned Nango image contains the migration entrypoint and preserves verify-full TLS", { timeout: 300_000 }, async () => {
  assert.deepEqual(await runNangoImageProof(), {
    image: nangoImage,
    migrationEntrypoint: "packages/server/dist/migrate.js",
    databaseTLS: "verify-full",
    authEnabled: true,
    gracefulShutdown: true,
    readOnlyRoot: true,
    runtimeUser: "1000:1000",
    verified: true,
  });
});

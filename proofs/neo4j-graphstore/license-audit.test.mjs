import assert from "node:assert/strict";
import test from "node:test";

import { auditLicenses } from "./license-audit.mjs";

test("license audit binds the approved driver and proof-only Community server", async () => {
  const result = await auditLicenses();
  assert.deepEqual(result, { components: 2, approvedRuntime: 1, proofOnly: 1, prohibitedRuntime: 0 });
});

test("license audit rejects version, hash, scope, and approval drift", async () => {
  for (const mutate of [
    (value) => { value.components[0].version = "v6.2.1"; },
    (value) => { value.components[0].license_sha256 = "0".repeat(64); },
    (value) => { value.components[1].scope = "runtime"; },
    (value) => { value.components[1].product_approved = true; },
  ]) {
    await assert.rejects(() => auditLicenses({ mutate }));
  }
});

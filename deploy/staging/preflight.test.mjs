import assert from "node:assert/strict";
import test from "node:test";

import { requiredTools, runPreflight, validateReleaseInput } from "./preflight.mjs";

const digest = (name, character) => `${name}@sha256:${character.repeat(64)}`;
const input = { environment: "production", privateEndpointOnly: true, endpoint_public_access: false, attackLabSecurityGroupID: "sg-1234abcd", productImages: [digest("zasp/web", "a"), digest("zasp/api", "b"), digest("zasp/worker", "c"), digest("zasp/ingest", "d"), digest("zasp/gateway", "e")] };

test("release preflight validates private inputs and exact tool availability", () => {
  const calls = [];
  const value = runPreflight(["--input", "release.json"], { read: () => JSON.stringify(input), spawn: (tool, args, options) => { calls.push({ tool, args, options }); return { status: 0 }; } });
  assert.deepEqual(value, { environment: "production", privateEndpointOnly: true, images: 5 });
  assert.deepEqual(calls.map(({ tool }) => tool), requiredTools);
  assert.ok(calls.every(({ args, options }) => args[0] === "version" && options.timeout === 10_000 && Object.keys(options.env).join() === "PATH"));
});
test("release preflight rejects public access, mutable images, missing SG, and tool failure", () => {
  for (const invalid of [
    { ...input, environment: "staging" },
    { ...input, privateEndpointOnly: false },
    { ...input, endpoint_public_access: true },
    { ...input, productImages: [...input.productImages.slice(0, 4), "zasp/gateway:latest"] },
    { ...input, attackLabSecurityGroupID: "" },
  ]) assert.throws(() => validateReleaseInput(invalid), /rejected/);
  assert.throws(() => runPreflight(["--input", "release.json"], { read: () => JSON.stringify(input), spawn: () => ({ status: 1 }) }), /rejected/);
});

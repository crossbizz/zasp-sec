import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import test from "node:test";
import { promisify } from "node:util";

const exec = promisify(execFile);
test("SIGTERM after allocation reaps every exact-owned container and network", { skip: process.env.ZASP_ATTACK_LAB_EGRESS_DOCKER !== "true", timeout: 180_000 }, async () => {
  let failure;
  try { await exec(process.execPath, [new URL("./run.mjs", import.meta.url).pathname, "--interrupt-after-allocation"], { timeout: 150_000 }); }
  catch (error) { failure = error; }
  assert.equal(failure?.code, 1);
  const owner = failure.stderr.match(/Interrupting owned fixture: (zasp-m521-[a-f0-9]{32})/)?.[1];
  assert.ok(owner, "test must reach actual Docker allocation before SIGTERM");
  assert.doesNotMatch(failure.stderr, /cleanup could not be verified/);
  for (const kind of ["container", "network"]) {
    const result = await exec("docker", [kind, "ls", ...(kind === "container" ? ["--all"] : []), "--quiet", "--filter", `label=zasp.fixture.owner=${owner}`], { timeout: 10_000 });
    assert.equal(result.stdout.trim(), "");
  }
});

import assert from "node:assert/strict";
import test from "node:test";
import { preparePinnedRuntimeImage } from "./pinned-runtime-image.mjs";
import { createRedTeamRuntimeProof } from "./red-team-runtime-proof.mjs";
import { createRuntimePipelineDependencies } from "./runtime-pipeline-dependencies.mjs";

for (const [name, factory, inspections] of [
  ["engine", createRedTeamRuntimeProof, 1],
  ["pipeline", createRuntimePipelineDependencies, 2],
]) {
  test(`${name} close during inspection prevents a later download`, async () => {
    let release;
    const pending = new Promise(resolve => { release = resolve; });
    const calls = [];
    const owner = factory(async (_executable, args) => {
      calls.push(args);
      assert.equal(args[0], "image");
      await pending;
      return { status: 1, stdout: "", stderr: `No such image: ${args[4]}` };
    });
    const rejected = assert.rejects(owner.prepare(), /interrupted/);
    await owner.close();
    release();
    await rejected;
    assert.equal(calls.length, inspections);
  });
}

const image = `example.invalid/runtime@sha256:${"a".repeat(64)}`;
const inspect = ["image", "inspect", "--format", "{{.Architecture}}", image];

function commands(results) {
  const calls = [];
  return {
    calls,
    command: async (executable, args, options) => {
      assert.equal(executable, "docker");
      assert.equal(options.reject, false);
      assert.ok(Number.isSafeInteger(options.timeout) && options.timeout > 0);
      calls.push(args);
      assert.ok(results.length, "unexpected external command");
      return results.shift();
    },
  };
}

for (const architecture of ["arm64", "amd64"]) {
  test(`cached ${architecture} image preparation never contacts a registry`, async () => {
    const boundary = commands([{ status: 0, stdout: `${architecture}\n`, stderr: "" }]);
    assert.equal(await preparePinnedRuntimeImage(boundary.command, image), architecture);
    assert.deepEqual(boundary.calls, [inspect]);
  });
}

test("confirmed missing pinned image is pulled once and then inspected", async () => {
  const boundary = commands([
    { status: 1, stdout: "", stderr: `Error response from daemon: No such image: ${image}\n` },
    { status: 0, stdout: "downloaded", stderr: "" },
    { status: 0, stdout: "arm64\n", stderr: "" },
  ]);
  assert.equal(await preparePinnedRuntimeImage(boundary.command, image), "arm64");
  assert.deepEqual(boundary.calls, [inspect, ["pull", image], inspect]);
});

for (const failure of ["Cannot connect to the Docker daemon", "permission denied", "No such image: another-image", ""]) {
  test(`inspection failure does not become download permission: ${failure || "empty response"}`, async () => {
    const boundary = commands([{ status: 1, stdout: "", stderr: failure }]);
    await assert.rejects(preparePinnedRuntimeImage(boundary.command, image), /inspection failed/);
    assert.deepEqual(boundary.calls, [inspect]);
  });
}

test("an unsupported cached image is rejected without pulling", async () => {
  const boundary = commands([{ status: 0, stdout: "s390x\n", stderr: "" }]);
  await assert.rejects(preparePinnedRuntimeImage(boundary.command, image), /architecture rejected/);
  assert.deepEqual(boundary.calls, [inspect]);
});

test("failed pull cannot be reported as successful preparation", async () => {
  const boundary = commands([
    { status: 1, stdout: "", stderr: `No such image: ${image}` },
    { status: 1, stdout: "", stderr: "registry unavailable" },
  ]);
  await assert.rejects(preparePinnedRuntimeImage(boundary.command, image), /pull failed/);
  assert.deepEqual(boundary.calls, [inspect, ["pull", image]]);
});

test("a successful pull still requires valid local image inspection", async () => {
  const boundary = commands([
    { status: 1, stdout: "", stderr: `No such image: ${image}` },
    { status: 0, stdout: "downloaded", stderr: "" },
    { status: 1, stdout: "", stderr: "daemon unavailable" },
  ]);
  await assert.rejects(preparePinnedRuntimeImage(boundary.command, image), /inspection failed/);
  assert.deepEqual(boundary.calls, [inspect, ["pull", image], inspect]);
});

test("mutable or malformed references are refused before external commands", async () => {
  const boundary = commands([]);
  for (const reference of ["runtime:latest", `${image}\n`, "", null, image.replace("@sha256:", "@sha512:"),
    `example.invalid//runtime@sha256:${"a".repeat(64)}`,
    `https://example.invalid/runtime@sha256:${"a".repeat(64)}`,
    `runtime:@sha256:${"a".repeat(64)}`,
  ]) {
    await assert.rejects(preparePinnedRuntimeImage(boundary.command, reference), /pinned image rejected/);
  }
  assert.deepEqual(boundary.calls, []);
});

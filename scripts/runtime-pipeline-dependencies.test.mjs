import assert from "node:assert/strict";
import test from "node:test";
import { buildRuntimeContainerArguments, createRuntimePipelineDependencies } from "./runtime-pipeline-dependencies.mjs";

const marker = "a".repeat(16);
const containerID = "b".repeat(64);

test("runtime proof uses pinned loopback-only disposable dependencies", () => {
  for (const kind of ["aws", "search"]) {
    const args = buildRuntimeContainerArguments(kind, marker);
    assert.deepEqual(args.slice(0, 3), ["run", "--detach", "--rm"]);
    assert.ok(args.includes(`zasp-runtime-pipeline-${kind}-${marker}`));
    assert.ok(args.includes(`zasp.marker=${marker}`));
    assert.ok(args.includes("zasp.proof=runtime-pipeline"));
    assert.ok(args.includes(kind === "aws" ? "127.0.0.1::4566" : "127.0.0.1::9200"));
    assert.match(args.at(-1), /@sha256:[a-f0-9]{64}$/);
    assert.equal(args.some((arg) => /docker\.sock|--privileged|--network=host/.test(arg)), false);
  }
  for (const kind of ["", "other"]) assert.throws(() => buildRuntimeContainerArguments(kind, marker));
  for (const bad of ["../escape", "A".repeat(16), "a".repeat(17)]) assert.throws(() => buildRuntimeContainerArguments("aws", bad));
});

test("cleanup is idempotent and verifies exact ownership before deletion", async () => {
  const calls = [];
  const command = async (_, args) => {
    calls.push(args);
    if (args[0] === "run") return { status: 0, stdout: containerID };
    if (args[0] === "inspect") return { status: 0, stdout: JSON.stringify([{ Id: containerID, Name: `/zasp-runtime-pipeline-aws-${marker}`, Config: { Labels: { "zasp.marker": marker, "zasp.proof": "runtime-pipeline" } }, NetworkSettings: { Ports: { "4566/tcp": [{ HostIp: "127.0.0.1", HostPort: "45678" }] } } }]) };
    return { status: 0, stdout: "" };
  };
  const dependencies = createRuntimePipelineDependencies(command, { marker });
  assert.equal(await dependencies.start("aws"), "http://127.0.0.1:45678");
  await dependencies.close();
  await dependencies.close();
  assert.deepEqual(calls.filter((args) => args[0] === "rm"), [["rm", "--force", containerID]]);
  await assert.rejects(() => dependencies.start("search"));
});

test("cleanup never deletes a container with mismatched ownership", async () => {
  const calls = [];
  const dependencies = createRuntimePipelineDependencies(async (_, args) => {
    calls.push(args);
    if (args[0] === "run") return { status: 0, stdout: containerID };
    return { status: 0, stdout: JSON.stringify([{ Id: containerID, Name: "/foreign", Config: { Labels: {} } }]) };
  }, { marker });
  await assert.rejects(() => dependencies.start("aws"));
  await assert.rejects(() => dependencies.close());
  assert.equal(calls.some((args) => args[0] === "rm"), false);
});

test("cold image preparation cannot hold container cleanup behind a registry request", async () => {
  let finishPull;
  const pulling = new Promise((resolve) => { finishPull = resolve; });
  const calls = [];
  const dependencies = createRuntimePipelineDependencies(async (_, args) => {
    calls.push(args);
    assert.equal(args[0], "pull");
    await pulling;
    return { status: 0, stdout: "" };
  }, { marker });
  const preparing = dependencies.prepare();
  await dependencies.close();
  assert.equal(calls.length, 2);
  finishPull();
  await assert.rejects(preparing, /interrupted/);
});

test("interrupted in-flight starts are bounded and delete only the verified owned ID", async () => {
  let finishStart;
  const starting = new Promise((resolve) => { finishStart = resolve; });
  const calls = [];
  const dependencies = createRuntimePipelineDependencies(async (_, args, options) => {
    calls.push(args);
    if (args[0] === "run") {
      assert.equal(options.timeout, 10_000);
      assert.ok(args.includes("--pull") && args.includes("never"));
      return starting;
    }
    assert.ok(options.timeout <= 3_000);
    if (args[0] === "inspect") return { status: 0, stdout: JSON.stringify([{ Id: containerID, Name: `/zasp-runtime-pipeline-aws-${marker}`, Config: { Labels: { "zasp.marker": marker, "zasp.proof": "runtime-pipeline" } }, NetworkSettings: { Ports: { "4566/tcp": [{ HostIp: "127.0.0.1", HostPort: "45678" }] } } }]) };
    return { status: 0, stdout: "" };
  }, { marker });
  const rejected = assert.rejects(dependencies.start("aws"), /binding rejected/);
  const cleanup = dependencies.close();
  finishStart({ status: 0, stdout: containerID });
  await Promise.all([rejected, cleanup]);
  assert.deepEqual(calls.filter((args) => args[0] === "rm"), [["rm", "--force", containerID]]);
});

test("public container bindings fail closed but owned cleanup still runs", async () => {
  const calls = [];
  const dependencies = createRuntimePipelineDependencies(async (_, args) => {
    calls.push(args);
    if (args[0] === "run") return { status: 0, stdout: containerID };
    if (args[0] === "inspect") return { status: 0, stdout: JSON.stringify([{ Id: containerID, Name: `/zasp-runtime-pipeline-aws-${marker}`, Config: { Labels: { "zasp.marker": marker, "zasp.proof": "runtime-pipeline" } }, NetworkSettings: { Ports: { "4566/tcp": [{ HostIp: "0.0.0.0", HostPort: "45678" }] } } }]) };
    return { status: 0, stdout: "" };
  }, { marker });
  await assert.rejects(dependencies.start("aws"), /binding rejected/);
  await dependencies.close();
  assert.deepEqual(calls.filter((args) => args[0] === "rm"), [["rm", "--force", containerID]]);
});

test("cleanup retries one transient inspection failure before verified deletion", async () => {
  let inspections = 0;
  const removals = [];
  const dependencies = createRuntimePipelineDependencies(async (_, args, options) => {
    if (args[0] === "run") return { status: 0, stdout: containerID };
    if (args[0] === "inspect") {
      assert.equal(options.timeout, 3_000);
      inspections++;
      if (inspections === 2) return { status: null, stdout: "", signal: "SIGKILL" };
      return { status: 0, stdout: JSON.stringify([{ Id: containerID, Name: `/zasp-runtime-pipeline-aws-${marker}`, Config: { Labels: { "zasp.marker": marker, "zasp.proof": "runtime-pipeline" } }, NetworkSettings: { Ports: { "4566/tcp": [{ HostIp: "127.0.0.1", HostPort: "45678" }] } } }]) };
    }
    removals.push(args);
    return { status: 0, stdout: "" };
  }, { marker });
  await dependencies.start("aws");
  await dependencies.close();
  assert.equal(inspections, 3);
  assert.deepEqual(removals, [["rm", "--force", containerID]]);
});

test("cleanup bounds persistent inspection failure and never deletes unverified identity", async () => {
  let inspections = 0;
  let removeCalls = 0;
  const dependencies = createRuntimePipelineDependencies(async (_, args) => {
    if (args[0] === "run") return { status: 0, stdout: containerID };
    if (args[0] === "inspect") {
      inspections++;
      return { status: 1, stdout: "" };
    }
    removeCalls++;
    return { status: 0, stdout: "" };
  }, { marker });
  await assert.rejects(dependencies.start("aws"), /inspection failed/);
  await assert.rejects(dependencies.close(), /cleanup incomplete/);
  assert.equal(inspections, 3, "one startup attempt and two bounded cleanup attempts");
  assert.equal(removeCalls, 0);
});

test("a successful inspection retry cannot substitute foreign or malformed ownership", async () => {
  for (const retryBody of ["invalid JSON", JSON.stringify([{ Id: containerID, Name: "/foreign", Config: { Labels: {} } }])]) {
    let inspections = 0;
    let removeCalls = 0;
    const dependencies = createRuntimePipelineDependencies(async (_, args) => {
      if (args[0] === "run") return { status: 0, stdout: containerID };
      if (args[0] === "inspect") {
        inspections++;
        if (inspections === 1) return { status: 0, stdout: JSON.stringify([{ Id: containerID, Name: `/zasp-runtime-pipeline-aws-${marker}`, Config: { Labels: { "zasp.marker": marker, "zasp.proof": "runtime-pipeline" } }, NetworkSettings: { Ports: { "4566/tcp": [{ HostIp: "127.0.0.1", HostPort: "45678" }] } } }]) };
        return inspections === 2 ? { status: 1, stdout: "" } : { status: 0, stdout: retryBody };
      }
      removeCalls++;
      return { status: 0, stdout: "" };
    }, { marker });
    await dependencies.start("aws");
    await assert.rejects(dependencies.close(), /cleanup incomplete/);
    assert.equal(inspections, 3);
    assert.equal(removeCalls, 0);
  }
});

import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { buildDaemonReplayArguments, validateDaemonReplayContainer, validateDaemonReplayResult, closeDaemonReplayContainer, cleanupDaemonReplayResources, daemonReplayCommandBudget } from "./sensor-daemon-replay.mjs";

const owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const id = "a".repeat(64);
const config = { owner, directory: "/tmp/zasp-daemon-proof-fixture" };

test("CI runs actual daemon proof and ownership regressions within a bounded step", async () => {
  const workflow = await readFile(new URL("../.github/workflows/runnable-ui.yml", import.meta.url), "utf8");
  assert.match(workflow, /- name: Verify actual daemon lost-success replay\n\s+timeout-minutes: 15\n\s+run: \|\n\s+node --test scripts\/sensor-daemon-replay.test.mjs\n\s+node scripts\/sensor-daemon-replay.mjs/);
});
const fixture = () => ({
  Id: id, Name: `/zasp-daemon-replay-${owner}`,
  Config: { User: "0:65532", Labels: { "zasp.proof": "daemon-replay", "zasp.owner": owner } },
  HostConfig: {
    NetworkMode: "none", ReadonlyRootfs: true, Privileged: false, CapDrop: ["ALL"],
    CapAdd: ["CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "NET_BIND_SERVICE", "SETGID", "SETUID"],
    SecurityOpt: ["no-new-privileges"], Memory: 1073741824, MemorySwap: 1073741824, PidsLimit: 128,
    NanoCpus: 2000000000, ShmSize: 67108864, PortBindings: {}, IpcMode: "private", PidMode: "",
    Tmpfs: { "/tmp": "rw,nosuid,nodev,size=536870912,mode=1777", "/var/lib/postgresql": "rw,nosuid,nodev,size=16777216", "/var/run/secrets/kubernetes.io/serviceaccount": "rw,nosuid,nodev,size=65536,mode=0755" },
  },
  Mounts: ["apiserver.test", "sensor-agent.test", "sensor-agent"].map(name => ({ Type: "bind", Source: `${config.directory}/${name}`, Destination: `/proof/${name}`, RW: false })),
  State: { Status: "exited", Running: false, Pid: 0, ExitCode: 0, OOMKilled: false, Error: "" },
});

test("daemon proof arguments reject widened mounts and require all isolation controls", () => {
  const args = buildDaemonReplayArguments(config);
  assert.equal(args[0], "create");
  assert.ok(args.includes("--network") && args.includes("none"));
  assert.ok(args.includes("--shm-size") && args.includes("64m"));
  assert.equal(args.filter(value => value === "--mount").length, 3);
  assert.ok(args.includes("ZASP_TEST_DAEMON_REPLAY=1"));
  for (const directory of ["/", "/tmp", "relative", "/tmp/bad,path", "/tmp/x\n"]) {
    assert.throws(() => buildDaemonReplayArguments({ ...config, directory }));
  }
  assert.throws(() => buildDaemonReplayArguments({ ...config, owner: "ambient" }));
});

test("daemon proof inspects exact identity, mounts, isolation and exit", () => {
  validateDaemonReplayContainer(fixture(), config);
  validateDaemonReplayResult(fixture(), "--- PASS: TestRuntimeAcceptanceActualDaemonLostSuccessReplay (3.00s)\nPASS\n");
  const mutations = [
    v => { v.Config.Labels["zasp.owner"] = "other"; },
    v => { v.HostConfig.NetworkMode = "host"; },
    v => { v.HostConfig.CapAdd.push("SYS_ADMIN"); },
    v => { v.HostConfig.ReadonlyRootfs = false; },
    v => { v.HostConfig.Tmpfs["/tmp"] = "rw"; },
    v => { v.Mounts[0].RW = true; },
    v => { v.Mounts[0].Source = "/Users/shared"; },
    v => { v.HostConfig.PidMode = "host"; },
  ];
  for (const mutate of mutations) { const value = fixture(); mutate(value); assert.throws(() => validateDaemonReplayContainer(value, config)); }
  for (const state of [{ OOMKilled: true }, { Running: true }, { ExitCode: 1 }, { Pid: 14 }]) {
    const value = fixture(); Object.assign(value.State, state); assert.throws(() => validateDaemonReplayResult(value, "PASS\n"));
  }
  assert.throws(() => validateDaemonReplayResult(fixture(), "--- SKIP: TestRuntimeAcceptanceActualDaemonLostSuccessReplay\nPASS\n"));
});

test("cleanup only removes verified stopped owned container on success", async () => {
  const calls = []; let removed = false;
  const command = async args => {
    calls.push(args);
    if (args[0] === "inspect") return removed ? { status: 1, stdout: "", stderr: "Error: No such object: " + id } : { status: 0, stdout: JSON.stringify([fixture()]) };
    assert.deepEqual(args, ["rm", id]); removed = true; return { status: 0, stdout: id };
  };
  await closeDaemonReplayContainer(command, config, true);
  assert.equal(calls.filter(args => args[0] === "rm").length, 1);
});

test("failed proof preserves stopped container and rejects foreign ownership", async () => {
  const calls = [];
  await closeDaemonReplayContainer(async args => { calls.push(args); return { status: 0, stdout: JSON.stringify([fixture()]) }; }, config, false);
  assert.deepEqual(calls.map(args => args[0]), ["inspect"]);
  const foreign = fixture(); foreign.Config.Labels["zasp.owner"] = "foreign";
  await assert.rejects(closeDaemonReplayContainer(async () => ({ status: 0, stdout: JSON.stringify([foreign]) }), config, true));
});

test("lost create response still stops exact owned container before preserving it", async () => {
  const calls = []; const value = fixture(); Object.assign(value.State, { Running: true, Status: "running", Pid: 111 });
  await closeDaemonReplayContainer(async args => {
    calls.push(args);
    if (args[0] === "stop") { Object.assign(value.State, { Running: false, Status: "exited", Pid: 0 }); return { status: 0 }; }
    return { status: 0, stdout: JSON.stringify([value]) };
  }, config, false);
  assert.deepEqual(calls.map(args => args[0]), ["inspect", "stop", "inspect"]);
  assert.deepEqual(calls[1], ["stop", "--time", "10", id]);
});

test("failed command join still reconciles container and forbids root deletion", async () => {
  const calls = [];
  await assert.rejects(cleanupDaemonReplayResources({
    commands: [{ stop: async () => { calls.push("join-failed"); throw new Error("unjoined"); } }, { stop: async () => { calls.push("joined"); } }],
    successful: true,
    container: async successful => { calls.push(`container:${successful}`); },
    removeRoot: async () => { calls.push("remove-root"); },
  }), AggregateError);
  assert.deepEqual(calls, ["join-failed", "joined", "container:false"]);
});

test("failed container cleanup preserves root and successful cleanup removes it last", async () => {
  for (const fail of [false, true]) {
    const calls = [];
    const cleanup = cleanupDaemonReplayResources({ commands: [{ stop: async () => { calls.push("joined"); } }], successful: true,
      container: async () => { calls.push("container"); if (fail) throw new Error("cannot stop"); },
      removeRoot: async () => { calls.push("root"); },
    });
    if (fail) await assert.rejects(cleanup, AggregateError); else await cleanup;
    assert.deepEqual(calls, fail ? ["joined", "container"] : ["joined", "container", "root"]);
  }
});

test("overall execution budget leaves three minutes before CI hard timeout", () => {
  assert.equal(daemonReplayCommandBudget(300_000, 0), 300_000);
  assert.equal(daemonReplayCommandBudget(300_000, 710_000), 10_000);
  assert.throws(() => daemonReplayCommandBudget(300_000, 720_000));
});

import assert from "node:assert/strict";
import test from "node:test";
import { chmod, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const ownedBrowserPostgres = await import("./owned-browser-postgres.mjs").catch(error => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const image = "postgres@sha256:80630f83606d8db77d30b3851b16a9f78be2d0d4dda6f7b82a1fdca5ebe3acba";
const id = "a".repeat(64);
const ok = (stdout = "") => ({ status: 0, signal: null, stdout, stderr: "" });
const failed = (stderr = "failure") => ({ status: 1, signal: null, stdout: "", stderr });

// Removing ownership checks, bounded joins, or the cancellation gate breaks
// these tests. Only the external process boundary is replaced.
function fixture(options = {}, override = () => undefined) {
  assert.equal(typeof ownedBrowserPostgres.createOwnedBrowserPostgres, "function", "owned PostgreSQL lifecycle must exist");
  const calls = [], stopped = [];
  let name, label, exists = false, running = false;
  const spawnCommand = (executable, args, commandOptions) => {
    calls.push({ executable, args, options: commandOptions });
    const result = override(args, { calls, setRunning: value => { running = value; } });
    let output;
    switch (args[0]) {
      case "create":
        name = args[args.indexOf("--name") + 1]; label = args[args.indexOf("--label") + 1]; exists = true; output = ok(id); break;
      case "start": running = true; output = ok(id); break;
      case "inspect":
        output = exists ? ok(JSON.stringify([{ Id: id, Name: `/${name}`, Config: { Image: image, Labels: { [label.split("=")[0]]: label.split("=")[1] } }, State: { Running: running, ExitCode: 0 } }])) : failed("No such object"); break;
      case "exec": output = ok(); break;
      case "stop": running = false; output = ok(id); break;
      case "rm": exists = false; output = ok(id); break;
      case "container": output = ok(exists ? `${id}\n` : ""); break;
      default: throw new Error(`unexpected command: ${args}`);
    }
    if (result?.completed) return { ...result, stop: async () => { stopped.push(args); await result.stop(); } };
    return { completed: Promise.resolve(result ?? output), stop: async () => { stopped.push(args); } };
  };
  const owner = ownedBrowserPostgres.createOwnedBrowserPostgres({ port: 54321, commandTimeoutMs: 30, readinessTimeoutMs: 40, pollMs: 1, spawnCommand, ...options });
  return { owner, calls, stopped };
}

test("starts only pinned loopback ephemeral PostgreSQL and joins its exact container", async () => {
  const { owner, calls } = fixture({ trackFunctions: true });
  await owner.start();
  await owner.assertRunning();
  assert.equal(owner.containerID, id);
  const args = calls[0].args;
  assert.deepEqual(args, ["create", "--pull=never", "--name", args[3], "--label", args[5], "--user", "postgres", "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777", "--tmpfs", "/var/lib/postgresql:rw,nosuid,nodev,mode=1777", "--tmpfs", "/var/run/postgresql:rw,nosuid,nodev,mode=1777", "--publish", "127.0.0.1:54321:5432", "--env", "POSTGRES_USER=zasp_e2e", "--env", "POSTGRES_DB=postgres", "--env", "POSTGRES_HOST_AUTH_METHOD=trust", "--env", "PGDATA=/tmp/pgdata", "--env", "POSTGRES_INITDB_ARGS=--no-locale --encoding=UTF8", image, "postgres", "-c", "track_functions=pl"]);
  assert.match(args[3], /^zasp-browser-postgres-[a-f0-9]{32}$/);
  assert.equal(args[5], `zasp.browser-postgres.owner=${args[3]}`);
  assert.ok(calls.every(call => call.executable === "docker"));
  assert.deepEqual(calls.find(call => call.args[0] === "exec").args, ["exec", id, "pg_isready", "-h", "127.0.0.1", "-U", "zasp_e2e", "-d", "postgres"]);
  await owner.stop();
  assert.deepEqual(calls.slice(-3).map(call => call.args), [["stop", "--time", "2", id], ["rm", "--force", "--volumes", id], ["container", "ls", "--all", "--no-trunc", "--filter", `id=${id}`, "--format", "{{.ID}}"]]);
});

test("rejects invalid ports before dispatch", () => {
  for (const port of [0, -1, 65536, 1.5, "5432", NaN]) assert.throws(() => fixture({ port }), /port/);
});

test("optional discovery helper is one exact readonly regular executable mount", async () => {
  const directory=await mkdtemp(path.join(os.tmpdir(),"zasp-owned-helper-test-"));
  const binary=path.join(directory,"collector.test");
  try {
    await writeFile(binary,"owned fixture bytes",{mode:0o755});await chmod(binary,0o755);
    const {owner,calls}=fixture({discoveryCollectorBinary:binary});await owner.start();await owner.stop();
    const args=calls[0].args;
    assert.deepEqual(args.filter((_,index)=>args[index-1]==="--mount"),[`type=bind,src=${binary},dst=/zasp-automatic-discovery-collector.test,readonly`]);
    assert.equal(args.includes("--read-only"),true);
    assert.equal(args.includes("/tmp:rw,nosuid,nodev,mode=1777"),true);
    const omitted=fixture();await omitted.owner.start();await omitted.owner.stop();
    assert.equal(omitted.calls[0].args.includes("--mount"),false);
    for(const invalid of [directory,path.join(directory,"missing"),`${binary},rw`,`${directory}/../collector.test`,"relative.test","/",null])assert.throws(()=>fixture({discoveryCollectorBinary:invalid}),/collector/);
    const link=path.join(directory,"symlink.test");await symlink(binary,link);assert.throws(()=>fixture({discoveryCollectorBinary:link}),/collector/);
    for(const mode of [0o644,0o700,0o777]){await chmod(binary,mode);assert.throws(()=>fixture({discoveryCollectorBinary:binary}),/collector/);}
  }finally{await rm(directory,{recursive:true,force:true});}
});

test("isolated browser PostgreSQL has no published port and joins its raw-wire bridge", async () => {
  const events = [];
  const bridgeFactory = options => {
    assert.deepEqual(options, { containerID: id, port: 54321 });
    return { start: async () => events.push("start"), stop: async () => events.push("stop") };
  };
  const { owner, calls } = fixture({ isolatedRelay: "/private/tmp/owned-relay", bridgeFactory });
  await owner.start();
  const args = calls[0].args;
  assert.equal(args.includes("--publish"), false);
  assert.equal(args[args.indexOf("--network") + 1], "none");
  assert.ok(args.includes("type=bind,src=/private/tmp/owned-relay,dst=/zasp-postgres-relay,readonly"));
  assert.deepEqual(events, ["start"]);
  await owner.stop();
  assert.deepEqual(events, ["start", "stop"]);
});

test("initializes the same C UTF8 database as the pinned migration reference fixture", async () => {
  const { owner, calls } = fixture();
  await owner.start();
  await owner.stop();
  assert.ok(calls[0].args.includes("POSTGRES_INITDB_ARGS=--no-locale --encoding=UTF8"));
});

test("default startup leaves function instrumentation off", async () => {
  const { owner, calls } = fixture(); await owner.start(); await owner.stop();
  assert.equal(calls[0].args.includes("track_functions=pl"), false);
});

test("readiness failure still removes the created container", async () => {
  const { owner, calls } = fixture({}, args => args[0] === "exec" ? failed("not ready") : undefined);
  await assert.rejects(owner.start(), /ready/);
  assert.ok(calls.some(call => call.args[0] === "rm" && call.args.at(-1) === id));
  await owner.stop();
});

test("early server exit fails readiness even if the CLI already exited successfully", async () => {
  const { owner, calls } = fixture({}, (args, state) => { if (args[0] === "inspect") state.setRunning(false); });
  await assert.rejects(owner.start(), /not running/);
  assert.equal(calls.some(call => call.args[0] === "exec"), false);
  assert.ok(calls.some(call => call.args[0] === "rm"));
});

test("failed start removes the exact created resource", async () => {
  const { owner, calls } = fixture({}, args => args[0] === "start" ? failed("start rejected") : undefined);
  await assert.rejects(owner.start(), /start rejected/);
  assert.ok(calls.some(call => call.args[0] === "rm" && call.args.at(-1) === id));
});

test("lost create response recovers only the invocation name and matching ownership label", async () => {
  const { owner, calls } = fixture({}, args => args[0] === "create" ? failed("lost response") : undefined);
  await assert.rejects(owner.start(), /lost response/);
  assert.deepEqual(calls[1].args, ["inspect", calls[0].args[3]]);
  assert.ok(calls.some(call => call.args[0] === "rm" && call.args.at(-1) === id));
});

test("ambiguous create cannot remove a container without matching ownership", async () => {
  const { owner, calls } = fixture({}, args => args[0] === "create" ? failed("lost response") : args[0] === "inspect" ? ok(JSON.stringify([{ Id: id, Name: "/foreign", Config: { Image: image, Labels: {} }, State: { Running: true } }])) : undefined);
  await assert.rejects(owner.start(), /cleanup/);
  assert.equal(calls.some(call => ["stop", "rm"].includes(call.args[0])), false);
});

test("concurrent and repeated stop perform one exact cleanup", async () => {
  const { owner, calls } = fixture(); await owner.start();
  const first = owner.stop(); assert.equal(owner.stop(), first); await first; await owner.stop();
  assert.equal(calls.filter(call => call.args[0] === "rm").length, 1);
  await assert.rejects(owner.start(), /stopped/);
});

test("cancellation joins an in-flight create then recovers and removes its resource", async () => {
  let release;
  const { owner, calls, stopped } = fixture({}, args => args[0] === "create" ? { completed: new Promise(resolve => { release = resolve; }), stop: async () => release(failed("cancelled")) } : undefined);
  const starting = owner.start(); const rejection = assert.rejects(starting, /cancelled|stopped/);
  await owner.stop(); await rejection;
  assert.equal(stopped.length, 1);
  assert.equal(calls.some(call => call.args[0] === "start"), false);
  assert.ok(calls.some(call => call.args[0] === "rm"));
});

test("hung commands are bounded and joined before cleanup", async () => {
  let release;
  const { owner, stopped, calls } = fixture({}, args => args[0] === "start" ? { completed: new Promise(resolve => { release = resolve; }), stop: async () => release(failed("stopped")) } : undefined);
  await assert.rejects(owner.start(), /deadline/);
  assert.equal(stopped.length, 1);
  assert.ok(calls.some(call => call.args[0] === "rm"));
});

test("cleanup failure stays rejected even when repeated and absence checks still run", async () => {
  const { owner, calls } = fixture({}, args => args[0] === "rm" ? failed("remove denied") : undefined);
  await owner.start(); await assert.rejects(owner.stop(), /cleanup/); await assert.rejects(owner.stop(), /cleanup/);
  assert.equal(calls.filter(call => call.args[0] === "rm").length, 1);
  assert.equal(calls.at(-1).args[0], "container");
});

test("successful CLI removal without observed container absence fails the join", async () => {
  const { owner } = fixture({}, args => args[0] === "container" ? ok(id) : undefined);
  await owner.start(); await assert.rejects(owner.stop(), /cleanup/);
});

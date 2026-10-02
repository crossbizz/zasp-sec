import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { EventEmitter } from "node:events";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PassThrough } from "node:stream";
import test from "node:test";
import { parentGraceMilliseconds, runBroker } from "./audit-export-container.mjs";
import { LOCALSTACK_IMAGE } from "./run.mjs";

const imageID = `sha256:${"b".repeat(64)}`;
const containerID = "a".repeat(64);
const schema = "audit-export-localstack-fixture-v1";
const self = fileURLToPath(import.meta.url);
const inspectFormat = '{{.Id}}|{{.Name}}|{{.Image}}|{{.Config.Image}}|{{index .Config.Labels "zasp.proof"}}|{{index .Config.Labels "zasp.marker"}}';

// Only Docker is substituted. Identity checks, readiness HTTP, file publication,
// child lifetime and the broker's cleanup are the actual implementation.
function declaredDocker(stateFile) {
  return (executable, args, options) => {
    const state = JSON.parse(readFileSync(stateFile, "utf8"));
    assert.equal(executable, "docker");
    assert.deepEqual(Object.keys(options.env), ["PATH"]);
    assert.equal(options.killSignal, "SIGKILL");
    assert.ok(options.timeout > 0 && options.timeout <= 30_000);
    assert.ok(options.maxBuffer <= 524_288);
    const name = `zasp-m1-12-${state.marker}`;
    const byName = ["ps", "--all", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}"];
    const byID = ["ps", "--all", "--no-trunc", "--filter", `id=${containerID}`, "--format", "{{.ID}}"];
    const run = ["run", "--detach", "--rm", "--name", name, "--publish", "127.0.0.1::4566", "--env", "SERVICES=s3,kms", "--env", "PERSISTENCE=0", "--label", "zasp.proof=m1-12", "--label", `zasp.marker=${state.marker}`, LOCALSTACK_IMAGE];
    const same = (expected) => JSON.stringify(args) === JSON.stringify(expected);
    let result = { status: 0, stdout: "", stderr: "" };
    if (same(byName) || same(byID)) result.stdout = state.present ? `${containerID}\n` : "";
    else if (same(["image", "inspect", "--format", "{{.Id}}", LOCALSTACK_IMAGE])) result.stdout = `${state.imageID ?? imageID}\n`;
    else if (same(run)) {
      assert.equal(state.present, false, "never attach to an existing candidate");
      state.present = true;
      result.stdout = `${containerID}\n`;
      if (state.uncertain) result = { status: null, signal: "SIGKILL", stdout: "", stderr: "private-start-detail" };
    } else if (same(["inspect", "--format", inspectFormat, containerID])) {
      result.stdout = [containerID, `/${name}`, imageID, LOCALSTACK_IMAGE, "m1-12", state.marker].map((value, index) => state.mismatch === index ? "foreign" : value).join("|");
      if (!state.present) result.status = 1;
    } else if (same(["port", containerID, "4566/tcp"])) result.stdout = `127.0.0.1:${state.port}\n`;
    else if (same(["rm", "--force", containerID])) {
      if (state.removeFails) result = { status: 1, stdout: "", stderr: "private-remove-detail" };
      else { state.present = false; result.stdout = `${containerID}\n`; }
    } else if (same(["inspect", containerID])) result.status = state.present ? 0 : 1;
    else assert.fail(`undeclared Docker command: ${JSON.stringify(args)}`);
    state.calls.push({ args, timeout: options.timeout });
    state.clock = (state.clock ?? 0) + (state.costs?.[state.calls.length - 1] ?? 0);
    writeFileSync(stateFile, JSON.stringify(state));
    if (state.signalAfter === args[0]) process.kill(process.pid, "SIGTERM");
    if (state.killAfter === args[0]) process.kill(process.pid, "SIGKILL");
    if (state.throwAfter === args[0]) throw new Error("private-command-detail");
    return result;
  };
}

async function fixture(t, extra = {}) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "zasp-audit-broker-test-")));
  chmodSync(root, 0o700);
  const marker = randomBytes(8).toString("hex");
  const stateFile = join(root, "docker-state.json");
  const readyFile = join(root, "ready.json");
  const server = http.createServer((_request, response) => {
    response.end(extra.health ?? JSON.stringify({ services: { s3: "available", kms: "running" } }));
    if (extra.expireAfterHealth) {
      const state = JSON.parse(readFileSync(stateFile, "utf8"));
      state.clock = 120_001;
      writeFileSync(stateFile, JSON.stringify(state));
    }
    if (extra.occupyAfterHealth) writeFileSync(readyFile, "parent-owned-race");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  writeFileSync(stateFile, JSON.stringify({ marker, present: false, port: server.address().port, calls: [], ...extra }));
  t.after(() => { server.closeAllConnections(); server.close(); rmSync(root, { recursive: true, force: true }); });
  return { root, marker, stateFile, readyFile, state: () => JSON.parse(readFileSync(stateFile, "utf8")), args: ["serve", marker, readyFile, imageID] };
}

function launch(t, f, args = f.args) {
  const child = spawn(process.execPath, [self, "--fixture-child", f.stateFile, ...args], { env: { PATH: process.env.PATH }, stdio: ["pipe", "pipe", "pipe"] });
  let output = "";
  let errorOutput = "";
  child.stdout.on("data", (chunk) => { output += chunk; if (output.length > 2048) child.kill("SIGKILL"); });
  child.stderr.on("data", (chunk) => { errorOutput += chunk; if (errorOutput.length > 2048) child.kill("SIGKILL"); });
  const finished = new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("owned fixture child exceeded 8s")); }, 8000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => { clearTimeout(timer); resolve({ code, signal, output, errorOutput }); });
  });
  t.after(async () => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); await finished.catch(() => {}); });
  return { child, finished };
}

async function ready(f, child) {
  const deadline = Date.now() + 4000;
  while (!existsSync(f.readyFile)) {
    assert.equal(child.exitCode, null, "broker must remain alive before readiness");
    assert.ok(Date.now() < deadline, "bounded readiness publication");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  const descriptor = JSON.parse(readFileSync(f.readyFile, "utf8"));
  assert.deepEqual(descriptor, { schema, marker: f.marker, containerID, resolvedImageID: imageID, endpoint: `http://127.0.0.1:${f.state().port}` });
  assert.equal(lstatSync(f.readyFile).mode & 0o777, 0o600);
  assert.equal(f.state().present, true, "already-owned candidate must exist at interruption");
}

// Explicit acceptance only: node audit-export-container.test.mjs --actual-owned
// The default Node test selection never dispatches Docker.
async function actualOwnedAcceptance() {
  let commandDeadline = Date.now() + 60_000;
  const docker = (args) => {
    const remaining = commandDeadline - Date.now();
    assert.ok(remaining > 0, "actual Docker stage deadline");
    const result = spawnSync("docker", args, { env: { PATH: process.env.PATH }, encoding: "utf8", timeout: Math.min(30_000, remaining), killSignal: "SIGKILL", maxBuffer: 16_384 });
    assert.equal(result.status, 0, `Docker acceptance command failed: ${args[0]}`);
    return result.stdout.trim();
  };
  const inspected = docker(["image", "inspect", "--format", "{{.Id}}|{{json .RepoDigests}}", LOCALSTACK_IMAGE]).split("|");
  const expectedImageID = inspected[0];
  assert.match(expectedImageID, /^sha256:[a-f0-9]{64}$/);
  assert.ok(JSON.parse(inspected[1]).includes("localstack/localstack@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c"));
  console.log(JSON.stringify({ preflight: "pinned-image", configuredImage: LOCALSTACK_IMAGE, resolvedImageID: expectedImageID }));
  for (const shutdown of ["EOF", "SIGTERM"]) {
    const root = realpathSync(mkdtempSync(join(tmpdir(), "zasp-audit-broker-actual-")));
    chmodSync(root, 0o700);
    const rootIdentity = lstatSync(root);
    const marker = randomBytes(8).toString("hex");
    const name = `zasp-m1-12-${marker}`;
    const readyFile = join(root, "ready.json");
    const brokerFile = fileURLToPath(new URL("./audit-export-container.mjs", import.meta.url));
    let child;
    let joined = false;
    let absent = false;
    let exit;
    let output = "";
    let errorOutput = "";
    let descriptor;
    const started = Date.now();
    const boundedJoin = async (milliseconds) => {
      let timer;
      try { return await Promise.race([exit, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error("actual broker join deadline")), milliseconds); })]); }
      finally { clearTimeout(timer); }
    };
    try {
      commandDeadline = Date.now() + 30_000;
      assert.equal(docker(["ps", "--all", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}"]), "");
      child = spawn(process.execPath, [brokerFile, "serve", marker, readyFile, expectedImageID], { env: { PATH: process.env.PATH }, stdio: ["pipe", "pipe", "pipe"] });
      child.stdout.on("data", (chunk) => { output += chunk; if (output.length > 2048) { output = output.slice(0, 2048); child.stdin.end(); } });
      child.stderr.on("data", (chunk) => { errorOutput += chunk; if (errorOutput.length > 2048) { errorOutput = errorOutput.slice(0, 2048); child.stdin.end(); } });
      exit = new Promise((resolveExit, reject) => { child.once("error", reject); child.once("close", (code, signal) => { joined = true; resolveExit({ code, signal }); }); });
      const readyDeadline = Date.now() + 125_000;
      while (!existsSync(readyFile)) {
        assert.equal(joined, false, `actual broker exited before readiness: ${errorOutput}`);
        assert.ok(Date.now() < readyDeadline, "actual readiness deadline");
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      const status = lstatSync(readyFile);
      assert.ok(status.isFile() && !status.isSymbolicLink() && status.size <= 1024 && status.uid === process.getuid());
      assert.equal(status.mode & 0o777, 0o600);
      descriptor = JSON.parse(readFileSync(readyFile, "utf8"));
      assert.deepEqual(Object.keys(descriptor).sort(), ["containerID", "endpoint", "marker", "resolvedImageID", "schema"]);
      assert.equal(descriptor.schema, schema); assert.equal(descriptor.marker, marker);
      assert.equal(descriptor.resolvedImageID, expectedImageID);
      assert.match(descriptor.containerID, /^[a-f0-9]{64}$/);
      const port = /^http:\/\/127\.0\.0\.1:([0-9]{4,5})$/.exec(descriptor.endpoint);
      assert.ok(port && Number(port[1]) >= 1024 && Number(port[1]) <= 65535);
      assert.equal(joined, false);
      commandDeadline = Date.now() + 60_000;
      const identity = docker(["inspect", "--format", inspectFormat, descriptor.containerID]);
      assert.equal(identity, [descriptor.containerID, `/${name}`, expectedImageID, LOCALSTACK_IMAGE, "m1-12", marker].join("|"));
      console.log(JSON.stringify({ shutdown, root, brokerPID: child.pid, name, identity, ready: descriptor }));
      if (shutdown === "EOF") child.stdin.end(); else child.kill("SIGTERM");
      const result = await boundedJoin(parentGraceMilliseconds);
      assert.deepEqual(result, { code: 0, signal: null });
      assert.equal(output, `${JSON.stringify({ schema, result: "absent" })}\n`);
      assert.equal(errorOutput, "");
      commandDeadline = Date.now() + 60_000;
      assert.equal(docker(["ps", "--all", "--no-trunc", "--filter", `id=${descriptor.containerID}`, "--format", "{{.ID}}"]), "");
      assert.equal(docker(["ps", "--all", "--no-trunc", "--filter", `name=^/${name}$`, "--format", "{{.ID}}"]), "");
      absent = true;
      console.log(JSON.stringify({ shutdown, joined, absentByFullID: descriptor.containerID, absentByExactName: name, elapsedMilliseconds: Date.now() - started }));
    } finally {
      if (child && !joined) {
        child.stdin.end();
        try { await boundedJoin(parentGraceMilliseconds); }
        catch { child.kill("SIGKILL"); await boundedJoin(5000); }
      }
      if (!absent) {
        // Failure recovery never takes an ID or marker from a descriptor.
        const result = spawnSync(process.execPath, [brokerFile, "recover", marker, expectedImageID], { env: { PATH: process.env.PATH }, encoding: "utf8", timeout: parentGraceMilliseconds, killSignal: "SIGKILL", maxBuffer: 2048 });
        console.log(JSON.stringify({ retainedRoot: root, recoveryCode: result.status, joined, name }));
      } else {
        const current = lstatSync(root);
        assert.equal(current.dev, rootIdentity.dev); assert.equal(current.ino, rootIdentity.ino);
        rmSync(root, { recursive: true, force: false });
      }
    }
  }
}

if (process.argv[2] === "--actual-owned") {
  await actualOwnedAcceptance();
} else if (process.argv[2] === "--overflow-child") {
  process.stdout.write("x".repeat(600_000));
  process.stderr.write("y".repeat(600_000));
} else if (process.argv[2] === "--fixture-parent") {
  const child = spawn(process.execPath, [self, "--fixture-child", ...process.argv.slice(3)], { env: { PATH: process.env.PATH }, stdio: ["pipe", "ignore", "ignore"] });
  process.stdout.write(`${child.pid}\n`);
  setTimeout(() => process.exit(99), 6000).unref();
} else if (process.argv[2] === "--fixture-child") {
  const stateFile = process.argv[3];
  setTimeout(() => process.exit(99), 6000).unref();
  process.exitCode = await runBroker({ argv: process.argv.slice(4), command: declaredDocker(stateFile), now: () => JSON.parse(readFileSync(stateFile, "utf8")).clock ?? 0 });
} else {
  test("parent join allowance outlasts a pending-signal startup burst and shared cleanup", () => {
    // DockerRuntime can issue several synchronous commands before Node handles
    // the parent's signal. Model the entire capped startup followed by cleanup.
    let elapsed = 0;
    for (const commandCost of [30_000, 30_000, 30_000, 30_000, 30_000, 30_000, 15_000]) {
      elapsed += commandCost;
      assert.ok(elapsed < parentGraceMilliseconds, "parent must not kill broker before its bounded cleanup completes");
    }
    assert.ok(parentGraceMilliseconds - elapsed >= 5000, "parent retains a 5s join margin");
  });

  for (const shutdown of ["EOF", "SIGTERM", "SIGINT"]) {
    test(`ready owned child removes its exact candidate after ${shutdown}`, async (t) => {
      const f = await fixture(t);
      const { child, finished } = launch(t, f);
      await ready(f, child);
      if (shutdown === "EOF") child.stdin.end(); else child.kill(shutdown);
      const result = await finished;
      assert.equal(result.code, 0, result.errorOutput);
      assert.equal(result.signal, null);
      assert.equal(f.state().present, false, "interrupted ready child leaked its owned container");
      assert.ok(f.state().calls.some(({ args }) => args[0] === "rm"));
      assert.equal(result.output, `${JSON.stringify({ schema, result: "absent" })}\n`);
      assert.equal(result.errorOutput, "");
    });
  }

  test("EOF already observed before entry never dispatches a Docker run", async (t) => {
    const f = await fixture(t);
    const stdin = new PassThrough();
    stdin.resume(); stdin.end();
    await new Promise((resolve) => stdin.once("end", resolve));
    const code = await runBroker({ argv: f.args, command: declaredDocker(f.stateFile), stdin, signals: new EventEmitter(), stdout: new PassThrough(), stderr: new PassThrough() });
    assert.equal(code, 0);
    assert.equal(f.state().calls.some(({ args }) => args[0] === "run"), false);
    assert.equal(existsSync(f.readyFile), false);
  });

  test("a handled signal during preflight prevents the subsequent container start", async (t) => {
    const f = await fixture(t, { signalAfter: "image" });
    const { finished } = launch(t, f);
    const result = await finished;
    assert.equal(result.code, 0, result.errorOutput);
    assert.equal(f.state().calls.some(({ args }) => args[0] === "run"), false);
    assert.equal(existsSync(f.readyFile), false);
  });

  test("uncertain Docker start is reconciled and EOF removes that exact full ID", async (t) => {
    const f = await fixture(t, { uncertain: true });
    const { child, finished } = launch(t, f);
    await ready(f, child); child.stdin.end();
    assert.equal((await finished).code, 0);
    assert.equal(f.state().present, false);
  });

  test("a command exception after accepted run still discovers and removes the owned candidate", async (t) => {
    const f = await fixture(t, { throwAfter: "run" });
    const { finished } = launch(t, f);
    const result = await finished;
    assert.equal(result.code, 1);
    assert.equal(f.state().present, false);
    assert.equal(existsSync(f.readyFile), false);
    assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: operation rejected.\n");
  });

  test("broker death during accepted run recovers by original marker before descriptor publication", async (t) => {
    const f = await fixture(t, { killAfter: "run" });
    const first = launch(t, f);
    assert.equal((await first.finished).signal, "SIGKILL");
    assert.equal(f.state().present, true);
    assert.equal(existsSync(f.readyFile), false);
    // Even a forged descriptor cannot supply a removal ID to recovery.
    writeFileSync(f.readyFile, JSON.stringify({ containerID: "c".repeat(64), marker: "foreign" }));
    const recovery = launch(t, f, ["recover", f.marker, imageID]);
    assert.equal((await recovery.finished).code, 0);
    assert.equal(f.state().present, false);
    assert.equal(JSON.parse(readFileSync(f.readyFile, "utf8")).marker, "foreign");
  });

  test("parent process death closes its sole broker pipe and the finite orphan stops", async (t) => {
    const f = await fixture(t);
    const parent = spawn(process.execPath, [self, "--fixture-parent", f.stateFile, ...f.args], { env: { PATH: process.env.PATH }, stdio: ["ignore", "pipe", "pipe"] });
    const parentExit = new Promise((resolve) => parent.once("close", (code, signal) => resolve({ code, signal })));
    t.after(async () => { if (parent.exitCode === null && parent.signalCode === null) parent.kill("SIGKILL"); await parentExit; });
    const brokerPID = await new Promise((resolve) => parent.stdout.once("data", (chunk) => resolve(Number(String(chunk).trim()))));
    assert.ok(Number.isInteger(brokerPID) && brokerPID > 0);
    await ready(f, parent);
    parent.kill("SIGKILL");
    assert.equal((await parentExit).signal, "SIGKILL");
    const deadline = Date.now() + 7000;
    let alive = true;
    while (Date.now() < deadline) {
      try { process.kill(brokerPID, 0); } catch (error) { assert.equal(error.code, "ESRCH"); alive = false; break; }
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(alive, false, "orphan must stop within its finite owned lifetime");
    assert.equal(f.state().present, false, "parent death must cause cleanup before the finite helper exit");
  });

  for (const health of ["not-json", "x".repeat(16_385), '{"services":{"s3":"running"}}']) {
    test(`unusable health (${health.length} bytes) never publishes and joins cleanup at deadline`, async (t) => {
      const f = await fixture(t, { health, expireAfterHealth: true });
      const { finished } = launch(t, f);
      const result = await finished;
      assert.equal(result.code, 1);
      assert.equal(f.state().present, false);
      assert.equal(existsSync(f.readyFile), false);
      assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: readiness rejected.\n");
    });
  }

  test("a ready-file collision during startup preserves parent bytes and still removes the container", async (t) => {
    const f = await fixture(t, { occupyAfterHealth: true });
    const { finished } = launch(t, f);
    assert.equal((await finished).code, 1);
    assert.equal(readFileSync(f.readyFile, "utf8"), "parent-owned-race");
    assert.equal(f.state().present, false);
  });

  test("finite executable output overflow remains bounded fixed failure", async (t) => {
    const f = await fixture(t);
    const output = new PassThrough();
    const errors = new PassThrough();
    let bytes = "";
    errors.on("data", (chunk) => { bytes += chunk; });
    const code = await runBroker({ argv: f.args, stdin: new PassThrough(), signals: new EventEmitter(), stdout: output, stderr: errors,
      command: (_executable, _args, options) => spawnSync(process.execPath, [self, "--overflow-child"], options) });
    assert.equal(code, 1);
    assert.equal(existsSync(f.readyFile), false);
    assert.equal(bytes, "audit-export-localstack-fixture-v1: cleanup rejected.\n");
  });

  test("stdin accepts EOF only and rejects data with joined cleanup", async (t) => {
    const f = await fixture(t);
    const { child, finished } = launch(t, f);
    await ready(f, child); child.stdin.write("{\"remove\":\"ambient\"}");
    const result = await finished;
    assert.equal(result.code, 1);
    assert.equal(f.state().present, false);
    assert.equal(result.output, "");
    assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: protocol rejected.\n");
  });

  test("cleanup failure is fixed nonzero output even after readiness", async (t) => {
    const f = await fixture(t, { removeFails: true });
    const { child, finished } = launch(t, f);
    await ready(f, child); child.stdin.end();
    const result = await finished;
    assert.equal(result.code, 1);
    assert.equal(f.state().present, true);
    assert.equal(result.output, "");
    assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: cleanup rejected.\n");
    assert.ok(f.state().calls.some(({ args }) => args[0] === "inspect" && args.length === 2), "absence check must still run after remove failure");
  });

  test("recovery removes a verified exact candidate without any ready descriptor", async (t) => {
    const f = await fixture(t, { present: true });
    const { finished } = launch(t, f, ["recover", f.marker, imageID]);
    const result = await finished;
    assert.equal(result.code, 0, result.errorOutput);
    assert.equal(f.state().present, false);
    assert.equal(existsSync(f.readyFile), false);
    assert.equal(f.state().calls.some(({ args }) => args[0] === "run"), false);
  });

  for (const mismatch of [0, 1, 2, 3, 4, 5]) {
    test(`recovery refuses mismatched ownership field ${mismatch} without removal`, async (t) => {
      const f = await fixture(t, { present: true, mismatch });
      const { finished } = launch(t, f, ["recover", f.marker, imageID]);
      const result = await finished;
      assert.equal(result.code, 1);
      assert.equal(f.state().present, true);
      assert.equal(f.state().calls.some(({ args }) => args[0] === "rm"), false);
      assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: cleanup rejected.\n");
    });
  }

  test("serve refuses a resolved pin different from the parent's verified identity", async (t) => {
    const f = await fixture(t, { imageID: `sha256:${"c".repeat(64)}` });
    const { finished } = launch(t, f);
    const result = await finished;
    assert.equal(result.code, 1);
    assert.equal(f.state().calls.some(({ args }) => args[0] === "run"), false);
    assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: operation rejected.\n");
  });

  test("recovery's 75s shared deadline caps each dispatch and forbids a fourth command", async (t) => {
    const f = await fixture(t, { present: true, costs: [30_000, 30_000, 15_000] });
    const { finished } = launch(t, f, ["recover", f.marker, imageID]);
    const result = await finished;
    assert.equal(result.code, 1);
    assert.equal(f.state().present, true);
    assert.deepEqual(f.state().calls.map(({ timeout }) => timeout), [30_000, 30_000, 15_000]);
    assert.equal(f.state().calls.some(({ args }) => args[0] === "rm"), false);
    assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: cleanup rejected.\n");
  });

  test("normal removal and absence checks share the same 75s including dispatch", async (t) => {
    const f = await fixture(t, { costs: [0, 0, 0, 0, 0, 0, 30_000, 30_000, 15_000] });
    const { child, finished } = launch(t, f);
    await ready(f, child); child.stdin.end();
    const result = await finished;
    assert.equal(result.code, 1, "unconfirmed absence at deadline is a cleanup failure");
    assert.equal(f.state().present, false);
    assert.deepEqual(f.state().calls.slice(6).map(({ timeout }) => timeout), [30_000, 30_000, 15_000]);
    assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: cleanup rejected.\n");
  });

  test("recovery refuses a changed pinned image without using ready-file authority", async (t) => {
    const f = await fixture(t, { present: true, imageID: `sha256:${"c".repeat(64)}` });
    const { finished } = launch(t, f, ["recover", f.marker, imageID]);
    assert.equal((await finished).code, 1);
    assert.equal(f.state().present, true);
    assert.equal(f.state().calls.some(({ args }) => args[0] === "rm" || args[0] === "run"), false);
  });

  for (const invalid of ["extra-argument", "bad-marker", "bad-image", "relative-path", "wrong-basename", "public-root", "symlink-root", "occupied-ready"]) {
    test(`closed protocol refuses ${invalid} before Docker dispatch`, async (t) => {
      const f = await fixture(t);
      const args = [...f.args];
      if (invalid === "extra-argument") args.push("ignored-authority");
      if (invalid === "bad-marker") args[1] = "abcd";
      if (invalid === "bad-image") args[3] = LOCALSTACK_IMAGE;
      if (invalid === "relative-path") args[2] = "ready.json";
      if (invalid === "wrong-basename") args[2] = join(f.root, "other.json");
      if (invalid === "public-root") chmodSync(f.root, 0o755);
      if (invalid === "symlink-root") { symlinkSync(f.root, join(f.root, "alias")); args[2] = join(f.root, "alias", "ready.json"); }
      if (invalid === "occupied-ready") writeFileSync(f.readyFile, "parent-owned-data");
      const { finished } = launch(t, f, args);
      const result = await finished;
      assert.equal(result.code, 1);
      assert.deepEqual(f.state().calls, []);
      assert.equal(result.errorOutput, "audit-export-localstack-fixture-v1: configuration rejected.\n");
      if (invalid === "occupied-ready") assert.equal(readFileSync(f.readyFile, "utf8"), "parent-owned-data");
    });
  }
}

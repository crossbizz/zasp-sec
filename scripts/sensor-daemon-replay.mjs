import assert from "node:assert/strict";
import { randomUUID, createHash } from "node:crypto";
import { chmod, lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { performance } from "node:perf_hooks";
import { spawnOwnedCommand } from "./owned-command.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const image = "postgres:18.6-bookworm@sha256:1c59e2c3c818eaa0f0628f695b36e7c9e362d6b219b36a54a32df645cbd7e1af";
const binaries = ["apiserver.test", "sensor-agent.test", "sensor-agent"];
const capabilities = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "KILL", "NET_BIND_SERVICE", "SETGID", "SETUID"];
const tmpfs = { "/tmp": "rw,nosuid,nodev,size=536870912,mode=1777", "/var/lib/postgresql": "rw,nosuid,nodev,size=16777216", "/var/run/secrets/kubernetes.io/serviceaccount": "rw,nosuid,nodev,size=65536,mode=0755" };
const testName = "TestRuntimeAcceptanceActualDaemonLostSuccessReplay";
const testArguments = [`-test.run=^(${testName}|TestSensorDaemonReplayOwnershipCleanup|TestSensorDaemonReplayTrace)`, "-test.v", "-test.timeout=120s"];
const proofEnvironment = ["ZASP_TEST_DAEMON_REPLAY=1", "GOMEMLIMIT=256MiB"];
export function daemonReplayPlatform(info) {
  assert.equal(info?.os, "linux", "daemon proof requires a Linux Docker host");
  const architecture = new Map([["amd64", "amd64"], ["x86_64", "amd64"], ["arm64", "arm64"], ["aarch64", "arm64"]]).get(info.architecture);
  assert.ok(architecture, "unsupported Docker host architecture");
  return `linux/${architecture}`;
}
function validateConfig({ owner, directory, imageEnvironment, platform }) {
  assert.match(owner, /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/);
  assert.ok(typeof directory === "string" && isAbsolute(directory) && resolve(directory) === directory && dirname(directory) !== "/" && !/[,\r\n\0]/.test(directory));
  assert.ok(Array.isArray(imageEnvironment) && imageEnvironment.every(value => typeof value === "string" && /^[A-Z_][A-Z0-9_]*=/.test(value) && !/[\r\n\0]/.test(value)));
  const keys = [...imageEnvironment, ...proofEnvironment].map(value => value.split("=", 1)[0]);
  assert.equal(new Set(keys).size, keys.length, "image defaults conflict with proof environment");
  assert.ok(platform === "linux/amd64" || platform === "linux/arm64", "unsupported proof platform");
}
export function buildDaemonReplayArguments(config) {
  validateConfig(config);
  return ["create", "--platform", config.platform, "--name", `zasp-daemon-replay-${config.owner}`, "--label", "zasp.proof=daemon-replay", "--label", `zasp.owner=${config.owner}`,
    "--network", "none", "--read-only", "--user", "0:65532", "--cap-drop", "ALL", ...capabilities.flatMap(value => ["--cap-add", value]),
    "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "1g", "--memory-swap", "1g", "--cpus", "2", "--shm-size", "64m",
    ...Object.entries(tmpfs).flatMap(([path, value]) => ["--tmpfs", `${path}:${value}`]),
    ...binaries.flatMap(name => ["--mount", `type=bind,src=${join(config.directory, name)},dst=/proof/${name},readonly`]),
    "--env", "ZASP_TEST_DAEMON_REPLAY=1", "--env", "GOMEMLIMIT=256MiB", "--entrypoint", "/proof/apiserver.test", image,
    ...testArguments];
}
export function validateDaemonReplayContainer(value, config) {
  validateConfig(config);
  assert.match(value?.Id ?? "", /^[a-f0-9]{64}$/);
  assert.equal(value.Name, `/zasp-daemon-replay-${config.owner}`);
  assert.equal(value.Config?.Labels?.["zasp.proof"], "daemon-replay");
  assert.equal(value.Config?.Labels?.["zasp.owner"], config.owner);
  assert.equal(value.Config.User, "0:65532");
  assert.equal(value.Config.Image, image);
  assert.deepEqual(value.Config.Entrypoint, ["/proof/apiserver.test"]);
  assert.deepEqual(value.Config.Cmd, testArguments);
  assert.deepEqual([...value.Config.Env].sort(), [...config.imageEnvironment, ...proofEnvironment].sort());
  const host = value.HostConfig;
  for (const [key, expected] of Object.entries({ NetworkMode: "none", ReadonlyRootfs: true, Privileged: false, Memory: 1073741824, MemorySwap: 1073741824, PidsLimit: 128, NanoCpus: 2000000000, ShmSize: 67108864, IpcMode: "private", PidMode: "" })) assert.equal(host?.[key], expected, key);
  assert.deepEqual(host.CapDrop, ["ALL"]);
  assert.deepEqual(host.CapAdd.map(value => value.replace(/^CAP_/, "")).sort(), capabilities);
  assert.deepEqual(host.SecurityOpt, ["no-new-privileges"]);
  assert.deepEqual(host.PortBindings, {});
  assert.deepEqual(host.Tmpfs, tmpfs);
  assert.equal(value.Mounts?.length, 3);
  for (const name of binaries) {
    const mount = value.Mounts.find(item => item.Destination === `/proof/${name}`);
    assert.ok(mount && mount.Type === "bind" && mount.RW === false && mount.Source === join(config.directory, name), `exact read-only ${name} bind required`);
  }
}
export function validateDaemonReplayResult(value, output) {
  assert.equal(value.State?.Running, false);
  assert.equal(value.State?.Pid, 0);
  assert.equal(value.State?.Status, "exited");
  assert.equal(value.State?.ExitCode, 0);
  assert.equal(value.State?.OOMKilled, false);
  assert.equal(value.State?.Error, "");
  assert.ok(output.includes(`--- PASS: ${testName} (`) && /\nPASS\s*$/.test(output), "actual daemon composition didn't pass");
}
export async function closeDaemonReplayContainer(command, config, successful) {
  const inspect = async () => {
    const result = await command(["inspect", `zasp-daemon-replay-${config.owner}`]);
    // Inspect by the recorded create intent, including a lost create response.
    if (result.status !== 0) throw new Error("cannot inspect owned container; preserving binary directory");
    const values = JSON.parse(result.stdout);
    assert.equal(values.length, 1);
    validateDaemonReplayContainer(values[0], config);
    return values[0];
  };
  let value = await inspect();
  if (value.State.Running) {
    const stop = await command(["stop", "--time", "10", value.Id]);
    assert.equal(stop.status, 0, "owned container stop failed; preserving state");
    value = await inspect();
  }
  assert.equal(value.State.Running, false);
  assert.equal(value.State.Pid, 0);
  if (!successful) return; // Keep failed container metadata and host evidence.
  const removed = await command(["rm", value.Id]);
  assert.equal(removed.status, 0, "exact stopped container removal failed");
  const absent = await command(["inspect", value.Id]);
  assert.ok(absent.status !== 0 && /No such (object|container)/i.test(absent.stderr ?? ""), "owned container absence isn't verified");
}

export function daemonReplayCommandBudget(requested, elapsed) {
  // CI permits 15 minutes. Ordinary execution ends after 12, leaving three for
  // command joins and independent Docker inspection/stop/removal attempts.
  const remaining = 720_000 - elapsed;
  assert.ok(remaining > 0, "overall daemon proof deadline");
  return Math.min(requested, remaining);
}

export async function cleanupDaemonReplayResources({ commands, container, removeRoot, successful }) {
  const failures = [];
  for (const command of commands) {
    try { await command.stop(); } catch (error) { failures.push(error); }
  }
  // A failed CLI/compiler join mustn't skip reconciliation of the independently
  // running Docker container. Its binary directory still cannot be deleted.
  try { await container(successful && failures.length === 0); } catch (error) { failures.push(error); }
  if (successful && failures.length === 0) {
    try { await removeRoot(); } catch (error) { failures.push(error); }
  }
  if (failures.length) throw new AggregateError(failures, "owned cleanup incomplete; evidence preserved");
}

export async function finishDaemonReplayCommand(owned, { directory, sequence, failed }) {
  await owned.stop();
  if (!failed) return;
  const result = await owned.completed.catch(error => ({ status: null, signal: null, stdout: "", stderr: error.message }));
  // CLI timeouts/interruption don't return through the normal attempt log path.
  // Keep joined output privately, before Docker shutdown destroys its tmpfs.
  await writeFile(join(directory, `failed-command-${sequence}.json`), JSON.stringify(result), { mode: 0o600 });
}

export async function runDaemonReplayProof() {
  const started = performance.now();
  const directory = await mkdtemp(join(tmpdir(), "zasp-daemon-proof-"));
  const directoryIdentity = await lstat(directory);
  const config = { owner: randomUUID(), directory, imageEnvironment: [] };
  const commands = new Set();
  let interrupted = false, creating = false, successful = false;
  let failure;
  let sequence = 0;
  const interrupt = () => { interrupted = true; for (const command of commands) void command.stop().catch(() => {}); };
  process.once("SIGINT", interrupt); process.once("SIGTERM", interrupt);
  const run = async (executable, args, { timeout = 20_000, env = process.env, cleanup = false, reject = true } = {}) => {
    if (interrupted && !cleanup) throw new Error("daemon proof interrupted");
    if (!cleanup) timeout = daemonReplayCommandBudget(timeout, performance.now() - started);
    const owned = spawnOwnedCommand(executable, args, { cwd: root, env });
    const commandSequence = ++sequence;
    commands.add(owned);
    let timer, timedOut = false, commandFailed = false;
    try {
      const result = await Promise.race([owned.completed, new Promise((_, reject) => {
        timer = setTimeout(() => { timedOut = true; reject(new Error("owned command deadline")); }, timeout);
      })]);
      if (reject && result.status !== 0) throw new Error(`${executable} failed: ${result.stderr.slice(-4000)}`);
      return result;
    } catch (error) {
      commandFailed = true;
      throw error;
    } finally {
      clearTimeout(timer);
      await finishDaemonReplayCommand(owned, { directory, sequence: commandSequence, failed: timedOut || interrupted || commandFailed });
      commands.delete(owned);
      if (timedOut) console.error("command deadline; owned process group joined");
    }
  };
  const docker = (args, options) => run("docker", args, options);
  try {
    const host = JSON.parse((await docker(["info", "--format", '{"os":{{json .OSType}},"architecture":{{json .Architecture}}}'])).stdout);
    config.platform = daemonReplayPlatform(host);
    await docker(["pull", "--platform", config.platform, image], { timeout: 120_000 });
    const metadata = JSON.parse((await docker(["image", "inspect", image])).stdout);
    assert.equal(metadata.length, 1);
    const arch = metadata[0].Architecture;
    assert.equal(metadata[0].Os, "linux");
    assert.equal(`linux/${arch}`, config.platform, "pulled image differs from Docker host platform");
    console.log(`daemon proof platform ${config.platform}; pinned image ${image}`);
    // Only defaults from the exact pulled digest may accompany our two entries.
    config.imageEnvironment = metadata[0].Config.Env ?? [];
    validateConfig(config);
    assert.ok(["arm64", "amd64"].includes(arch));
    const env = { ...process.env, CGO_ENABLED: "0", GOOS: "linux", GOARCH: arch };
    for (const [name, module, packageName] of [["apiserver.test", "platform", "./apiserver"], ["sensor-agent.test", "sensor-agent", "."], ["sensor-agent", "sensor-agent", "."]]) {
      const binary = join(directory, name);
      await run("go", [...(name.endsWith(".test") ? ["test", "-C", `services/${module}`, "-c"] : ["build", "-C", `services/${module}`]), "-mod=readonly", "-trimpath", "-o", binary, packageName], { env, timeout: 300_000 });
      await chmod(binary, 0o755);
      console.log(`${name} sha256 ${createHash("sha256").update(await readFile(binary)).digest("hex")}`);
    }
    await chmod(directory, 0o755);
    creating = true;
    const created = await docker(buildDaemonReplayArguments(config));
    const id = created.stdout.trim(); assert.match(id, /^[a-f0-9]{64}$/);
    const inspect = async name => {
      const values = JSON.parse((await docker(["inspect", id])).stdout);
      assert.equal(values.length, 1); assert.equal(values[0].Id, id);
      validateDaemonReplayContainer(values[0], config);
      await writeFile(join(directory, name), JSON.stringify(values, null, 2), { mode: 0o600 });
      return values[0];
    };
    await inspect("before.json");
    for (let attempt = 1; attempt <= 2; attempt++) {
      const result = await docker(["start", "--attach", id], { timeout: 130_000, reject: false });
      const output = result.stdout + result.stderr;
      await writeFile(join(directory, `attempt-${attempt}.log`), output, { mode: 0o600 });
      process.stdout.write(output);
      const value = await inspect(`after-${attempt}.json`);
      assert.equal(result.status, 0);
      validateDaemonReplayResult(value, result.stdout);
    }
    successful = !interrupted;
    assert.ok(successful, "daemon proof interrupted");
  } catch (error) {
    failure = error;
  } finally {
    try {
      await cleanupDaemonReplayResources({ commands: [...commands], successful,
        container: async removable => { if (creating) await closeDaemonReplayContainer(args => docker(args, { cleanup: true, reject: false }), config, removable); },
        removeRoot: async () => {
          const current = await lstat(directory);
          assert.ok(current.isDirectory() && current.dev === directoryIdentity.dev && current.ino === directoryIdentity.ino);
          await rm(directory, { recursive: true });
        },
      });
      if (!successful) console.error(`Failed proof evidence retained at ${directory}; container intent zasp-daemon-replay-${config.owner}. Container tmpfs doesn't survive exit.`);
    } catch (error) {
      console.error(`Cleanup incomplete; retained evidence ${directory}; container intent zasp-daemon-replay-${config.owner}`);
      failure = failure ? new AggregateError([failure, error], "daemon proof and cleanup failed") : error;
    } finally { process.removeListener("SIGINT", interrupt); process.removeListener("SIGTERM", interrupt); }
  }
  if (failure) throw failure;
  console.log("PASS: actual daemon replay twice; owned container removed. Local fixture, not deployed production acceptance.");
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runDaemonReplayProof().catch(error => { console.error(error.message); process.exitCode = 1; });
}

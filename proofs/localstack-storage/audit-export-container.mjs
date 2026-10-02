import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { closeSync, constants, fchmodSync, fsyncSync, linkSync, lstatSync, openSync, realpathSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { ARTIFACT_MODE, DockerRuntime, LOCALSTACK_IMAGE } from "./run.mjs";

export const brokerSchema = "audit-export-localstack-fixture-v1";
export const cleanupMilliseconds = 75_000;
// DockerRuntime can issue several synchronous commands before Node handles a
// pending signal. Allow the entire 120s startup burst + 75s cleanup + 5s join
// margin. The worker's 250ms escalation is not a container cleanup allowance.
export const parentGraceMilliseconds = 200_000;
const startupMilliseconds = 120_000;
const readyBytesLimit = 1024;
const reject = () => { throw new Error("broker boundary rejected"); };
const eventTurn = () => new Promise((resolveTurn) => setImmediate(resolveTurn));

function privateRoot(path) {
  const status = lstatSync(path);
  if (!status.isDirectory() || status.isSymbolicLink() || (status.mode & 0o777) !== 0o700 ||
    status.uid !== process.getuid() || realpathSync(path) !== path) reject();
  return { path, dev: status.dev, ino: status.ino };
}

function sameRoot(root) {
  const current = privateRoot(root.path);
  if (current.dev !== root.dev || current.ino !== root.ino) reject();
}

function requireMissing(path) {
  try { lstatSync(path); } catch (error) { if (error.code === "ENOENT") return; throw error; }
  reject();
}

function configuration(argv) {
  if (!Array.isArray(argv) || argv.some((value) => typeof value !== "string" || value.length > 4096)) reject();
  const [mode, marker] = argv;
  if (!/^[a-f0-9]{16}$/.test(marker ?? "")) reject();
  const expectedImageID = argv[mode === "serve" ? 3 : 2];
  if (!/^sha256:[a-f0-9]{64}$/.test(expectedImageID ?? "")) reject();
  if (mode === "recover" && argv.length === 3) return { mode, marker, expectedImageID };
  if (mode !== "serve" || argv.length !== 4) reject();
  const readyFile = argv[2];
  if (!isAbsolute(readyFile) || resolve(readyFile) !== readyFile || basename(readyFile) !== "ready.json") reject();
  const root = privateRoot(dirname(readyFile));
  requireMissing(readyFile);
  return { mode, marker, expectedImageID, readyFile, root };
}

function publishReady(config, runtime, endpoint) {
  const descriptor = { schema: brokerSchema, marker: config.marker, containerID: runtime.token, resolvedImageID: runtime.resolvedImageID, endpoint };
  const bytes = `${JSON.stringify(descriptor)}\n`;
  if (Buffer.byteLength(bytes) > readyBytesLimit) reject();
  sameRoot(config.root);
  const temporary = join(config.root.path, `.ready-${randomBytes(8).toString("hex")}.tmp`);
  let fd;
  let created = false;
  try {
    fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    created = true;
    fchmodSync(fd, 0o600);
    writeFileSync(fd, bytes);
    fsyncSync(fd);
    closeSync(fd); fd = undefined;
    sameRoot(config.root);
    // link is atomic and refuses any existing destination (including symlinks).
    // The private temporary name is unlinked immediately; readers see full bytes.
    linkSync(temporary, config.readyFile);
  } finally {
    if (fd !== undefined) closeSync(fd);
    if (created) { sameRoot(config.root); unlinkSync(temporary); }
  }
}

// Private CLI: serve MARKER /absolute/0700-root/ready.json RESOLVED_IMAGE_ID
//          or recover MARKER RESOLVED_IMAGE_ID
// stdin carries no messages: EOF releases the fixture. Recovery uses only the
// parent's original marker and independently verified image, never ready.json.
export async function runBroker({
  argv = process.argv.slice(2), command = spawnSync, stdin = process.stdin,
  signals = process, stdout = process.stdout, stderr = process.stderr,
  now = () => performance.now(), path = process.env.PATH,
} = {}) {
  let stopRequested = stdin.readableEnded || stdin.destroyed;
  let protocolFailed = false;
  let resolveStop;
  const stopped = new Promise((resolveStopped) => { resolveStop = resolveStopped; });
  const stop = () => { stopRequested = true; resolveStop(); };
  const badInput = () => { protocolFailed = true; stop(); };
  // Install all liveness handlers before validating paths or dispatching Docker.
  stdin.on("end", stop); stdin.on("close", stop); stdin.on("error", badInput); stdin.on("data", badInput);
  signals.on("SIGTERM", stop); signals.on("SIGINT", stop);
  stdin.resume();
  if (stopRequested) stop();
  let runtime;
  let config;
  let failure;
  let startAttempted = false;
  let deadline = now() + startupMilliseconds;
  const remaining = () => {
    const value = Math.floor(deadline - now());
    if (!Number.isFinite(value) || value <= 0) reject();
    return value;
  };
  const boundedCommand = (executable, args, options) => {
    const result = command(executable, args, { ...options, timeout: Math.min(options.timeout, remaining()) });
    remaining();
    return result;
  };
  const checkpoint = async () => { await eventTurn(); remaining(); return !stopRequested; };
  try {
    failure = "configuration";
    config = configuration(argv);
    runtime = new DockerRuntime({ mode: ARTIFACT_MODE, marker: config.marker, command: boundedCommand, path, home: config.root?.path ?? "/" });
    failure = "operation";
    if (config.mode === "serve" && await checkpoint()) {
      await runtime.ensureAbsent();
      if (runtime.resolvedImageID !== config.expectedImageID) reject();
      if (await checkpoint()) {
        startAttempted = true;
        await runtime.start();
        if (await checkpoint()) {
          await runtime.verifyOwned();
          const endpoint = await runtime.endpoint();
          failure = "readiness";
          let ready = false;
          for (let attempt = 0; attempt < 120 && await checkpoint(); attempt += 1) {
            if (await runtime.isReady(endpoint)) { ready = true; break; }
            await Promise.race([stopped, new Promise((resolveWait) => setTimeout(resolveWait, 250))]);
          }
          if (await checkpoint()) {
            if (!ready) reject();
            failure = "operation";
            publishReady(config, runtime, endpoint);
            await stopped;
          }
        }
      }
    }
    failure = undefined;
  } catch { /* Only a fixed category crosses this process boundary. */ }
  finally {
    // This single budget includes recovery image inspection, identity checks,
    // removal and both ID/name absence queries. No dispatch after expiry.
    deadline = now() + cleanupMilliseconds;
    if (runtime) {
      let cleanupFailed = false;
      try {
        if (config.mode === "recover") {
          const image = runtime.docker(["image", "inspect", "--format", "{{.Id}}", LOCALSTACK_IMAGE]);
          if (image?.status !== 0 || String(image.stdout).trim() !== config.expectedImageID) reject();
          runtime.resolvedImageID = config.expectedImageID;
          await runtime.remove();
        } else if (startAttempted && runtime.hasCandidate()) await runtime.remove();
      } catch { cleanupFailed = true; }
      try { await runtime.requireAbsent(); } catch { cleanupFailed = true; }
      if (cleanupFailed) failure = "cleanup";
    }
    stdin.pause();
    stdin.off("end", stop); stdin.off("close", stop); stdin.off("error", badInput); stdin.off("data", badInput);
    signals.off("SIGTERM", stop); signals.off("SIGINT", stop);
  }
  if (protocolFailed && failure !== "cleanup") failure = "protocol";
  if (failure) { stderr.write(`${brokerSchema}: ${failure} rejected.\n`); return 1; }
  stdout.write(`${JSON.stringify({ schema: brokerSchema, result: "absent" })}\n`);
  return 0;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = await runBroker();

import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const requiredProofEnvironment = Object.freeze([
  "AWS_M009_ISOLATED_TEST",
  "AWS_M009_REGION",
  "AWS_M009_SOURCE_ACCOUNT_ID",
  "AWS_M009_TARGET_ACCOUNT_ID",
  "AWS_M009_SOURCE_PRINCIPAL_ARN",
  "AWS_M009_SOURCE_ACCESS_KEY_ID",
  "AWS_M009_SOURCE_SECRET_ACCESS_KEY",
  "AWS_M009_TARGET_ADMIN_ACCESS_KEY_ID",
  "AWS_M009_TARGET_ADMIN_SECRET_ACCESS_KEY",
]);
const optionalProofEnvironment = Object.freeze([
  "AWS_M009_SOURCE_SESSION_TOKEN",
  "AWS_M009_TARGET_ADMIN_SESSION_TOKEN",
]);
const attestation = "isolated-disposable-aws-test-accounts-only";
const successLine = "Real AWS IAM proof passed: cross_account=true assumed=true allowed_read=true denied_call=true cleanup=true audit=true.";
const outputLimit = 4096;
const goMainTimeoutMs = 90_000;
const goCleanupTimeoutMs = 30_000;
const supervisorMarginMs = 60_000;
const proofSupervisorTimeoutMs = goMainTimeoutMs + goCleanupTimeoutMs + supervisorMarginMs;
const proofDirectory = dirname(fileURLToPath(import.meta.url));

export class SafeFailure extends Error {
  constructor(category) {
    super(category);
    this.category = category;
  }
}

export function validateProofEnvironment(environment) {
  if (environment === null || typeof environment !== "object") {
    throw new SafeFailure("configuration");
  }
  const result = Object.create(null);
  for (const name of requiredProofEnvironment) {
    const value = environment[name];
    if (typeof value !== "string" || value.length === 0) {
      throw new SafeFailure("configuration");
    }
    result[name] = value;
  }
  if (result.AWS_M009_ISOLATED_TEST !== attestation) {
    throw new SafeFailure("capability");
  }
  for (const name of optionalProofEnvironment) {
    const value = environment[name];
    if (typeof value === "string" && value.length > 0) {
      result[name] = value;
    }
  }
  return result;
}

export function buildChildEnvironment(environment) {
  const result = Object.create(null);
  for (const name of ["PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE", "GOPATH"]) {
    const value = environment[name];
    if (typeof value === "string" && value.length > 0) {
      result[name] = value;
    }
  }
  if (typeof result.PATH !== "string") {
    throw new SafeFailure("configuration");
  }
  result.CGO_ENABLED = "0";
  result.GOFLAGS = "-mod=readonly";
  return result;
}

export function runBounded(command, arguments_, options, spawnImplementation = spawn) {
  return new Promise((resolve, reject) => {
    let child;
    try {
      child = spawnImplementation(command, arguments_, {
        cwd: options.cwd,
        env: options.env,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      reject(new SafeFailure("operation"));
      return;
    }
    if (child === null || typeof child !== "object" || child.stdout === undefined || child.stderr === undefined) {
      reject(new SafeFailure("operation"));
      return;
    }
    let settled = false;
    let total = 0;
    const stdout = [];
    const stderr = [];
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      callback();
    };
    const stop = () => {
      child.stdout?.destroy?.();
      child.stderr?.destroy?.();
      child.kill?.("SIGKILL");
    };
    const consume = (target) => (chunk) => {
      const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      total += value.byteLength;
      if (total > options.outputLimit) {
        stop();
        finish(() => reject(new SafeFailure("operation")));
        return;
      }
      target.push(value);
    };
    child.stdout.on("data", consume(stdout));
    child.stderr.on("data", consume(stderr));
    child.once("error", () => finish(() => reject(new SafeFailure("operation"))));
    child.once("close", (code, signal) => finish(() => resolve({
      code,
      signal,
      stdout: Buffer.concat(stdout).toString("utf8"),
      stderr: Buffer.concat(stderr).toString("utf8"),
    })));
    const timer = setTimeout(() => {
      stop();
      finish(() => reject(new SafeFailure("operation")));
    }, options.timeoutMs);
  });
}

export async function orchestrate({
  environment = process.env,
  spawnImplementation = spawn,
  runImplementation = runBounded,
  makeTemp = () => mkdtemp(join(tmpdir(), "zasp-m009-")),
  removeTemp = removeProofTemp,
} = {}) {
  const proofEnvironment = validateProofEnvironment(environment);
  const buildEnvironment = buildChildEnvironment(environment);
  let directory;
  let failure;
  try {
    directory = await makeTemp();
    if (typeof directory !== "string" || directory.length === 0) {
      throw new SafeFailure("operation");
    }
    const executable = join(directory, "proof");
    const build = await runImplementation("go", ["build", "-trimpath", "-mod=readonly", "-o", executable, "."], {
      cwd: proofDirectory, env: buildEnvironment, outputLimit, timeoutMs: 60_000,
    }, spawnImplementation);
    if (build.code !== 0 || build.signal !== null || build.stdout !== "" || build.stderr !== "") {
      throw new SafeFailure("operation");
    }
    const proof = await runImplementation(executable, [], {
      cwd: proofDirectory, env: proofEnvironment, outputLimit, timeoutMs: proofSupervisorTimeoutMs,
    }, spawnImplementation);
    if (proof.code !== 0 || proof.signal !== null || proof.stdout !== `${successLine}\n` || proof.stderr !== "") {
      const match = proof.stdout === "" && proof.signal === null
        ? proof.stderr.match(/^Real AWS IAM proof failed: (configuration|capability|authentication|authorization|ownership|operation|cleanup) rejected\.\n$/)
        : null;
      if (match !== null) throw new SafeFailure(match[1]);
      throw new SafeFailure("operation");
    }
  } catch (error) {
    failure = error instanceof SafeFailure ? error : new SafeFailure("operation");
  } finally {
    if (directory !== undefined) {
      try {
        await removeTemp(directory);
      } catch {
        failure = new SafeFailure("cleanup");
      }
    }
  }
  if (failure !== undefined) throw failure;
  return successLine;
}

export async function removeProofTemp(directory) {
  const prefix = join(tmpdir(), "zasp-m009-");
  if (typeof directory !== "string" || !directory.startsWith(prefix) || directory === prefix) {
    throw new SafeFailure("cleanup");
  }
  await rm(directory, { recursive: true, force: false, maxRetries: 0 });
}

export function fixedFailureLine(error) {
  const category = error instanceof SafeFailure && [
    "configuration", "capability", "authentication", "authorization", "ownership", "operation", "cleanup",
  ].includes(error.category) ? error.category : "operation";
  return `Real AWS IAM proof failed: ${category} rejected.`;
}

export async function runCLI({ environment = process.env, writeOut = process.stdout.write.bind(process.stdout), writeErr = process.stderr.write.bind(process.stderr), ...dependencies } = {}) {
  try {
    const line = await orchestrate({ environment, ...dependencies });
    writeOut(`${line}\n`);
    return 0;
  } catch (error) {
    writeErr(`${fixedFailureLine(error)}\n`);
    return 1;
  }
}

if (process.argv[1] !== undefined && pathToFileURL(process.argv[1]).href === import.meta.url) {
  process.exitCode = await runCLI();
}

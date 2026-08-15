import { spawnSync } from "node:child_process";
import { devNull } from "node:os";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const defaultRepositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const defaultTimeoutMilliseconds = 120_000;
const defaultMaxOutputBytes = 1_048_576;

export const successLine = "Repository build passed: targets=8\n";
export const failureLine = "Repository build rejected\n";

function requiredEnvironmentValue(environment, name) {
  const value = environment?.[name];
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error("invalid build environment");
  }
  return value;
}

function exactBaseEnvironment(environment) {
  return {
    PATH: requiredEnvironmentValue(environment, "PATH"),
    HOME: requiredEnvironmentValue(environment, "HOME"),
    LANG: typeof environment.LANG === "string" && environment.LANG.length > 0 && !environment.LANG.includes("\0")
      ? environment.LANG
      : "C.UTF-8",
  };
}

export function createBuildTargets({
  repositoryRoot = defaultRepositoryRoot,
  environment = process.env,
  nodeExecutable = process.execPath,
  nullDevice = devNull,
} = {}) {
  if (typeof repositoryRoot !== "string" || !isAbsolute(repositoryRoot) || repositoryRoot.includes("\0")) {
    throw new Error("invalid repository root");
  }
  if (typeof nodeExecutable !== "string" || nodeExecutable.length === 0 || nodeExecutable.includes("\0")) {
    throw new Error("invalid node executable");
  }
  if (typeof nullDevice !== "string" || nullDevice.length === 0 || nullDevice.includes("\0")) {
    throw new Error("invalid null device");
  }

  const base = exactBaseEnvironment(environment);
  const goEnvironment = {
    ...base,
    GOENV: "off",
    GOTOOLCHAIN: "local",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOWORK: "off",
    CGO_ENABLED: "0",
  };
  const pythonEnvironment = {
    ...base,
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONUNBUFFERED: "1",
    PYTHONPATH: resolve(repositoryRoot, "workers/security-python"),
  };
  const webEnvironment = {
    ...base,
    NPM_CONFIG_AUDIT: "false",
    NPM_CONFIG_FUND: "false",
    NPM_CONFIG_OFFLINE: "true",
    NPM_CONFIG_UPDATE_NOTIFIER: "false",
  };
  const target = (name, command, args, targetEnvironment, expectedStdout, expectedStderr) => ({
    name,
    command,
    args,
    cwd: repositoryRoot,
    environment: targetEnvironment,
    timeoutMilliseconds: defaultTimeoutMilliseconds,
    maxOutputBytes: defaultMaxOutputBytes,
    expectedStdout,
    expectedStderr,
  });

  return [
    target("agentsec-api", "go", ["-C", "services/platform", "build", "-trimpath", "-o", nullDevice, "./agentsec-api"], goEnvironment, "", ""),
    target("agentsec-worker", "go", ["-C", "services/platform", "build", "-trimpath", "-o", nullDevice, "./agentsec-worker"], goEnvironment, "", ""),
    target("event-ingest", "go", ["-C", "services/event-ingest", "build", "-trimpath", "-o", nullDevice, "."], goEnvironment, "", ""),
    target("runtime-gateway", "go", ["-C", "services/runtime-gateway", "build", "-trimpath", "-o", nullDevice, "."], goEnvironment, "", ""),
    target("security-python", "python3", ["-m", "security_worker", "health"], pythonEnvironment, "security-worker health ok\n", ""),
    target("redteam-node", nodeExecutable, ["workers/redteam-node/health.mjs", "health"], base, "redteam-worker health ok\n", ""),
    target("web", "npm", ["--prefix", "apps/web", "run", "build"], webEnvironment),
    target("agentsecctl", "go", ["-C", "cmd/agentsecctl", "build", "-trimpath", "-o", nullDevice, "."], goEnvironment, "", ""),
  ];
}

function executeTarget(target) {
  return spawnSync(target.command, target.args, {
    cwd: target.cwd,
    env: target.environment,
    encoding: "utf8",
    timeout: target.timeoutMilliseconds,
    killSignal: "SIGKILL",
    maxBuffer: target.maxOutputBytes,
    windowsHide: true,
  });
}

function requireSuccessfulResult(target, result) {
  if (!result || typeof result !== "object") {
    throw new Error("invalid build result");
  }
  const { error, status, signal, stdout, stderr } = result;
  if (typeof stdout !== "string" || typeof stderr !== "string") {
    throw new Error("invalid build output");
  }
  if (Buffer.byteLength(stdout) > target.maxOutputBytes || Buffer.byteLength(stderr) > target.maxOutputBytes) {
    throw new Error("build output exceeded limit");
  }
  if (error !== undefined || status !== 0 || signal !== null) {
    throw new Error("build target rejected");
  }
  if (target.expectedStdout !== undefined && stdout !== target.expectedStdout) {
    throw new Error("unexpected build stdout");
  }
  if (target.expectedStderr !== undefined && stderr !== target.expectedStderr) {
    throw new Error("unexpected build stderr");
  }
}

export function buildRepository(options = {}) {
  const execute = options.execute ?? executeTarget;
  if (typeof execute !== "function") {
    throw new Error("invalid build executor");
  }
  const targets = createBuildTargets(options);
  for (const target of targets) {
    requireSuccessfulResult(target, execute(target));
  }
  return targets.length;
}

function writeFixed(stream, line) {
  if (!stream || typeof stream.write !== "function" || stream.write(line) === false) {
    throw new Error("build output unavailable");
  }
}

export function runMain({
  arguments: arguments_ = process.argv.slice(2),
  stdout = process.stdout,
  stderr = process.stderr,
  runtime,
} = {}) {
  try {
    if (!Array.isArray(arguments_) || arguments_.length !== 0) {
      throw new Error("invalid build arguments");
    }
    buildRepository(runtime);
    writeFixed(stdout, successLine);
    return 0;
  } catch {
    try {
      writeFixed(stderr, failureLine);
    } catch {
      // The fixed process exit remains nonzero when no output sink is available.
    }
    return 1;
  }
}

const entryUrl = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (entryUrl === import.meta.url) {
  process.exitCode = runMain();
}

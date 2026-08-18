import { spawnSync } from "node:child_process";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const defaultRepositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const defaultTimeoutMilliseconds = 120_000;
const defaultMaxOutputBytes = 1_048_576;

export const successLine = "M1 schema check passed: targets=5\n";
export const failureLine = "M1 schema check rejected\n";

function requiredEnvironmentValue(environment, name) {
  const value = environment?.[name];
  if (typeof value !== "string" || value.length === 0 || value.includes("\0")) {
    throw new Error("invalid schema-check environment");
  }
  return value;
}

function exactGoEnvironment(environment) {
  return {
    PATH: requiredEnvironmentValue(environment, "PATH"),
    HOME: requiredEnvironmentValue(environment, "HOME"),
    LANG: typeof environment.LANG === "string" && environment.LANG.length > 0 && !environment.LANG.includes("\0")
      ? environment.LANG
      : "C.UTF-8",
    GOENV: "off",
    GOTOOLCHAIN: "local",
    GOPROXY: "off",
    GOSUMDB: "off",
    GOWORK: "off",
  };
}

export function createSchemaTargets({
  repositoryRoot = defaultRepositoryRoot,
  environment = process.env,
} = {}) {
  if (typeof repositoryRoot !== "string" || !isAbsolute(repositoryRoot) || repositoryRoot.includes("\0")) {
    throw new Error("invalid repository root");
  }
  const goEnvironment = exactGoEnvironment(environment);
  const target = (name, packagePath) => ({
    name,
    command: "go",
    args: ["-C", "services/platform", "test", "-race", "-count=1", packagePath],
    cwd: repositoryRoot,
    environment: goEnvironment,
    timeoutMilliseconds: defaultTimeoutMilliseconds,
    maxOutputBytes: defaultMaxOutputBytes,
  });

  return [
    target("database-migrations", "./migrations"),
    target("canonical-domain", "./domain"),
    target("security-event", "./securityevent"),
    target("event-index-template", "./eventindex"),
    target("queue-message-schemas", "./queuedefinition"),
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
    throw new Error("invalid schema-check result");
  }
  const { error, status, signal, stdout, stderr } = result;
  if (typeof stdout !== "string" || typeof stderr !== "string") {
    throw new Error("invalid schema-check output");
  }
  if (Buffer.byteLength(stdout) > target.maxOutputBytes || Buffer.byteLength(stderr) > target.maxOutputBytes) {
    throw new Error("schema-check output exceeded limit");
  }
  if (error !== undefined || status !== 0 || signal !== null) {
    throw new Error("schema-check target rejected");
  }
}

export function checkSchemas(options = {}) {
  const execute = options.execute ?? executeTarget;
  if (typeof execute !== "function") {
    throw new Error("invalid schema-check executor");
  }
  const targets = createSchemaTargets(options);
  for (const target of targets) {
    requireSuccessfulResult(target, execute(target));
  }
  return targets.length;
}

function writeFixed(stream, line) {
  if (!stream || typeof stream.write !== "function" || stream.write(line) === false) {
    throw new Error("schema-check output unavailable");
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
      throw new Error("invalid schema-check arguments");
    }
    checkSchemas(runtime);
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

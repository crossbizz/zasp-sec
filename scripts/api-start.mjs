import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnOwnedCommand } from "./owned-command.mjs";

// This developer launch boundary accepts only these credential aliases. The API
// retains its original full configuration and current-authorization validation.
export function apiEnvironment(environment) {
  const mapped = { ...environment, GOTOOLCHAIN: "local" };
  for (const suffix of ["PROJECT_ID", "SECRET", "PUBLIC_TOKEN"]) {
    const standard = `STYTCH_${suffix}`, alias = `ZASP_STYTCH_${suffix}`;
    const hasStandard = Object.hasOwn(environment, standard), hasAlias = Object.hasOwn(environment, alias);
    for (const key of [standard, alias]) {
      if (Object.hasOwn(environment, key) && (typeof environment[key] !== "string" || environment[key].trim() === "")) {
        throw new Error("API credential mapping refused");
      }
    }
    if (hasStandard && hasAlias && environment[standard] !== environment[alias]) throw new Error("API credential mapping refused");
    if (hasStandard && !hasAlias) mapped[alias] = environment[standard];
  }
  return mapped;
}

export async function runAPI(environment, signals = process) {
  const env = apiEnvironment(environment);
  const command = spawnOwnedCommand("go", ["run", "-mod=readonly", "./agentsec-api"], {
    cwd: path.resolve(fileURLToPath(new URL("../services/platform", import.meta.url))),
    env, maxOutputBytes: 262144,
  });
  let requestedSignal, stopping, stopFailure;
  const stop = () => stopping ??= command.stop();
  const handlers = new Map(["SIGINT", "SIGTERM", "SIGHUP"].map(name => [name, () => {
    requestedSignal ??= name;
    void stop().catch(() => { stopFailure = true; });
  }]));
  for (const [name, handler] of handlers) signals.on(name, handler);
  try {
    const result = await command.completed;
    if (result.outputLimitExceeded) throw new Error("API launch refused");
    if (stopFailure) throw new Error("API launch refused");
    return { status: result.status, signal: requestedSignal ?? result.signal };
  } finally {
    try { await stop(); } finally {
      for (const [name, handler] of handlers) signals.removeListener(name, handler);
    }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 2) throw new Error("API launch refused");
    const result = await runAPI(process.env);
    if (result.signal) process.kill(process.pid, result.signal);
    else process.exitCode = result.status;
  } catch {
    process.stderr.write("API launch refused\n");
    process.exitCode = 1;
  }
}

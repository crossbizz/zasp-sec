import { execFileSync } from "node:child_process";
import { accessSync, constants, statSync } from "node:fs";
import path from "node:path";

const controls = /\p{Cc}/u;

function absolutePath(file, label) {
  if (typeof file !== "string" || !file || !path.isAbsolute(file) || controls.test(file)) {
    throw new Error(`${label} requires a nonempty absolute path without control characters`);
  }
}

function executableFile(file, label) {
  absolutePath(file, label);
  try {
    if (!statSync(file).isFile()) throw new Error("not a regular file");
    accessSync(file, constants.X_OK);
  } catch (cause) {
    throw new Error(`${label} must be an executable regular file: ${file}`, { cause });
  }
  return file;
}

function findExecutable(names, env, label, validate = executableFile) {
  // Do not search the working directory through empty/relative PATH entries.
  for (const name of names) {
    for (const directory of (env.PATH ?? "").split(path.delimiter)) {
      if (!path.isAbsolute(directory) || controls.test(directory)) continue;
      const candidate = path.join(directory, name);
      try { validate(candidate, label); return candidate; } catch { /* Try the next installed candidate. */ }
    }
  }
  throw new Error(`${label} not found as an executable regular file on PATH (${names.join(", ")})`);
}

export function selectBrowserExecutable({ platform = process.platform, env = process.env, validate = executableFile } = {}) {
  if (Object.hasOwn(env, "ZASP_COMBINED_E2E_CHROME")) {
    const explicit = env.ZASP_COMBINED_E2E_CHROME;
    absolutePath(explicit, "browser ZASP_COMBINED_E2E_CHROME");
    validate(explicit, "browser ZASP_COMBINED_E2E_CHROME");
    return explicit;
  }
  if (platform === "darwin") {
    const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
    validate(chrome, "browser Chrome");
    return chrome;
  }
  if (platform === "linux") return findExecutable(["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"], env, "browser Chrome", validate);
  throw new Error(`browser requires ZASP_COMBINED_E2E_CHROME on unsupported platform ${platform}`);
}

// Setup cannot create databases, compile Go, or allocate owned resources until
// every prerequisite has passed. This never installs tools or pulls images.
export async function withBrowserPrerequisites({ root, env = process.env, platform = process.platform }, setup) {
  const chrome = selectBrowserExecutable({ env, platform });
  for (const name of ["go", "docker", "openssl"]) findExecutable([name], env, `required tool ${name}`);
  const pgConfig = findExecutable(["pg_config"], env, "required tool pg_config");
  let postgresBin;
  try {
    postgresBin = execFileSync(pgConfig, ["--bindir"], { env, encoding: "utf8", timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096, stdio: ["ignore", "pipe", "pipe"] }).trim();
  } catch (cause) {
    throw new Error("required tool pg_config --bindir failed", { cause });
  }
  absolutePath(postgresBin, "PostgreSQL binary directory from pg_config");
  executableFile(path.join(postgresBin, "psql"), "required tool psql");
  executableFile(path.join(root, "node_modules/.bin/vinext"), "required tool node_modules/.bin/vinext");
  const compiledUI = path.join(root, "dist/server/index.js");
  try {
    if (!statSync(compiledUI).isFile()) throw new Error("not a regular file");
    accessSync(compiledUI, constants.R_OK);
  } catch (cause) {
    throw new Error(`required compiled UI dist/server/index.js unavailable; run npm run build first: ${compiledUI}`, { cause });
  }
  return setup({ chrome, postgresBin });
}

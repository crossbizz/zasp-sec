#!/usr/bin/env node
// Runs the Fern CLI at the version pinned in fern/fern.config.json.
//
//   node fern/scripts/fern.mjs check
//   node fern/scripts/fern.mjs generate --docs --preview
//
// The CLI is fetched with npx and is not a dependency of this repository.
//
// Token: the CLI reads FERN_TOKEN. If only FERN_API_KEY is set, its value is
// passed on as FERN_TOKEN. The token is never printed and never written to a
// file. `fern check` needs no token.
//
// Proxy: when HTTPS_PROXY is set and the package `undici` can be resolved,
// proxy-preload.cjs is added to NODE_OPTIONS so that the CLI's fetch goes
// through the proxy. See "Behind an HTTP proxy" in fern/README.md.

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");

// The preload is used only when it can do its work: a proxy is configured and
// undici resolves from the repository root, from this directory or NODE_PATH.
function proxyPreload(env) {
  if (!env.HTTPS_PROXY && !env.https_proxy) return undefined;
  try {
    createRequire(join(here, "proxy-preload.cjs")).resolve("undici", { paths: [root, here] });
  } catch {
    return undefined;
  }
  return join(here, "proxy-preload.cjs");
}

export function runFern(args, options = {}) {
  const { version } = JSON.parse(readFileSync(join(root, "fern", "fern.config.json"), "utf8"));
  const env = { ...process.env };
  if (!env.FERN_TOKEN && env.FERN_API_KEY) env.FERN_TOKEN = env.FERN_API_KEY;
  const preload = proxyPreload(env);
  if (preload) env.NODE_OPTIONS = `${env.NODE_OPTIONS ?? ""} --require ${JSON.stringify(preload)}`.trim();
  const result = spawnSync("npx", ["--yes", `fern-api@${version}`, ...args], { cwd: root, env, stdio: "inherit", ...options });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(runFern(process.argv.slice(2)));
}

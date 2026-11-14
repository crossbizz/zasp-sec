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

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

export function runFern(args, options = {}) {
  const { version } = JSON.parse(readFileSync(join(root, "fern", "fern.config.json"), "utf8"));
  const env = { ...process.env };
  if (!env.FERN_TOKEN && env.FERN_API_KEY) env.FERN_TOKEN = env.FERN_API_KEY;
  const result = spawnSync("npx", ["--yes", `fern-api@${version}`, ...args], { cwd: root, env, stdio: "inherit", ...options });
  if (result.error) throw result.error;
  return result.status ?? 1;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  process.exit(runFern(process.argv.slice(2)));
}

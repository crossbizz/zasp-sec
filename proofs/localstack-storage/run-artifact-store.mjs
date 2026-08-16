import { fileURLToPath } from "node:url";

import { ARTIFACT_MODE, runMain } from "./run.mjs";

export async function artifactRunMain(options = {}) {
  return runMain({ ...options, mode: ARTIFACT_MODE });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await artifactRunMain();

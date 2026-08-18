import { fileURLToPath } from "node:url";

import { QUEUE_DEFINITIONS_MODE, runMain } from "../localstack-storage/run.mjs";

export async function runQueueDefinitionsMain(options = {}) {
  return runMain({ ...options, mode: QUEUE_DEFINITIONS_MODE });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await runQueueDefinitionsMain();

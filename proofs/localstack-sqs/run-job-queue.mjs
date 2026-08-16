import { fileURLToPath } from "node:url";

import { JOB_QUEUE_MODE, runMain } from "../localstack-storage/run.mjs";

export async function runJobQueueMain(options = {}) {
  return runMain({ ...options, mode: JOB_QUEUE_MODE });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await runJobQueueMain();

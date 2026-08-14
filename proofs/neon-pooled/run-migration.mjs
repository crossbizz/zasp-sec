import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const proofDirectory = fileURLToPath(new URL(".", import.meta.url));
const result = spawnSync("go", ["run", ".", "migration"], {
  cwd: proofDirectory,
  env: process.env,
  stdio: "inherit",
});

process.exit(Number.isInteger(result.status) ? result.status : 1);

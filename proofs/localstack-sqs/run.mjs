import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const goArguments = process.argv[2] === "audit" ? ["run", ".", "audit"] : ["run", "."];
const result = spawnSync("go", goArguments, {
  cwd: fileURLToPath(new URL(".", import.meta.url)),
  env: {
    AWS_ENDPOINT_URL: process.env.AWS_ENDPOINT_URL,
    HOME: process.env.HOME,
    PATH: process.env.PATH,
  },
  stdio: "inherit",
});

process.exit(Number.isInteger(result.status) ? result.status : 1);

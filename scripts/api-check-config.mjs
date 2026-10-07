import path from "node:path";
import { pathToFileURL } from "node:url";
import { runAPIConfigurationCheck } from "./api-start.mjs";

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 2) throw new Error("API configuration check refused");
    const result = await runAPIConfigurationCheck(process.env);
    if (result.signal) process.kill(process.pid, result.signal);
    else {
      process.stdout.write(result.status === 0
        ? "API configuration syntax accepted; runtime access and production readiness are unverified.\n"
        : "API configuration syntax refused.\n");
      process.exitCode = result.status;
    }
  } catch {
    process.stderr.write("API configuration check refused\n");
    process.exitCode = 1;
  }
}

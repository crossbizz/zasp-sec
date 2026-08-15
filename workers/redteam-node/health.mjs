import { pathToFileURL } from "node:url";

export function run(arguments_, output) {
  if (arguments_.length !== 1 || arguments_[0] !== "health") {
    return 2;
  }
  output.write("redteam-worker health ok\n");
  return 0;
}

export function main(arguments_ = process.argv.slice(2), output = process.stdout) {
  try {
    return run(arguments_, output);
  } catch {
    return 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main();
}

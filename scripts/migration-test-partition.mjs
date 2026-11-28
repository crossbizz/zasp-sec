import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { pathToFileURL } from "node:url";

const prefix = "^TestTemporalDiscovery";
const reserved = prefix + "(Continuation|ShippedRuntime|TenantIsolation)Postgres$";
const options = {
  continuation: ["-timeout=70m", "-run", prefix + "ContinuationPostgres$"],
  "discovery-long": ["-timeout=45m", "-run", prefix + "(ShippedRuntime|TenantIsolation)Postgres$"],
  discovery: ["-timeout=65m", "-run", prefix, "-skip", reserved],
  remaining: ["-timeout=90m", "-skip", prefix],
};

export const migrationTestCommands = Object.freeze(Object.fromEntries(
  Object.entries(options).map(([lane, flags]) => [lane, Object.freeze([
    "go", "test", "-C", "services/platform", "-race", "-count=1", ...flags, "./agentsec-migrate",
  ])]),
));

export function migrationTestCensus(output) {
  const lines = output.trimEnd().split("\n");
  assert.match(lines.pop(), /^ok\s+github\.com\/zasp-ai\/zasp-sec\/services\/platform\/agentsec-migrate\s+\d+(?:\.\d+)?s(?:\s+.*)?$/);
  assert.equal(new Set(lines).size, lines.length, "duplicate Go test inventory");
  const counts = Object.fromEntries(Object.keys(options).map(lane => [lane, 0]));
  for (const name of lines) {
    assert.match(name, /^(?:Test|Example|Fuzz)[\p{L}\p{N}_]*$/u);
    const selected = Object.entries(options).filter(([, flags]) => {
      const matches = (flag, fallback) => {
        const index = flags.indexOf(flag);
        return index < 0 ? fallback : new RegExp(flags[index + 1]).test(name);
      };
      return matches("-run", true) && !matches("-skip", false);
    });
    assert.equal(selected.length, 1, `expected one migration lane for ${name}`);
    counts[selected[0][0]]++;
  }
  assert.equal(counts.continuation, 1, "missing standalone continuation test");
  assert.equal(counts["discovery-long"], 2, "long discovery cases changed");
  assert.ok(counts.discovery > 0 && counts.remaining > 0, "empty migration lane");
  return counts;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const inventory = execFileSync("go", [
    "test", "-C", "services/platform", "-race", "-count=1", "-list", "^(Test|Fuzz|Example)", "./agentsec-migrate",
  ], { encoding: "utf8", timeout: 18 * 60_000, maxBuffer: 4 * 1024 * 1024 });
  console.log("Migration cases per runner", migrationTestCensus(inventory));
}

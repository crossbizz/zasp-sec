import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const exec = promisify(execFile);

describe("M3 connector and sensor implementation batch", () => {
  it("keeps Nango private, pinned, bounded, and secret-referenced", async () => {
    const { stdout } = await exec(process.execPath, [
      "--test",
      "--test-reporter=tap",
      "--test-name-pattern=production release renders private Nango",
      "deploy/production/release-contract.test.mjs",
    ], { cwd: root, encoding: "utf8" });

    expect(stdout).toMatch(/# pass 1\n/);
    expect(stdout).toMatch(/# fail 0\n/);
  });

  it("publishes all seven sensor operations without credential internals", async () => {
    const openapi = await readFile(resolve(root, "openapi/openapi.yaml"), "utf8");
    const operations = [
      "listSensors", "createSensorEnrollment", "getSensor", "updateSensor",
      "deleteSensor", "rotateSensorToken", "getSensorCoverage",
    ];
    for (const operation of operations) expect(openapi).toContain(`operationId: ${operation}`);
    expect(openapi).not.toMatch(/token_hash|raw_credential|nango_connection_id/i);
  });

  it("records the 24-task batch as active behind the real-AWS gate", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toContain("| M3 | 75 | 0 | 0 | 73 | 2 |");
    const blocked = tracker.match(/## Blocked[\s\S]*/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    expect(blocked.match(/^\| M3-14 \|/gm)).toHaveLength(1);
    for (const task of ["M3-15", "M3-16", "M3-17", "M3-18", "M3-19", "M3-20", "M3-21", "M3-22a", "M3-22b", "M3-22c", "M3-22", "M3-23", "M3-24", "M3-25", "M3-26", "M3-27", "M3-28", "M3-29", "M3-30", "M3-31", "M3-32", "M3-33", "M3-34"]) {
      expect(complete.match(new RegExp(`^\\| ${task.replace("-", "\\-")} \\|`, "gm"))).toHaveLength(1);
    }
    expect(readme).toContain("M3-15 through M3-36 are Complete");
    expect(readme).toContain("required real-AWS denial fixture is unavailable");
  });
});

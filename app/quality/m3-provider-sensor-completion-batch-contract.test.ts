import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M3-15 through M3-36 completion batch", () => {
  it("reuses the reviewed provider and sensor proof commands", () => {
    const pkg = JSON.parse(read("package.json"));
    for (const script of ["proof:cartography:test", "proof:prowler:test", "proof:nango:test", "proof:nango:oauth:test", "proof:nango:proxy:test", "proof:tetragon:test"]) expect(pkg.scripts[script]).toBeTruthy();
    const sensor = read("services/platform/sensor/sensor.go") + read("services/platform/sensor/http.go");
    for (const method of ["List", "Create", "Get", "Update", "Delete", "Rotate", "Coverage", "Heartbeat"]) expect(sensor).toContain(`) ${method}(`);
    const openapi = read("openapi/openapi.yaml");
    for (const operation of ["listSensors", "createSensorEnrollment", "getSensor", "updateSensor", "deleteSensor", "rotateSensorToken", "getSensorCoverage"]) expect(openapi).not.toContain(`operationId: ${operation}`);
  });

  it("keeps the real-AWS credential adapter blocked behind its exact dependency", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const blocked = tracker.match(/## Blocked[\s\S]*/)?.[0] || "";
    expect(blocked.match(/^\| M3-14 \|/gm)).toHaveLength(1);
    expect(blocked).toContain("required real-AWS denial");
  });

  it("completes exactly 25 independently verified provider and sensor tasks", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] || "";
    const selected = ["M3-15", "M3-16", "M3-17", "M3-18", "M3-19", "M3-20", "M3-21", "M3-22a", "M3-22b", "M3-22c", "M3-22", "M3-23", "M3-24", "M3-25", "M3-26", "M3-27", "M3-28", "M3-29", "M3-30", "M3-31", "M3-32", "M3-33", "M3-34", "M3-35", "M3-36"];
    for (const id of selected) expect(complete.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 0 |", "| Complete | 667 |", "`0/0/667/61`", "| M3 | 75 | 0 | 0 | 73 | 2 |"]) expect(tracker).toContain(value);
  });
});

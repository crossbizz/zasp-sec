import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("M3 connector and sensor implementation batch", () => {
  it("keeps Nango private, pinned, bounded, and secret-referenced", async () => {
    const manifest = await readFile(resolve(root, "deploy/staging/nango/manifest.yaml"), "utf8");
    expect(manifest).toContain("nangohq/nango-server:hosted-7faf2c303bbb0322333f526e9ca31c0fe95ef58e@sha256:b191d8d5b072fec5984e28da67298e9dabd5dc3a2585f1ebff7e2f5b9dfb66ed");
    expect(manifest).toContain("type: ClusterIP");
    expect(manifest).not.toMatch(/kind: (?:Ingress|LoadBalancer)/);
    expect(manifest).toContain('NANGO_ENABLED_FEATURES, value: "auth,proxy"');
    expect(manifest).toContain('NANGO_FUNCTIONS_ENABLED, value: "false"');
    expect(manifest).toContain('NANGO_WEBHOOKS_ENABLED, value: "false"');
    expect(manifest).toContain('NANGO_MCP_ENABLED, value: "false"');
    expect(manifest.match(/secretKeyRef:/g)).toHaveLength(2);
    expect(manifest).toContain("readOnlyRootFilesystem: true");
  });

  it("publishes exactly seven sensor product operations", async () => {
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
    expect(tracker).toMatch(/^\| M3 \| 75 \| \d+ \| \d+ \| \d+ \| 0 \|/m);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    expect(active.match(/^\| M3-14 \|/gm)).toHaveLength(1);
    for (const task of ["M3-15", "M3-16", "M3-17", "M3-18", "M3-19", "M3-20", "M3-21", "M3-22a", "M3-22b", "M3-22c", "M3-22", "M3-23", "M3-24", "M3-25", "M3-26", "M3-27", "M3-28", "M3-29", "M3-30", "M3-31", "M3-32", "M3-33", "M3-34"]) {
      expect(complete.match(new RegExp(`^\\| ${task.replace("-", "\\-")} \\|`, "gm"))).toHaveLength(1);
    }
    expect(readme).toContain("M3-15 through M3-36 are Complete");
    expect(readme).toContain("required real-AWS denial fixture is unavailable");
  });
});

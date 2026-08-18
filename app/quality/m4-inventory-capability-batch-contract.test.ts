import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const operations = ["listAgents", "getAgent", "updateAgent", "getAgentCapabilities", "getAgentRelationships", "listAgentSessions", "listTools", "getTool", "listIdentities", "getIdentity", "listRuntimes", "getRuntime", "getAsset"];

describe("M4 inventory, capability, and posture batch", () => {
  it("publishes all thirteen inventory operations in OpenAPI and generated client", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of operations) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("binds six capability categories and four evidence-backed posture rules", async () => {
    const source = await readFile(resolve(root, "services/platform/reconciliation/capability.go"), "utf8");
    for (const value of ["data_read", "data_write", "action_execute", "identity_assume", "network_egress", "administration", "reachable", "observed", "verified", "blocked"]) expect(source).toContain(value);
    for (const value of ["ownerless_agent", "human_credential", "shared_credential", "untrusted_production_write"]) expect(source).toContain(value);
    expect(source).toContain("EvidenceAttackLab");
    expect(source).toContain("EvidenceRuntimePolicy");
  });

  it("moves exactly the twenty-two local tasks to In progress without claiming Neon", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toContain("| Complete | 259 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("| M4 | 82 | 0 | 66 | 16 | 0 |");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (let index = 2; index <= 10; index += 1) expect(complete.match(new RegExp(`^\\| M4-${String(index).padStart(2, "0")} \\|`, "gm"))).toHaveLength(1);
    const tasks = Array.from({ length: 13 }, (_, index) => `M4-${String(index + 11).padStart(2, "0")}`);
    expect(tasks).toHaveLength(13);
    for (const task of tasks) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-11 through M4-23 remain batched as In progress");
    expect(prose).toContain("make no Neon, live-provider, staging, or release-gate claim");
  });
});

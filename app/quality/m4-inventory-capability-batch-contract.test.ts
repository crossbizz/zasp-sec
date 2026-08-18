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
    for (const value of ["| Pending | 451 |", "| In progress | 90 |", "| Complete | 184 |", "| Blocked | 3 |", "`451/90/184/3`", "| M4 | 82 | 53 | 29 | 0 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const tasks = Array.from({ length: 22 }, (_, index) => `M4-${String(index + 2).padStart(2, "0")}`);
    expect(tasks).toHaveLength(22);
    for (const task of tasks) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-02 through M4-23 are batched as In progress");
    expect(prose).toContain("make no Neon, live-provider, staging, or release-gate claim");
  });
});

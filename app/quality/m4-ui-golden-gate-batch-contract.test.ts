import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("M4 UI and golden-gate batch", () => {
  it("wires production inventory and risk routes without importing demo actions", async () => {
    const [app, productionView, riskView, globalSearch] = await Promise.all([
      readFile(resolve(root, "app/components/ZaspProductionApp.tsx"), "utf8"),
      readFile(resolve(root, "app/features/agents/ProductionAgentSecurityView.tsx"), "utf8"),
      readFile(resolve(root, "app/features/risk/ProductionRiskView.tsx"), "utf8"),
      readFile(resolve(root, "app/components/ProductionGlobalSearch.tsx"), "utf8"),
    ]);
    expect(app).toContain("<ProductionAgentSecurityView");
    expect(app).toContain("<ProductionRiskView");
    for (const route of ["/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes", "/violations", "/exposure/attack-paths"]) expect(app).toContain(route);
    for (const operation of ["listAgents", "getAgent", "updateAgent", "getAgentCapabilities", "getAgentRelationships", "listAgentSessions", "getHomeSummary"]) expect(productionView).toContain(operation);
    for (const operation of ["updateFinding", "acceptFindingRisk", "createFindingTicket", "getAttackPathBreakOptions"]) expect(riskView).toContain(operation);
    expect(app).toContain("<ProductionGlobalSearch");
    expect(globalSearch).toContain("/api/v1/search");
    expect(riskView).toContain("Retry retained ticket creation");
    for (const heading of ["Why", "Evidence", "Path", "Fix", "Verify"]) expect(riskView).toContain(heading);
    for (const heading of ["Effective capabilities", "Runtime policy coverage"]) expect(productionView).toContain(heading);
  });

  it("implements one coherent five-stage local M4 gate", async () => {
    const source = await readFile(resolve(root, "services/platform/m4gate/m4gate.go"), "utf8");
    for (const value of ["Inventory", "Capability", "Posture", "AttackPath", "ExposureUX", 'Status: "PASS"', "Checks: 5"]) expect(source).toContain(value);
  });

  it("records the complete Agent Security UI and golden-gate slice", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    for (const value of ["| Pending | 0 |", "| In progress | 0 |", "| Complete | 667 |", "| Blocked | 61 |", "`0/0/667/61`", "| M4 | 82 | 0 | 0 | 82 | 0 |"]) expect(tracker).toContain(value);
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    const completed = ["M4-50a", "M4-50b1", "M4-50b2", "M4-50b3", "M4-50c", "M4-50", "M4-51a", "M4-51b1", "M4-51b2", "M4-51b3", "M4-51c", "M4-51d", "M4-51e", "M4-51", "M4-52", "M4-53", "M4-54", "M4-55", "M4-56", "M4-57", "M4-58", "M4-59a", "M4-59b", "M4-59c", "M4-59d", "M4-59e", "M4-59"];
    expect(completed).toHaveLength(27);
    for (const task of completed) expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-51d through M4-59 are Complete");
    expect(prose).toContain("live third-party webhook delivery remains an external evidence gate");
  });
});

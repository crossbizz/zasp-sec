import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("M4 UI and golden-gate batch", () => {
  it("wires the seven product routes to one generated-schema Agent Security surface", async () => {
    const [app, view] = await Promise.all([
      readFile(resolve(root, "app/components/ZaspApp.tsx"), "utf8"),
      readFile(resolve(root, "app/features/agents/AgentSecurityView.tsx"), "utf8"),
    ]);
    expect(app).toContain("<AgentSecurityView");
    for (const route of ["/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes", "/violations", "/exposure/attack-paths"]) expect(app).toContain(route);
    for (const operation of ["listAgents", "getAgent", "updateAgent", "getAgentCapabilities", "getAgentRelationships", "listAgentSessions", "listFindings", "updateFinding", "acceptFindingRisk", "createFindingTicket", "listAttackPaths", "getAttackPathBreakOptions", "getHomeSummary"]) expect(view).toContain(operation);
    for (const heading of ["Why", "Evidence", "Path", "Fix", "Verify", "Effective capabilities", "Runtime policy coverage"]) expect(view).toContain(heading);
  });

  it("implements one coherent five-stage local M4 gate", async () => {
    const source = await readFile(resolve(root, "services/platform/m4gate/m4gate.go"), "utf8");
    for (const value of ["Inventory", "Capability", "Posture", "AttackPath", "ExposureUX", 'Status: "PASS"', "Checks: 5"]) expect(source).toContain(value);
  });

  it("moves exactly twenty-seven related UI and golden-gate tasks to In progress", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    for (const value of ["| Pending | 369 |", "| In progress | 172 |", "| Complete | 184 |", "| Blocked | 3 |", "`369/172/184/3`", "| M4 | 82 | 0 | 82 | 0 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const tasks = ["M4-50a", "M4-50b1", "M4-50b2", "M4-50b3", "M4-50c", "M4-50", "M4-51a", "M4-51b1", "M4-51b2", "M4-51b3", "M4-51c", "M4-51d", "M4-51e", "M4-51", "M4-52", "M4-53", "M4-54", "M4-55", "M4-56", "M4-57", "M4-58", "M4-59a", "M4-59b", "M4-59c", "M4-59d", "M4-59e", "M4-59"];
    expect(tasks).toHaveLength(27);
    for (const task of tasks) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-50a through M4-59 are batched as In progress");
    expect(prose).toContain("not Neon, provider, staging, external webhook, or release-gate evidence");
  });
});

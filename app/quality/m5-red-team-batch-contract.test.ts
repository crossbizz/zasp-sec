import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => fs.readFileSync(path.join(root, file), "utf8");

describe("M5 red-team and safe Attack Lab batch", () => {
  it("publishes all eight tenant-scoped Red Team operations through the strict contract", () => {
    const openapi = read("openapi/openapi.yaml");
    for (const operation of ["listTests", "createTest", "getTest", "updateTest", "runTest", "listTestRuns", "getTestRun", "cancelTestRun"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
    }
    const api = read("app/features/redteam/api.ts");
    for (const path of ["/api/v1/tests", "/api/v1/tests/{id}", "/api/v1/tests/{id}/runs", "/api/v1/test-runs", "/api/v1/test-runs/{id}", "/api/v1/test-runs/{id}/cancel"]) expect(api).toContain(path);
  });

  it("implements normalized tests, safety, queue, artifacts, sandbox, canary, and evidence", () => {
    const source = read("services/platform/redteam/redteam.go");
    for (const symbol of ["NormalizePromptfoo", "SelectCuratedPacks", "TestSafetyPreflight", "NewWorker", "SandboxProvider", "BuildFargateSpec", "SignEgressToken", "AttackLabPreflight", "BuildCanary", "CollectAttackLabEvidence"]) {
      expect(source).toContain(` ${symbol}`);
    }
  });

  it("mounts the production Red Team list, wizard, runs, evidence, and bounded verification affordance", () => {
    const app = read("app/components/ZaspProductionApp.tsx");
    const source = read("app/features/redteam/ProductionRedTeamView.tsx");
    for (const text of ["/red-team/results", "red-team.read", "red-team.write", "ProductionRedTeamView"]) expect(app).toContain(text);
    for (const text of ["Create Red Team test", "Curated categories", "Immutable evidence", "Cancel run", "/test/attack-lab"]) expect(source).toContain(text);
    for (const forbidden of ["custom_prompt", "target_url", "shell_command", "production_write"]) expect(source).not.toContain(forbidden);
  });

  it("records the nine-task foundation complete without claiming provider completion", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    expect(tracker).toContain("| Pending | 0 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| M5 | 42 | 0 | 0 | 42 | 0 |");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (let index = 1; index <= 9; index += 1) {
      const task = `M5-${String(index).padStart(2, "0")}`;
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
  });
});

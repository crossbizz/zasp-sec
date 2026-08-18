import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

const root = process.cwd();
const read = (file: string) => fs.readFileSync(path.join(root, file), "utf8");

describe("M5 red-team and safe Attack Lab batch", () => {
  it("publishes the eight red-team operations through the strict contract", () => {
    const openapi = read("openapi/openapi.yaml");
    for (const operation of ["listTests", "createTest", "getTest", "updateTest", "runTest", "listTestRuns", "getTestRun", "cancelTestRun"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
    }
  });

  it("implements normalized tests, safety, queue, artifacts, sandbox, canary, and evidence", () => {
    const source = read("services/platform/redteam/redteam.go");
    for (const symbol of ["NormalizePromptfoo", "SelectCuratedPacks", "TestSafetyPreflight", "NewWorker", "SandboxProvider", "BuildFargateSpec", "SignEgressToken", "AttackLabPreflight", "BuildCanary", "CollectAttackLabEvidence"]) {
      expect(source).toContain(` ${symbol}`);
    }
  });

  it("keeps the existing Red Team list, wizard, results, and safe verification affordance", () => {
    const source = read("app/features/redteam/RedTeamViews.tsx");
    for (const text of ["Red team scans", "Run new scan", "Test suites", "Execution limits", "Red team results", "/test/attack-lab"]) expect(source).toContain(text);
  });

  it("records exactly the 29-task M5 batch without claiming provider completion", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    expect(tracker).toContain("| Pending | 191 |");
    expect(tracker).toContain("| In progress | 350 |");
    expect(tracker).toContain("| M5 | 42 | 0 | 42 | 0 | 0 |");
    for (const task of ["M5-01", "M5-12", "M5-17", "M5-23a", "M5-23d", "M5-23", "M5-25", "M5-26", "M5-35"]) expect(tracker).toMatch(new RegExp(`\\| ${task.replace("-", "\\-")} \\| August 18, 2026 \\|`));
  });
});

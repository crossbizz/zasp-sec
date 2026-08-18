import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M8-60 through M8-54 final release batch", () => {
  it("adds golden parity, onboarding, recovery, and release gates", () => {
    const source = read("cmd/agentsecctl/profiles.go");
    for (const symbol of [
      "InspectSaaSGoldenResult",
      "StartSingleTenantGolden",
      "InspectSingleTenantGolden",
      "EvaluateSaaSOnboarding",
      "ValidateSaaSRecoveryFixture",
      "StartSaaSRecovery",
      "InspectSaaSCoreRecovery",
      "StartSaaSDerivedRebuild",
      "EvaluateSaaSRecoveryObjectives",
      "EvaluateSaaSDRGate",
      "EvaluateM8ReleaseGate",
    ]) expect(source).toContain(`func ${symbol}`);
  });

  it("keeps live and human release evidence explicitly unresolved", () => {
    const readme = read("README.md");
    expect(readme).toContain("M8 release evidence remains open");
    expect(readme).toContain("live provider, human usability, and disaster-recovery runs");
  });

  it("advances the final 16 M8 tasks without claiming completion", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const selected = ["M8-60", "M8-61a", "M8-61", "M8-62a", "M8-62b", "M8-62c", "M8-62d", "M8-62e", "M8-62", "M8-63a", "M8-63b", "M8-63c", "M8-63d", "M8-63e", "M8-63", "M8-54"];
    for (const id of selected) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 122 |", "`0/122/603/3`", "| M8 | 141 | 0 | 116 | 25 | 0 |"]) expect(tracker).toContain(value);
  });
});

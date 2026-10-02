import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M1A-07 through M1A-10 staging gate batch", () => {
  it("adds the exact executable web/API deployment, evidence, and gate boundary", () => {
    const source = read("deploy/staging/gate.mjs");
    for (const symbol of ["buildStagingDeployment", "startStagingDeployment", "inspectStagingDeployment", "createStagingEvidence", "evaluateM1AGate"]) expect(source).toContain(`function ${symbol}`);
    for (const contract of ['name: "web"', 'name: "agentsec-api"', 'serviceAccount: "agentsec-web"', 'serviceAccount: "agentsec-api"', "perWorkloadIAM"]) expect(source).toContain(contract);
    for (const retired of ["runStagingDependencySmoke", "throughIRSA", "otlpHealthEmitted"]) expect(source).not.toContain(retired);
    const pkg = JSON.parse(read("package.json"));
    expect(pkg.scripts["staging:gate:test"]).toBe("node --test deploy/staging/gate.test.mjs deploy/staging/preflight.test.mjs");
  });

  it("blocks the final four staging tasks on the missing authorized AWS run", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const blocked = tracker.match(/## Blocked[\s\S]*/)?.[0] || "";
    for (const id of ["M1A-07", "M1A-08", "M1A-09", "M1A-10"]) {
      expect(active).not.toMatch(new RegExp(`^\\| ${id} \\|`, "m"));
      expect(blocked.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    }
    for (const value of ["| Pending | 0 |", "| In progress | 0 |", "| Complete | 667 |", "| Blocked | 61 |", "`0/0/667/61`", "| M1A | 10 | 0 | 0 | 6 | 4 |", "| M3 | 75 | 0 | 0 | 73 | 2 |"]) expect(tracker).toContain(value);
    expect(tracker).toContain("no authorized AWS staging execution");
  });
});

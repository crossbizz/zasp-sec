import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M1A-07 through M1A-10 staging gate batch", () => {
  it("adds one executable staging deploy, smoke, evidence, and gate boundary", () => {
    const source = read("deploy/staging/gate.mjs");
    for (const symbol of ["buildStagingDeployment", "startStagingDeployment", "inspectStagingDeployment", "runStagingDependencySmoke", "createStagingEvidence", "evaluateM1AGate"]) expect(source).toContain(`function ${symbol}`);
    const pkg = JSON.parse(read("package.json"));
    expect(pkg.scripts["staging:gate:test"]).toBe("node --test deploy/staging/gate.test.mjs");
  });

  it("moves only the final four pending tasks to honest active status", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    for (const id of ["M1A-07", "M1A-08", "M1A-09", "M1A-10"]) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 6 |", "`0/6/667/55`", "| M1A | 10 | 0 | 4 | 6 | 0 |"]) expect(tracker).toContain(value);
    expect(tracker).toContain("real AWS staging execution remains unresolved");
  });
});

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const operations = [
  "listFindings", "getFinding", "updateFinding", "acceptFindingRisk", "createFindingTicket",
  "listAttackPaths", "getAttackPath", "getAttackPathBreakOptions", "getHomeSummary", "globalSearch",
] as const;

describe("M4 risk, path, home, and search batch", () => {
  it("publishes ten generated product operations", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of operations) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("implements the remaining posture, finding, path, home, and safe-search boundaries", async () => {
    const source = (await Promise.all([
      readFile(resolve(root, "services/platform/reconciliation/capability.go"), "utf8"),
      readFile(resolve(root, "services/platform/reconciliation/risk.go"), "utf8"),
    ])).join("\n");
    for (const value of [
      "shell_credential", "egress_sensitive", "unapproved_tool", "destructive_no_control",
      "no_runtime_coverage", "weak_runtime_isolation", "cicd_production_secret", "zombie_credential",
      "VisibleByDefault", "RiskFactor", "AttackPath", "BreakOption", "HomeSummary", "SearchRecord",
    ]) expect(source).toContain(value);
    expect(source).toContain("hmac.New(sha256.New");
    expect(source).not.toContain("MATCH (n)");
  });

  it("records the full risk, path, Home, and search slice as Complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toContain("| Complete | 309 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("| M4 | 82 | 0 | 16 | 66 | 0 |");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    const completed = Array.from({ length: 26 }, (_, index) => `M4-${String(index + 24).padStart(2, "0")}`);
    for (const task of completed) expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    for (const task of completed) expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-36 through M4-50 and M4-51a through M4-51c are Complete");
    expect(prose).toContain("No external webhook delivery, Neon, provider, staging, or release-gate success is claimed");
  });
});

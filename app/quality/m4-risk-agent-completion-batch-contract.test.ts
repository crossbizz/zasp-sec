import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const selected = [
  ...Array.from({ length: 14 }, (_, index) => `M4-${String(index + 36).padStart(2, "0")}`),
  "M4-50a", "M4-50b1", "M4-50b2", "M4-50b3", "M4-50c", "M4-50",
  "M4-51a", "M4-51b1", "M4-51b2", "M4-51b3", "M4-51c",
];

describe("M4 risk and Agent UI completion batch", () => {
  it("keeps mounted risk and Home operations while hiding external actions", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of ["updateFinding", "acceptFindingRisk", "listAttackPaths", "getAttackPath", "getAttackPathBreakOptions", "getHomeSummary"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
    for (const operation of ["createFindingTicket", "globalSearch"]) {
      expect(openapi).not.toContain(`operationId: ${operation}`);
      expect(generated).not.toContain(` ${operation}:`);
    }
  });

  it("records exactly the selected 25 tasks as Complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(selected).toHaveLength(25);
    for (const value of ["| Pending | 0 |", "| In progress | 0 |", "| Complete | 667 |", "| Blocked | 61 |", "`0/0/667/61`", "| M4 | 82 | 0 | 0 | 82 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-36 through M4-50 and M4-51a through M4-51c are Complete");
    expect(prose).toContain("M4-51d through M4-59 are Complete");
  });
});

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const selected = [
  ...Array.from({ length: 13 }, (_, index) => `M5-${String(index + 10).padStart(2, "0")}`),
  "M5-23a", "M5-23b", "M5-23c", "M5-23d", "M5-23",
  ...Array.from({ length: 7 }, (_, index) => `M5-${String(index + 24).padStart(2, "0")}`),
];

describe("M5 worker and Attack Lab completion batch", () => {
  it("keeps the run and Attack Lab operations in the generated product contract", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of ["listTestRuns", "getTestRun", "cancelTestRun", "listAttackLabRuns", "createAttackLabRun", "getAttackLabRun", "cancelAttackLabRun"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("records exactly M5-10 through the M5-30 boundary as Complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(selected).toHaveLength(25);
    for (const value of ["| Pending | 0 |", "| In progress | 238 |", "| Complete | 487 |", "| Blocked | 3 |", "`0/238/487/3`", "| M5 | 42 | 0 | 0 | 42 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M5-01 through M5-35 are Complete");
    expect(prose).toContain("does not claim live Attack Lab/Fargate execution");
  });
});

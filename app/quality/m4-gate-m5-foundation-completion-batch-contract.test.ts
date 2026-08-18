import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const selected = [
  "M4-51d", "M4-51e", "M4-51", "M4-52", "M4-53", "M4-54", "M4-55", "M4-56",
  "M4-57", "M4-58", "M4-59a", "M4-59b", "M4-59c", "M4-59d", "M4-59e", "M4-59",
  ...Array.from({ length: 9 }, (_, index) => `M5-${String(index + 1).padStart(2, "0")}`),
];

describe("M4 gate and M5 foundation completion batch", () => {
  it("keeps the M5 foundation operations in the generated product contract", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of ["listTests", "createTest", "getTest", "updateTest", "runTest"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("records exactly the selected 25 tasks as Complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(selected).toHaveLength(25);
    for (const value of ["| Pending | 0 |", "| In progress | 193 |", "| Complete | 532 |", "| Blocked | 3 |", "`0/193/532/3`", "| M4 | 82 | 0 | 0 | 82 | 0 |", "| M5 | 42 | 0 | 0 | 42 | 0 |"]) expect(tracker).toContain(value);
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of selected) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-51d through M4-59 are Complete");
    expect(prose).toContain("M5-01 through M5-35 are Complete");
  });
});

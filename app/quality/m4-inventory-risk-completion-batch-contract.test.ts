import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");
const completedTasks = Array.from({ length: 25 }, (_, index) => `M4-${String(index + 11).padStart(2, "0")}`);

describe("M4 inventory and risk completion batch", () => {
  it("keeps the completed API and risk boundaries executable", async () => {
    const [openapi, generated] = await Promise.all([
      readFile(resolve(root, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(root, "apps/web/api/generated.ts"), "utf8"),
    ]);
    for (const operation of ["listIdentities", "getIdentity", "listRuntimes", "getRuntime", "getAsset", "listFindings", "getFinding"]) {
      expect(openapi).toContain(`operationId: ${operation}`);
      expect(generated).toContain(operation);
    }
  });

  it("records exactly M4-11 through M4-35 as complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(completedTasks).toHaveLength(25);
    expect(tracker).toContain("| Pending | 0 |");
    expect(tracker).toContain("| In progress | 147 |");
    expect(tracker).toContain("| Complete | 578 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("| M4 | 82 | 0 | 0 | 82 | 0 |");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] ?? "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] ?? "";
    for (const task of completedTasks) {
      expect(active.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(0);
      expect(complete.match(new RegExp(`^\\| ${task} \\|`, "gm")) ?? []).toHaveLength(1);
    }
    const prose = readme.replace(/\s+/g, " ");
    expect(prose).toContain("M4-11 through M4-35 are Complete");
    expect(prose).toContain("M4-36 through M4-50 and M4-51a through M4-51c are Complete");
  });
});

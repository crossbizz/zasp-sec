import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = process.cwd();

describe("Cartography scope proof delivery-waiver status contract", () => {
  it("starts M0-10 without changing the blocked provider dependencies", async () => {
    const [waiver, tracker, readme, sourcePlan] = await Promise.all([
      readFile(
        resolve(repositoryRoot, "docs/internal/2026-08-14-m0-10-cartography-proof-implementation-plan.md"),
        "utf8",
      ),
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(
        resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
        "utf8",
      ),
    ]);

    expect(tracker).toContain("| Pending | 718 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 8 |");
    expect(tracker).toContain("| Blocked | 1 |");
    expect(tracker).toMatch(/\| M0 \| 27 \| 17 \| 1 \| 8 \| 1 \|/);
    expect(tracker).toContain(
      "| M0-10 | August 14, 2026 | Implement the two-Organization Cartography AWS/GitHub fixture proof under the delivery waiver; normalization and OSS integration only, with no AWS/GitHub authorization-parity claim. |",
    );
    expect(tracker).toMatch(/## Blocked[\s\S]*?\| M0-09 \| August 13, 2026 \|/);
    expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
    expect(tracker).toContain("R-03 remains incomplete");
    expect(readme).toContain("M0-10 is In progress under the Cartography delivery waiver");
    expect(waiver).toContain("fixture-only Cartography normalization proof");
    expect(sourcePlan).toContain("**M0-10 - Cartography proof**");
  });
});

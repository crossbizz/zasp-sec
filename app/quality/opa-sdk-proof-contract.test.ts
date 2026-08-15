import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");

function markdownRows(markdown: string) {
  return markdown
    .split("\n")
    .filter((line) => line.startsWith("|") && line.endsWith("|"))
    .map((line) => line.slice(1, -1).split("|").map((cell) => cell.trim()));
}

function taskRows(tracker: string, heading: "In progress" | "Complete") {
  const end = heading === "In progress" ? "Complete" : "Blocked";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(section).slice(2);
}

function assertM017Active(tracker: string, readme: string, riskRegister: string) {
  const section = readme.match(/## OPA SDK proof[\s\S]*?## Promptfoo red-team proof/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-10");

  expect(section).toBeDefined();
  expect(section).toContain("M0-17 is In progress");
  expect(section).toContain("OPA Go SDK");
  expect(section).toContain("in-process");
  expect(section).toContain("one Allow and one Block decision");
  expect(section).toContain("R-10 remains Not run");
  expect(section).not.toMatch(/uses an OPA server|customer-facing Rego|external policy service/i);

  expect(tracker).toContain("| Pending | 707 |");
  expect(tracker).toContain("| In progress | 1 |");
  expect(tracker).toContain("| Complete | 18 |");
  expect(tracker).toContain("| Blocked | 1 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 6 \| 1 \| 18 \| 1 \|/);
  expect(tracker).toContain("`707/1/18/1`");
  expect(activeRows).toHaveLength(1);
  expect(activeRows[0]?.[0]).toBe("M0-17");
  expect(activeRows[0]?.[1]).toBe("August 15, 2026");
  expect(activeRows[0]?.[2]).toContain("OPA Go SDK");
  expect(completeRows.filter(([task]) => task === "M0-16")).toHaveLength(1);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-18")).toHaveLength(0);
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toBe("Not run — M0-17");
}

describe("OPA SDK proof repository contract", () => {
  it("binds the exact source task, product boundary, and approved implementation", async () => {
    const sourcePlan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const prd = await readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8");
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-17-opa-sdk-proof-design.md"),
      "utf8",
    );
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-17-opa-sdk-proof-implementation-plan.md"),
      "utf8",
    );
    const sourceSection = sourcePlan.match(/\*\*M0-17 - OPA SDK proof\*\*[\s\S]*?\*\*M0-18 -/)?.[0];

    expect(sourceSection).toBeDefined();
    expect(sourceSection).toContain("Depends on: `M0-16`");
    expect(sourceSection).toContain("Evaluate one Allow and one Block decision using OPA Go SDK in-process");
    expect(sourceSection).toContain("Both decisions are deterministic and meet local latency sanity check");
    expect(sourceSection).toContain("Timebox: <=15 minutes");
    expect(prd).toContain("OPA Go SDK embedded in the runtime gateway");
    expect(prd).toContain("custom user-authored Rego");
    expect(design).toContain("v1.17.0");
    expect(design).toContain("100 warm-up evaluations");
    expect(design).toContain("1,000 measured evaluations");
    expect(design).toContain("at most 10 ms");
    expect(plan).toContain("behavior or bug fix follows a witnessed RED");
    expect(plan).toMatch(/two consecutive direct CLI\s+runs/);
  });

  it("starts only M0-17 and leaves R-10 unadvanced", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    assertM017Active(tracker, readme, riskRegister);
  });

  it("rejects duplicate, concurrent, premature-risk, external-service, and aggregate drift", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const row = taskRows(tracker, "In progress")[0]?.join(" | ");

    expect(row).toBeDefined();
    expect(() => assertM017Active(tracker, readme, riskRegister)).not.toThrow();
    expect(() =>
      assertM017Active(
        tracker.replace("## Complete\n", `| ${row} |\n\n## Complete\n`),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM017Active(
        tracker.replace("## Complete\n", "| M0-18 | August 15, 2026 | Concurrent work. |\n\n## Complete\n"),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM017Active(
        tracker,
        readme,
        riskRegister.replace("Not run — M0-17", "PASS — M0-17 — premature"),
      ),
    ).toThrow();
    expect(() =>
      assertM017Active(
        tracker,
        readme.replace("in-process", "through an external OPA server with customer-facing Rego"),
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM017Active(
        tracker.replace("| Pending | 707 |", "| Pending | 706 |"),
        readme,
        riskRegister,
      ),
    ).toThrow();
  });
});

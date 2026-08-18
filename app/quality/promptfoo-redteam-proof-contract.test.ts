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

const completionEvidence =
  ".superpowers/sdd/agent_security_platform_Technical_Implementation_Plan_v1.5/task-M0-16-report.md; proof head 4abd751918913be813a662ea0f3847676369b012";

function assertM016Complete(tracker: string, readme: string, riskRegister: string) {
  const section = readme.match(/## Promptfoo red-team proof[\s\S]*?## Nango proxy proof/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-09");

  expect(section).toBeDefined();
  expect(section).toContain("M0-16 is Complete");
  expect(section).toContain("one direct prompt-injection case");
  expect(section).toContain("local fake agent");
  expect(section).toContain("objective, verdict, and evidence reference");
  expect(section).toMatch(/Two consecutive final-code\s+live passes/);
  expect(section).toContain("exact zero-resource cleanup");
  expect(section).toContain("R-09 is PASS");
  expect(section).not.toMatch(/Promptfoo Cloud|external model|real credential/i);

  expect(tracker).toContain("| Pending | 642 |");
  expect(tracker).toContain("| In progress | 1 |");
  expect(tracker).toContain("| Complete | 82 |");
  expect(tracker).toContain("| Blocked | 3 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
  expect(tracker).toContain("`642/1/82/3`");
  expect(activeRows.map(([task]) => task)).toEqual(["M1-41"]);
  expect(completeRows.filter(([task]) => task === "M0-16")).toHaveLength(1);
  expect(completeRows.find(([task]) => task === "M0-16")?.[1]).toBe("August 15, 2026");
  expect(completeRows.find(([task]) => task === "M0-16")?.[2]).toContain("Promptfoo");
  expect(completeRows.find(([task]) => task === "M0-16")?.[2]).toContain("local fake agent");
  expect(completeRows.filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-17")).toHaveLength(1);
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toBe(`PASS — M0-16 — ${completionEvidence}`);
}

describe("Promptfoo red-team proof repository contract", () => {
  it("binds the exact source task, product boundary, and approved implementation", async () => {
    const sourcePlan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const prd = await readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8");
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-16-promptfoo-proof-design.md"),
      "utf8",
    );
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-16-promptfoo-proof-implementation-plan.md"),
      "utf8",
    );
    const sourceSection = sourcePlan.match(/\*\*M0-16 - Promptfoo proof\*\*[\s\S]*?\*\*M0-17 -/)?.[0];

    expect(sourceSection).toBeDefined();
    expect(sourceSection).toContain("Depends on: `M0-15`");
    expect(sourceSection).toContain("Run one prompt-injection case against a local fake agent target");
    expect(sourceSection).toContain("Result can be normalized to objective, verdict and evidence reference");
    expect(sourceSection).toContain("Timebox: <=15 minutes");
    expect(prd).toContain("Promptfoo for MVP red-team orchestration");
    expect(prd).toContain("direct prompt injection");
    expect(prd).toContain("Results group by vulnerability/outcome, not raw prompts");
    expect(design).toContain("0.121.19");
    expect(design).toContain("one-shot Promptfoo evaluation runner");
    expect(design).toContain("evidence:promptfoo:sha256:");
    expect(design).toContain("zasp.dev/proof=m0-16");
    expect(plan).toContain("behavior-first tests");
    expect(plan).toContain("two consecutive final-code live passes");
    expect(plan).toMatch(/every Critical, Important,\s+and Minor finding tests-first/);
  });

  it("completes only M0-16 and advances R-09 with reviewed evidence", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    assertM016Complete(tracker, readme, riskRegister);
  });

  it("rejects duplicate, concurrent, premature-risk, external-target, and aggregate drift", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const row = taskRows(tracker, "Complete").find(([task]) => task === "M0-16")?.join(" | ");

    expect(row).toBeDefined();
    expect(() => assertM016Complete(tracker, readme, riskRegister)).not.toThrow();
    expect(() =>
      assertM016Complete(
        tracker.replace(`| ${row} |\n`, `| ${row} |\n| ${row} |\n`),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM016Complete(
        tracker.replace("## Complete\n", "| M0-17 | August 15, 2026 | Concurrent work. |\n\n## Complete\n"),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM016Complete(
        tracker,
        readme,
        riskRegister.replace(`PASS — M0-16 — ${completionEvidence}`, "Not run — M0-16"),
      ),
    ).toThrow();
    expect(() =>
      assertM016Complete(
        tracker,
        readme.replace("local fake agent", "external model with a real credential"),
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM016Complete(
        tracker.replace("| Complete | 82 |", "| Complete | 17 |"),
        readme,
        riskRegister,
      ),
    ).toThrow();
  });

  it("exposes exact hermetic, live, and immutable-license root boundaries", async () => {
    const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8"));
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const inventory = JSON.parse(await readFile(
      resolve(repositoryRoot, "proofs/promptfoo-redteam/adapter-license.json"),
      "utf8",
    ));
    const section = readme.match(/## Promptfoo red-team proof[\s\S]*?## Nango proxy proof/)?.[0];

    expect(packageJson.scripts["proof:promptfoo:test"]).toBe(
      "node --test proofs/promptfoo-redteam/*.test.mjs",
    );
    expect(packageJson.scripts["proof:promptfoo:run"]).toBe(
      "node proofs/promptfoo-redteam/run.mjs",
    );
    expect(packageJson.scripts["proof:promptfoo:license"]).toBe(
      "node proofs/promptfoo-redteam/license-audit.mjs",
    );
    expect(section).toContain("npm run proof:promptfoo:test");
    expect(section).toContain("npm run proof:promptfoo:run");
    expect(section).toContain("npm run proof:promptfoo:license");
    expect(section).toContain(
      "Promptfoo red-team proof passed: objective=true verdict=vulnerable evidence=true cleanup=true.",
    );
    expect(section).toContain("Docker prerequisite");
    expect(section).toContain("no model or provider credential");
    expect(section).toContain("raw prompts, target responses, canaries, Promptfoo-native identifiers, and Docker state");
    expect(inventory.schema_version).toBe(1);
    expect(inventory.allowed_licenses).toEqual(["MIT"]);
    expect(inventory.components).toHaveLength(1);
    expect(inventory.images).toHaveLength(1);
  });
});

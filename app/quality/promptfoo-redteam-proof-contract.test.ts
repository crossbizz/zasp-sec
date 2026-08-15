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

function assertM016Active(tracker: string, readme: string, riskRegister: string) {
  const section = readme.match(/## Promptfoo red-team proof[\s\S]*?## Nango proxy proof/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-09");

  expect(section).toBeDefined();
  expect(section).toContain("M0-16 is In progress");
  expect(section).toContain("one direct prompt-injection case");
  expect(section).toContain("local fake agent");
  expect(section).toContain("objective, verdict, and evidence reference");
  expect(section).toContain("R-09 remains Not run");
  expect(section).not.toMatch(/Promptfoo Cloud|external model|real credential/i);

  expect(tracker).toContain("| Pending | 708 |");
  expect(tracker).toContain("| In progress | 1 |");
  expect(tracker).toContain("| Complete | 17 |");
  expect(tracker).toContain("| Blocked | 1 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 7 \| 1 \| 17 \| 1 \|/);
  expect(tracker).toContain("`708/1/17/1`");
  expect(activeRows).toHaveLength(1);
  expect(activeRows[0]?.[0]).toBe("M0-16");
  expect(activeRows[0]?.[1]).toBe("August 15, 2026");
  expect(activeRows[0]?.[2]).toContain("Promptfoo");
  expect(activeRows[0]?.[2]).toContain("local fake agent");
  expect(completeRows.filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-17")).toHaveLength(0);
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toBe("Not run — M0-16");
}

function activeFixture(tracker: string, readme: string) {
  const section = [
    "## Promptfoo red-team proof",
    "",
    "M0-16 is In progress. It runs one direct prompt-injection case through",
    "exact-pinned Promptfoo against a local fake agent and normalizes only the",
    "objective, verdict, and evidence reference. R-09 remains Not run until live evidence and review pass.",
    "",
  ].join("\n");
  const row =
    "| M0-16 | August 15, 2026 | Run one exact-pinned Promptfoo direct prompt-injection case against a local fake agent and normalize its objective, verdict, and evidence reference. |";
  return {
    readme: readme.replace(/## Nango proxy proof/, `${section}\n## Nango proxy proof`),
    tracker: tracker
      .replace("| Pending | 709 |", "| Pending | 708 |")
      .replace("| In progress | 0 |", "| In progress | 1 |")
      .replace("| M0 | 27 | 8 | 0 | 17 | 1 |", "| M0 | 27 | 7 | 1 | 17 | 1 |")
      .replace("`709/0/17/1`", "`708/1/17/1`")
      .replace("| --- | --- | --- |\n\n## Complete", `| --- | --- | --- |\n${row}\n\n## Complete`),
  };
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

  it("starts only M0-16 and leaves R-09 unadvanced", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    assertM016Active(tracker, readme, riskRegister);
  });

  it("rejects duplicate, concurrent, premature-risk, external-target, and aggregate drift", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const active = activeFixture(tracker, readme);
    const row = taskRows(active.tracker, "In progress")[0]?.join(" | ");

    expect(row).toBeDefined();
    expect(() => assertM016Active(active.tracker, active.readme, riskRegister)).not.toThrow();
    expect(() =>
      assertM016Active(
        active.tracker.replace("## Complete\n", `| ${row} |\n\n## Complete\n`),
        active.readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM016Active(
        active.tracker.replace("## Complete\n", "| M0-17 | August 15, 2026 | Concurrent work. |\n\n## Complete\n"),
        active.readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM016Active(
        active.tracker,
        active.readme,
        riskRegister.replace("Not run — M0-16", "PASS — M0-16 — premature"),
      ),
    ).toThrow();
    expect(() =>
      assertM016Active(
        active.tracker,
        active.readme.replace("local fake agent", "external model with a real credential"),
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM016Active(
        active.tracker.replace("| Pending | 708 |", "| Pending | 707 |"),
        active.readme,
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

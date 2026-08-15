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
  ".superpowers/sdd/2026-08-15-m0-17-opa-sdk-proof-implementation-plan/task-5-report.md; proof head bd72e785c543f381d2d8a9bdf9a4150275605e3d";

function assertM017Complete(tracker: string, readme: string, riskRegister: string) {
  const section = readme.match(/## OPA SDK proof[\s\S]*?## Promptfoo red-team proof/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-10");

  expect(section).toBeDefined();
  expect(section).toContain("M0-17 is Complete");
  expect(section).toContain("OPA Go SDK");
  expect(section).toContain("in-process");
  expect(section).toContain("one Allow and one Block decision");
  expect(section).toContain("R-10 is PASS");
  expect(section).not.toMatch(/uses an OPA server|customer-facing Rego|external policy service/i);

  expect(tracker).toContain("| Pending | 697 |");
  expect(tracker).toContain("| In progress | 0 |");
  expect(tracker).toContain("| Complete | 28 |");
  expect(tracker).toContain("| Blocked | 3 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
  expect(tracker).toContain("`697/0/28/3`");
  expect(activeRows).toHaveLength(0);
  expect(completeRows.filter(([task]) => task === "M0-17")).toHaveLength(1);
  expect(completeRows.find(([task]) => task === "M0-17")?.[1]).toBe("August 15, 2026");
  expect(completeRows.find(([task]) => task === "M0-17")?.[2]).toContain("OPA Go SDK");
  expect(completeRows.filter(([task]) => task === "M0-16")).toHaveLength(1);
  expect(tracker.match(/## Blocked[\s\S]*?## Review findings/)?.[0]).toContain("| M0-18 |");
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toBe(`PASS — M0-17 — ${completionEvidence}`);
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

  it("completes only M0-17 and advances R-10 with reviewed evidence", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    assertM017Complete(tracker, readme, riskRegister);
  });

  it("exposes exact hermetic, direct, and immutable-license commands", async () => {
    const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8"));
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## OPA SDK proof[\s\S]*?## Promptfoo red-team proof/)?.[0] ?? "";
    const normalizedSection = section.replace(/\s+/g, " ");

    expect(packageJson.scripts["proof:opa:test"]).toBe("cd proofs/opa-sdk && go test -race -count=1 ./...");
    expect(packageJson.scripts["proof:opa:run"]).toBe("cd proofs/opa-sdk && go run .");
    expect(packageJson.scripts["proof:opa:license"]).toBe("node proofs/opa-sdk/license-audit.mjs");
    expect(normalizedSection).toContain("OPA v1.17.0");
    expect(normalizedSection).toContain("100 warm-ups per decision");
    expect(normalizedSection).toContain("1,000 measured evaluations per decision");
    expect(normalizedSection).toContain("decision-specific p95 at or below 10 ms");
    expect(section).toContain("proof:opa:test");
    expect(section).toContain("proof:opa:run");
    expect(section).toContain("proof:opa:license");
    expect(section).toContain("OPA SDK proof passed: allow=true block=true deterministic=true evaluations=2000 p95_under_10ms=true.");
    expect(normalizedSection).toContain("no server, subprocess, bundle, network call, customer Rego, or environment configuration");
  });

  it("rejects duplicate, concurrent, premature-risk, external-service, and aggregate drift", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const row = taskRows(tracker, "Complete").find(([task]) => task === "M0-17")?.join(" | ");

    expect(row).toBeDefined();
    expect(() => assertM017Complete(tracker, readme, riskRegister)).not.toThrow();
    expect(() =>
      assertM017Complete(
        tracker.replace(`| ${row} |\n`, `| ${row} |\n| ${row} |\n`),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM017Complete(
        tracker.replace("## Complete\n", "| M0-18 | August 15, 2026 | Concurrent work. |\n\n## Complete\n"),
        readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM017Complete(
        tracker,
        readme,
        riskRegister.replace(`PASS — M0-17 — ${completionEvidence}`, "Not run — M0-17"),
      ),
    ).toThrow();
    expect(() =>
      assertM017Complete(
        tracker,
        readme.replace("in-process", "through an external OPA server with customer-facing Rego"),
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM017Complete(
        tracker.replace("| Complete | 28 |", "| Complete | 19 |"),
        readme,
        riskRegister,
      ),
    ).toThrow();
  });
});

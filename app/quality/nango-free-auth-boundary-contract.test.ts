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

function assertM014Complete(tracker: string, readme: string, riskRegister: string) {
  const section = readme.match(/## Nango free Auth boundary[\s\S]*?## Nango API-key proof/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const m014Rows = completeRows.filter(([task]) => task === "M0-14");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-08");

  expect(section).toBeDefined();
  expect(section).toContain("M0-14 is Complete");
  expect(section).toContain("Auth plus Proxy");
  expect(section).toContain("Functions, Webhooks, and MCP are out of scope");
  expect(section).toMatch(/not a claim that\s+every excluded route is absent/);
  expect(section).toContain("M0-15");
  expect(section).toContain("R-08 is PASS");

  expect(tracker).toContain("| Pending | 642 |");
  expect(tracker).toContain("| In progress | 1 |");
  expect(tracker).toContain("| Complete | 82 |");
  expect(tracker).toContain("| Blocked | 3 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
  expect(activeRows.map(([task]) => task)).toEqual(["M1-41"]);
  expect(m014Rows).toHaveLength(1);
  expect(m014Rows[0]?.[1]).toBe("August 15, 2026");
  expect(m014Rows[0]?.[2]).toContain("Auth plus Proxy");
  expect(completeRows.filter(([task]) => ["M0-14a", "M0-14b", "M0-14c"].includes(task))).toHaveLength(3);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");
  expect(tracker).toMatch(
    /\| M0-14 final review \|[^\n]*zero remaining Critical, Important, or Minor[^\n]*\| Complete August 15, 2026[^\n]*R-08 was deferred to M0-15[^\n]*\|/,
  );

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toMatch(/^PASS — M0-15 — /);
}

function completedFixture(tracker: string, readme: string) {
  const activeRow = taskRows(tracker, "In progress").find(([task]) => task === "M0-14")?.join(" | ");
  if (!activeRow) {
    return { tracker, readme };
  }
  const completedRow = activeRow.replace("Record the evidence-backed", "Recorded the evidence-backed");
  return {
    readme: readme.replace("M0-14 is In progress", "M0-14 is Complete"),
    tracker: tracker
      .replace("| In progress | 1 |", "| In progress | 2 |")
      .replace("| Complete | 15 |", "| Complete | 16 |")
      .replace("| M0 | 27 | 9 | 1 | 15 | 1 |", "| M0 | 27 | 9 | 0 | 16 | 1 |")
      .replace("`710/1/15/1`", "`710/0/16/1`")
      .replace(`| ${activeRow} |\n`, "")
      .replace("\n`PRE-01`, `PRE-02`, and `PROV-01`", `\n| ${completedRow} |\n\n\`PRE-01\`, \`PRE-02\`, and \`PROV-01\``),
  };
}

describe("Nango free Auth boundary contract", () => {
  it("binds the source task and product requirement to Auth plus Proxy only", async () => {
    const sourcePlan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const prd = await readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8");
    const sourceSection = sourcePlan.match(/\*\*M0-14 - Nango free auth proof\*\*[\s\S]*?\*\*M0-15 -/)?.[0];

    expect(sourceSection).toBeDefined();
    expect(sourceSection).toContain("Depends on: `M0-14c`");
    expect(sourceSection).toContain("Record the validated Nango free feature boundary for MVP");
    expect(sourceSection).toContain("Functions, Webhooks and MCP as out of scope");
    expect(sourceSection).toContain("Timebox: <=15 minutes");
    expect(prd).toContain("Nango free self-hosted for Auth + Proxy only");
    expect(prd).toContain(
      "MVP does not depend on Nango Functions, Webhooks, MCP server, RBAC, full observability or Enterprise-only runtime features",
    );
  });

  it("records an evidence-only boundary without claiming excluded routes are absent", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-14-nango-free-auth-boundary-design.md"),
      "utf8",
    );
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-14-nango-free-auth-boundary-implementation-plan.md"),
      "utf8",
    );

    expect(design).toContain("evidence-only boundary consolidation");
    expect(design).toContain("Auth plus the Proxy surface");
    expect(design).toContain("Functions or function runners");
    expect(design).toContain("Nango Webhooks");
    expect(design).toContain("Nango MCP server");
    expect(design).toMatch(
      /not a\s+claim that every corresponding route or source module is absent from the\s+image/,
    );
    expect(design).toContain("M0-15 alone may advance R-08");
    expect(plan).toContain("do not add a new runtime, Docker lifecycle, provider call, or credential path");
    expect(plan).toContain("Run focused RED");
    expect(plan).toContain("successful exact-SHA Runnable UI evidence");
  });

  it("completes the boundary while retaining every dependency and risk gate", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    assertM014Complete(tracker, readme, riskRegister);
  });

  it("rejects duplicate, concurrent, risk, scope, and count drift", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const completed = completedFixture(tracker, readme);
    const row = completed.tracker.split("\n").find((line) => line.startsWith("| M0-14 |"));

    expect(row).toBeDefined();
    expect(() => assertM014Complete(completed.tracker, completed.readme, riskRegister)).not.toThrow();
    expect(() =>
      assertM014Complete(
        completed.tracker.replace(`${row}\n`, `${row}\n${row}\n`),
        completed.readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM014Complete(
        completed.tracker.replace(
          "## Complete\n",
          "| M0-15 | August 15, 2026 | Concurrent Proxy work. |\n\n## Complete\n",
        ),
        completed.readme,
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM014Complete(
        completed.tracker,
        completed.readme,
        riskRegister.replace("PASS — M0-15 —", "PASS — M0-14 —"),
      ),
    ).toThrow();
    expect(() =>
      assertM014Complete(
        completed.tracker,
        completed.readme.replace("MCP are out of scope", "MCP are supported"),
        riskRegister,
      ),
    ).toThrow();
    expect(() =>
      assertM014Complete(
        completed.tracker.replace("| Pending | 642 |", "| Pending | 686 |"),
        completed.readme,
        riskRegister,
      ),
    ).toThrow();
  });
});

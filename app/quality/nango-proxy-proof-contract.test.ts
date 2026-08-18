import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const proofHead = "7f64ca823365af066c273a755e01acd7cf05c0ab";
const completionEvidence = `.superpowers/sdd/2026-08-15-m0-15-nango-proxy-proof-implementation-plan/task-6-report.md; proof head ${proofHead}`;

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

function assertM015Active(tracker: string, readme: string, riskRegister: string) {
  const section = readme.match(/## Nango proxy proof[\s\S]*?## Nango free Auth boundary/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-08");

  expect(section).toBeDefined();
  expect(section).toContain("M0-15 is In progress");
  expect(section).toContain("authenticated provider GET");
  expect(section).toContain("private TLS fixture");
  expect(section).toContain("raw provider token");
  expect(section).toContain("R-08 remains Not run");

  expect(tracker).toContain("| Pending | 710 |");
  expect(tracker).toContain("| In progress | 0 |");
  expect(tracker).toContain("| Complete | 16 |");
  expect(tracker).toContain("| Blocked | 1 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 9 \| 1 \| 16 \| 1 \|/);
  expect(activeRows).toHaveLength(1);
  expect(activeRows[0]?.[0]).toBe("M0-15");
  expect(activeRows[0]?.[1]).toBe("August 15, 2026");
  expect(activeRows[0]?.[2]).toContain("authenticated provider GET");
  expect(completeRows.filter(([task]) => task === "M0-14")).toHaveLength(1);
  expect([...activeRows, ...completeRows].filter(([task]) => task === "M0-16")).toHaveLength(1);
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toBe("Not run — M0-14a through M0-15");
}

function assertM015Complete(tracker: string, readme: string, riskRegister: string) {
  const section = readme.match(/## Nango proxy proof[\s\S]*?## Nango free Auth boundary/)?.[0];
  const activeRows = taskRows(tracker, "In progress");
  const completeRows = taskRows(tracker, "Complete");
  const riskRows = markdownRows(riskRegister).filter(([id]) => id === "R-08");

  expect(section).toBeDefined();
  expect(section).toContain("M0-15 is Complete");
  expect(section).toContain("authenticated provider GET");
  expect(section).toContain("raw provider token");
  expect(section).toContain("R-08 is PASS");

  expect(tracker).toContain("| Pending | 656 |");
  expect(tracker).toContain("| In progress | 0 |");
  expect(tracker).toContain("| Complete | 69 |");
  expect(tracker).toContain("| Blocked | 3 |");
  expect(tracker).toMatch(/\| M0 \| 27 \| 0 \| 0 \| 24 \| 3 \|/);
  expect(activeRows.map(([task]) => task)).toEqual([]);
  expect(completeRows.filter(([task]) => task === "M0-15")).toHaveLength(1);
  expect(completeRows.filter(([task]) => task === "M0-14")).toHaveLength(1);
  expect(completeRows.filter(([task]) => task === "M0-16")).toHaveLength(1);
  expect(tracker).toContain("M0-09 and PROV-01 remain Blocked");
  expect(tracker).toContain("R-03 remains incomplete");

  expect(riskRows).toHaveLength(1);
  expect(riskRows[0]?.[5]).toBe(`PASS — M0-15 — ${completionEvidence}`);
}

function activeFixture(tracker: string, readme: string) {
  if (taskRows(tracker, "In progress").some(([task]) => task === "M0-15") && readme.includes("## Nango proxy proof")) {
    return { tracker, readme };
  }
  const section = [
    "## Nango proxy proof",
    "",
    "M0-15 is In progress. It proves one authenticated provider GET through",
    "free self-hosted Nango against a private TLS fixture. Product state must",
    "retain no raw provider token. R-08 remains Not run until live evidence and review pass.",
    "",
  ].join("\n");
  const row =
    "| M0-15 | August 15, 2026 | Prove one authenticated provider GET through the private Nango Proxy boundary without retaining the raw provider token. |";
  return {
    readme: readme.replace(/## Nango proxy proof[\s\S]*?(?=## Nango free Auth boundary)/, `${section}\n`),
    tracker: tracker
      .replace("| Pending | 656 |", "| Pending | 710 |")
      .replace("| Complete | 69 |", "| Complete | 16 |")
      .replace("| Blocked | 3 |", "| Blocked | 1 |")
      .replace("| M0 | 27 | 0 | 0 | 24 | 3 |", "| M0 | 27 | 9 | 1 | 16 | 1 |")
      .replace("`656/0/69/3`", "`710/1/16/1`")
      .replace(/^\| M0-22 \| August 15, 2026 \|.*\|\n/m, "")
      .replace(/^\| M0-21a \| August 15, 2026 \|.*\|\n/m, "")
      .replace(/^\| M0-21 \| August 15, 2026 \|.*\|\n/m, "")
      .replace(/^\| M0-20 \| August 15, 2026 \|.*\|\n/m, "")
      .replace(/^\| M0-19 \| August 15, 2026 \|.*\|\n/m, "")
      .replace(/^\| M0-18 \| August 15, 2026 \|.*\|\n/m, "")
      .replace(/^\| M0-17 \| August 15, 2026 \|.*\|\n/m, "")
      .replace(/^\| M0-15 \| August 15, 2026 \|.*\|\n/m, "")
      .replace(
        /## In progress[\s\S]*?## Complete/,
        `## In progress\n\n| Task | Started | Current work |\n| --- | --- | --- |\n${row}\n\n## Complete`,
      ),
  };
}

describe("Nango Proxy proof delivery contract", () => {
  it("exposes exact hermetic and live commands with the fixed private output boundary", async () => {
    const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8")) as {
      scripts?: Record<string, string>;
    };
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## Nango proxy proof[\s\S]*?## Nango free Auth boundary/)?.[0];

    expect(packageJson.scripts?.["proof:nango:proxy:test"]).toBe("node --test proofs/nango-proxy/*.test.mjs");
    expect(packageJson.scripts?.["proof:nango:proxy:run"]).toBe("node proofs/nango-proxy/run.mjs");
    expect(packageJson.scripts?.["proof:nango:proxy:test"]).not.toMatch(/docker|env-file|credential|source/i);
    expect(section).toBeDefined();
    expect(section).toContain("npm run proof:nango:proxy:test");
    expect(section).toContain("npm run proof:nango:proxy:run");
    expect(section).toContain("Nango proxy proof passed: get=true response=true product_state_safe=true cleanup=true.");
    expect(section).toContain("GET /api/v2/events?limit=1");
    expect(section).toContain("no host port");
    expect(section).toContain("no `.env`");
    expect(section).toContain("raw provider token");
    expect(section).toContain("M0-15 is Complete");
  });

  it("binds the exact source task, accepted product boundary, and implementation decision", async () => {
    const sourcePlan = await readFile(
      resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"),
      "utf8",
    );
    const prd = await readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8");
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-15-nango-proxy-proof-design.md"),
      "utf8",
    );
    const plan = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m0-15-nango-proxy-proof-implementation-plan.md"),
      "utf8",
    );
    const sourceSection = sourcePlan.match(/\*\*M0-15 - Nango proxy proof\*\*[\s\S]*?\*\*M0-16 -/)?.[0];

    expect(sourceSection).toBeDefined();
    expect(sourceSection).toContain("Depends on: `M0-14`");
    expect(sourceSection).toContain("Proxy one authenticated GET through free self-hosted Nango");
    expect(sourceSection).toContain("Provider response succeeds and product code never persists the raw provider token");
    expect(sourceSection).toContain("Timebox: <=15 minutes");
    expect(prd).toContain("Nango free self-hosted for long-tail Auth + Proxy only");
    expect(prd).toContain("A long-tail connector built with Nango Proxy still requires product code to call provider APIs and normalize security semantics");
    expect(design).toContain("GET /proxy/api/v2/events?limit=1");
    expect(design).toContain("GET /api/v2/events?limit=1");
    expect(design).toContain("zasp.dev/proof=m0-15");
    expect(design).toContain("R-08 move to PASS");
    expect(plan).toContain("tests-first RED/GREEN");
    expect(plan).toContain("two consecutive final-code live passes");
    expect(plan).toMatch(/every Critical,\s+Important, and Minor finding tests-first/);
  });

  it("completes only M0-15 and advances only the full R-08 gate", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    assertM015Complete(tracker, readme, riskRegister);
  });

  it("rejects duplicate, concurrent, early-risk, exclusion, and aggregate drift", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const riskRegister = await readFile(resolve(repositoryRoot, "docs/decisions/mvp-risk-register.md"), "utf8");
    const active = activeFixture(tracker, readme);
    const activeRisk = riskRegister.replace(`PASS — M0-15 — ${completionEvidence}`, "Not run — M0-14a through M0-15");
    const row = taskRows(active.tracker, "In progress")[0]?.join(" | ");

    expect(row).toBeDefined();
    expect(() => assertM015Active(active.tracker, active.readme, activeRisk)).not.toThrow();
    expect(() =>
      assertM015Active(
        active.tracker.replace("## Complete\n", `| ${row} |\n\n## Complete\n`),
        active.readme,
        activeRisk,
      ),
    ).toThrow();
    expect(() =>
      assertM015Active(
        active.tracker.replace("## Complete\n", "| M0-16 | August 15, 2026 | Concurrent work. |\n\n## Complete\n"),
        active.readme,
        activeRisk,
      ),
    ).toThrow();
    expect(() =>
      assertM015Active(
        active.tracker,
        active.readme,
        activeRisk.replace("Not run — M0-14a through M0-15", "PASS — M0-15 — premature"),
      ),
    ).toThrow();
    expect(() =>
      assertM015Active(
        active.tracker,
        active.readme.replace("private TLS fixture", "Nango Functions fixture"),
        activeRisk,
      ),
    ).toThrow();
    expect(() =>
      assertM015Active(
        active.tracker.replace("| Pending | 710 |", "| Pending | 709 |"),
        active.readme,
        activeRisk,
      ),
    ).toThrow();
  });
});

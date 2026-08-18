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

function taskRows(tracker: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return markdownRows(section).slice(2);
}

describe("M1-10 Neon schema baseline contract", () => {
  it("binds the baseline to the approved migration boundary", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-10-neon-schema-baseline-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-10-neon-schema-baseline-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-10 - Neon schema baseline\*\*[\s\S]*?\*\*M1-11 - Neon pool wrapper/)?.[0];

    expect(section).toContain("Depends on: `M1-09`");
    expect(section).toContain("initial Neon migration framework and schema-version table");
    expect(section).toContain("Fresh up migration and down rollback pass on disposable Neon branch");
    expect(design).toContain("public.zasp_schema_versions");
    expect(design).toContain("M1-11 remains Pending");
    expect(plan).toContain("exact live up/down proof");
  });

  it("completes only M1-10 after M1-09", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-10 is Complete");
    expect(readme).toContain("versioned Neon schema baseline");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-10")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-09")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-11")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-11")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("exposes stable hermetic and disposable live root commands", async () => {
    const [manifestText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(manifestText) as { scripts?: Record<string, string> };
    const section = readme.match(/## Neon schema baseline[\s\S]*?## Neon pooled proof/)?.[0];

    expect(manifest.scripts?.["db:schema:test"]).toBe(
      "go test -C services/platform -race -count=1 ./migrations && go test -C proofs/neon-pooled -race -count=1 ./...",
    );
    expect(manifest.scripts?.["db:schema:run"]).toBe(
      "node --env-file=.env proofs/neon-pooled/run-schema-baseline.mjs",
    );
    expect(section).toContain("npm run db:schema:test");
    expect(section).toContain("npm run db:schema:run");
    expect(section).toContain("NEON_API_KEY");
    expect(section).toContain("NEON_PROJECT_ID");
    expect(section).toContain("DATABASE_URL");
    expect(section).toContain("Neon schema baseline passed: up=true version=1 down=true baseline_restored=true branch_deleted=true.");
  });
});

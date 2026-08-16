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
    expect(tracker).toContain("| Pending | 671 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 54 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`671/0/54/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "38", "0", "30", "0"]);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-10")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-09")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-11")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-11")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
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

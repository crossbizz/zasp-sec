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

describe("M1-11 Neon pool wrapper contract", () => {
  it("binds the wrapper to the authoritative dependency and approved boundary", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-11-neon-pool-wrapper-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-11-neon-pool-wrapper-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-11 - Neon pool wrapper\*\*[\s\S]*?\*\*M1-12 - S3 artifact interface/)?.[0];

    expect(section).toContain("Depends on: `M1-10`");
    expect(section).toContain("pooled application DB wrapper with query timeout and health stats");
    expect(section).toContain("Pool test reports wait/in-use and closes cleanly");
    expect(design).toContain("services/platform/database");
    expect(design).toContain("M1-12 remains Pending");
    expect(plan).toContain("exact live command");
  });

  it("completes only M1-11 after reviewed live evidence", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-11 is Complete");
    expect(readme).toContain("driver-neutral application pool wrapper");
    expect(tracker).toContain("| Pending | 680 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 45 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`680/0/45/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "47", "0", "21", "0"]);
    expect(active.filter(([task]) => task === "M1-11")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-11")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-10")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-12")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-12")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes exact hermetic and live root commands with fixed output", async () => {
    const [manifestText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(manifestText) as { scripts?: Record<string, string> };
    const section = readme.match(/## Neon application pool wrapper[\s\S]*?## Neon pooled proof/)?.[0];

    expect(manifest.scripts?.["db:pool:test"]).toBe(
      "go test -C services/platform -race -count=1 ./database && go test -C proofs/neon-pooled -race -count=1 ./...",
    );
    expect(manifest.scripts?.["db:pool:run"]).toBe(
      "node --env-file=.env proofs/neon-pooled/run-pool-wrapper.mjs",
    );
    expect(section).toContain("npm run db:pool:test");
    expect(section).toContain("npm run db:pool:run");
    expect(section).toContain("DATABASE_URL");
    expect(section).toContain("Neon pool wrapper passed: reads=10 waited=true in_use=true acquired=0 closed=true.");
  });
});

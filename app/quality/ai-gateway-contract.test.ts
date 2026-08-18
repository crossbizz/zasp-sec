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

describe("M1-20 AI gateway contract", () => {
  it("binds the closed AI-egress boundary to the source task and PRD", async () => {
    const [source, prd, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-20-ai-gateway-contract-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-20-ai-gateway-contract-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-20 - AI gateway contract\*\*[\s\S]*?\*\*M1-21 - observability contract/)?.[0];

    expect(section).toContain("Depends on: `M1-19`");
    expect(section).toContain("Define AIGateway request/result and data-policy metadata");
    expect(section).toContain("Schema test rejects unapproved purpose");
    expect(prd).toContain("OpenRouter receives only explicitly requested, redacted AI-assistance payloads");
    expect(prd).toContain("disallowed by Organization data policy");
    expect(design).toContain("services/platform/aigateway");
    expect(design).toContain("PurposeFindingExplanation");
    expect(design).toContain("DataPolicyMetadata");
    expect(design).toContain("every unknown purpose therefore fail before driver I/O");
    expect(plan).toContain("M1-21 remains Pending");
  });

  it("completes only M1-20 and preserves its prerequisite and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toMatch(/M1-20\s+is\s+Complete/);
    expect(tracker).toContain("| Pending | 652 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 73 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`652/0/73/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "19", "0", "49", "0"]);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-19")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-20")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-21")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes only the hermetic root contract and documents the AI authority boundary", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts: Record<string, string> };
    const section = readme.match(/## AI gateway contract[\s\S]*?(?=\n## )/)?.[0] ?? "";

    expect(packageJson.scripts["aigateway:test"]).toBe("go test -C services/platform -race -count=1 ./aigateway");
    expect(section).toContain("npm run aigateway:test");
    expect(section).toMatch(/Organization,\s+Workspace,\s+and\s+Environment/);
    expect(section).toContain("finding_explanation");
    expect(section).toContain("redacted_summary");
    expect(section).toContain("no_provider_storage");
    expect(section).toMatch(/unapproved purpose/i);
    expect(section).toMatch(/one bounded generation\s+attempt/);
    expect(section).toContain("hermetic fake driver");
    expect(section).toMatch(/non-authoritative/);
    expect(section.replace(/\s+/g, " ")).toContain("does not prove an OpenRouter adapter, hosted delivery, model routing, streaming, caching, or persistence");
    expect(section).toMatch(/M1-21\s+is\s+Complete/);
  });
});

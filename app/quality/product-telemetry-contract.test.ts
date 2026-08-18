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

describe("M1-19 product telemetry contract", () => {
  it("binds the closed analytics boundary to the source task and PRD", async () => {
    const [source, prd, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-19-analytics-contract-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-19-analytics-contract-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-19 - analytics contract\*\*[\s\S]*?\*\*M1-20 - AI gateway contract/)?.[0];

    expect(section).toContain("Depends on: `M1-18`");
    expect(section).toContain("Define ProductTelemetry interface and allowlist serializer contract");
    expect(section).toContain("Unknown field is rejected, not silently forwarded");
    expect(prd).toContain("**PostHog:** allowlisted usage analytics");
    expect(design).toContain("services/platform/producttelemetry");
    expect(design).toContain("EventSerializer");
    expect(design).toContain("never forwards");
    expect(plan).toContain("M1-20 remains Pending");
  });

  it("keeps M1-19 and M1-20 complete", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toMatch(/M1-19\s+is\s+Complete/);
    expect(tracker).toContain("| Pending | 644 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 80 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`644/1/80/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "11", "1", "56", "0"]);
    expect(active.map(([task]) => task)).toEqual(["M1-39"]);
    expect(complete.filter(([task]) => task === "M1-18")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-19")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-20")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes only the hermetic root contract and documents the privacy boundary", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts: Record<string, string> };
    const section = readme.match(/## Product telemetry contract[\s\S]*?(?=\n## )/)?.[0] ?? "";

    expect(packageJson.scripts["producttelemetry:test"]).toBe("go test -C services/platform -race -count=1 ./producttelemetry");
    expect(section).toContain("npm run producttelemetry:test");
    expect(section).toMatch(/Organization,\s+Workspace,\s+and\s+Environment/);
    expect(section).toContain("proof_completed");
    expect(section).toContain("source");
    expect(section).toContain("success");
    expect(section).toContain("unknown field");
    expect(section).toMatch(/prompt, secret, IP address, raw evidence/i);
    expect(section).toMatch(/one bounded capture\s+attempt/);
    expect(section).toContain("hermetic fake driver");
    expect(section).toMatch(/optional and\s+non-authoritative/);
    expect(section.replace(/\s+/g, " ")).toContain("does not prove a PostHog adapter, hosted delivery, batching, persistence, or consent policy");
    expect(section).toMatch(/M1-20\s+is\s+Complete/);
  });
});

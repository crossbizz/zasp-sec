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

describe("M1-14 OpenSearch EventStore contract", () => {
  it("binds the product boundary to the authoritative task and approved design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-14-opensearch-event-store-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-14-opensearch-event-store-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-14 - OpenSearch EventStore\*\*[\s\S]*?\*\*M1-15 - GraphStore interface/)?.[0];

    expect(section).toContain("Depends on: `M1-13`");
    expect(section).toContain("EventStore interface and OpenSearch index/search skeleton");
    expect(section).toContain("Index/search fixture passes and scope filter is mandatory");
    expect(design).toContain("services/platform/eventstore");
    expect(design).toContain("M1-15 remains Pending");
    expect(plan).toContain("mandatory Organization/Workspace/Environment search scope");
  });

  it("completes only M1-14 and preserves prior completion and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-14 is Complete");
    expect(readme).toContain("scoped EventStore");
    expect(tracker).toContain("| Pending | 670 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 54 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`670/1/54/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "37", "1", "30", "0"]);
    expect(active.map(([task]) => task)).toEqual(["M1-25"]);
    expect(complete.filter(([task]) => task === "M1-13")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-14")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-15")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes only the exact hermetic and disposable EventStore commands", async () => {
    const [manifestRaw, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(manifestRaw) as { scripts?: Record<string, string> };
    expect(manifest.scripts?.["event:store:test"]).toBe(
      "go test -C services/platform -race -count=1 ./eventstore && go test -C proofs/opensearch-event -race -count=1 ./... && node --test proofs/opensearch-event/run.test.mjs proofs/opensearch-event/event-store-run.test.mjs",
    );
    expect(manifest.scripts?.["event:store:run"]).toBe("node proofs/opensearch-event/run.mjs --event-store");
    const section = readme.match(/## OpenSearch EventStore proof[\s\S]*?(?=\n## )/)?.[0] ?? "";
    expect(section).toContain("npm run event:store:test\nnpm run event:store:run");
    expect(section).toMatch(/Organization, Workspace, Environment,\s+and session/);
    expect(section).toMatch(/no dotenv, cloud profile, proxy, credential, or shared service\s+input/);
    expect(section).toContain("does not prove AWS OpenSearch Service");
  });
});

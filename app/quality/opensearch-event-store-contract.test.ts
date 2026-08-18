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
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-13")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-14")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-15")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
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

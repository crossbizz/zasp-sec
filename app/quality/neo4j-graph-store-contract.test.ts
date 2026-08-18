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

describe("M1-16 Neo4j GraphStore contract", () => {
  it("binds the adapter to the authoritative task and approved design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-16-neo4j-graph-store-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-16-neo4j-graph-store-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-16 - Neo4j GraphStore\*\*[\s\S]*?\*\*M1-17 - audit emitter contract/)?.[0];

    expect(section).toContain("Depends on: `M1-15`");
    expect(section).toContain("minimal Neo4j node/edge upsert/read contract");
    expect(section).toContain("Scoped upsert/read fixture passes");
    expect(design).toContain("github.com/neo4j/neo4j-go-driver/v6");
    expect(design).toContain("neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357");
    expect(plan).toContain("M1-17 remains Pending");
  });

  it("completes only M1-16 while preserving prior completion and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-16 is Complete");
    expect(tracker).toContain("| Pending | 645 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 79 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`645/1/79/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "12", "1", "55", "0"]);
    expect(active.map(([task]) => task)).toEqual(["M1-38"]);
    expect(complete.filter(([task]) => task === "M1-15")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-16")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-17")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("keeps the provider boundary scoped and excludes raw Cypher", async () => {
    const design = await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-15-m1-16-neo4j-graph-store-design.md"),
      "utf8",
    );

    expect(design).toContain("ZaspGraphNode");
    expect(design).toContain("ZASP_GRAPH_EDGE");
    expect(design).toContain("exact scope");
    expect(design).toContain("No caller value is interpolated into Cypher");
    expect(design).toContain("disposable Neo4j Community image is proof-only");
  });

  it("exposes exact hermetic, live, and license commands with the local-only boundary", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts: Record<string, string> };

    expect(packageJson.scripts["graph:neo4j:test"]).toBe("go test -C services/platform -race -count=1 ./graphstore/... && go test -C proofs/neo4j-graphstore -race -count=1 ./... && node --test proofs/neo4j-graphstore/run.test.mjs proofs/neo4j-graphstore/license-audit.test.mjs");
    expect(packageJson.scripts["graph:neo4j:run"]).toBe("node proofs/neo4j-graphstore/run.mjs");
    expect(packageJson.scripts["graph:neo4j:license"]).toBe("node proofs/neo4j-graphstore/license-audit.mjs");
    expect(readme).toContain("## Neo4j GraphStore proof");
    expect(readme).toContain("npm run graph:neo4j:test");
    expect(readme).toContain("npm run graph:neo4j:run");
    expect(readme).toContain("npm run graph:neo4j:license");
    expect(readme).toContain("Neo4j GraphStore proof passed: nodes=3 edges=2 replay=true scoped=true cross_organization_zero=true cleanup=true audit=true.");
    expect(readme).toContain("local-only compatibility proof");
    expect(readme).toContain("does not accept raw Cypher or customer query text");
    expect(readme).toContain("does not target a shared Neo4j service");
    expect(readme).toContain("does not approve Neo4j Community server packaging or redistribution");
  });
});

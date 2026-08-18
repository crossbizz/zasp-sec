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

describe("M1-21 observability contract", () => {
  it("binds the closed resource and correlation boundary to source and prior OTLP evidence", async () => {
    const [source, prd, design, plan, ingest, ingestNormalizer, exporter] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-21-observability-contract-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-21-observability-contract-implementation-plan.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-14-m0-13-otlp-proof-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "proofs/otlp-ingest/normalizer.mjs"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m0-22-otlp-export-proof-design.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-21 - observability contract\*\*[\s\S]*?\*\*M1-22 - event envelope/)?.[0];

    expect(section).toContain("Depends on: `M1-20`");
    expect(section).toContain("Define common OTLP resource attributes and correlation helper");
    expect(section).toContain("Cardinality/unit test rejects raw customer content attributes");
    expect(prd).toContain("OTLP/gateway attributes for agent, session, task, tool, and sandbox IDs");
    expect(source).toContain("Common attributes must be bounded-cardinality");
    expect(source).toContain("Never export raw prompt text, tool arguments, secret values or arbitrary high-cardinality customer content as operational telemetry");
    for (const key of [
      "service.namespace", "service.name", "service.version",
      "deployment.environment.name", "organization.id", "workspace.id", "environment.id",
    ]) expect(design).toContain(key);
    expect(design).toContain("Correlation is a request/span value, never a resource attribute");
    expect(ingest).toContain("- `organization.id`");
    expect(ingestNormalizer).toContain('["service.name", "zasp.proof.agent"]');
    expect(ingestNormalizer).toContain('["service.version", "1"]');
    expect(ingestNormalizer).toContain('["organization.id", "organizationId"]');
    expect(exporter).toContain("six Organization/agent/session/task/tool/sandbox identities");
    expect(plan).toContain("M1-22 remains Pending");
  });

  it("completes only M1-21 and preserves its prerequisite, successor, and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toMatch(/M1-21\s+is\s+Complete/);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-21")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-20")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-22")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("exposes only the hermetic root command and documents the closed boundary", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts: Record<string, string> };
    const section = readme.match(/## Observability contract[\s\S]*?(?=\n## )/)?.[0] ?? "";

    expect(packageJson.scripts["observability:test"]).toBe("go test -C services/platform -race -count=1 ./observability");
    expect(section).toContain("npm run observability:test");
    for (const key of [
      "service.namespace", "service.name", "service.version",
      "deployment.environment.name", "organization.id", "workspace.id", "environment.id",
    ]) expect(section).toContain(key);
    expect(section).toContain("agentsec-api");
    expect(section).toContain("agentsec-worker");
    for (const deployment of ["development", "test", "staging", "production"]) {
      expect(section).toContain(deployment);
    }
    expect(section).toMatch(/raw prompt\/response text/i);
    expect(section).toMatch(/tool arguments/i);
    expect(section).toMatch(/arbitrary customer content/i);
    expect(section).toMatch(/32-character trace/i);
    expect(section).toMatch(/16-character span/i);
    expect(section).toMatch(/replacement fails closed/i);
    expect(section).toMatch(/hermetic/i);
    expect(section).toMatch(/no OpenTelemetry SDK, exporter,\s+Collector, backend, provider, network, credential, database, or Docker I\/O/i);
    expect(section).toMatch(/M1-22\s+is\s+Complete/);
  });
});

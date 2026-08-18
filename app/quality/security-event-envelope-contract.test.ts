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

function verifyM122CompleteStatus(tracker: string, readme: string) {
  const active = taskRows(tracker, "In progress");
  const complete = taskRows(tracker, "Complete");
  const blocked = taskRows(tracker, "Blocked");
  const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

  expect(readme).toMatch(/M1-22\s+is\s+Complete/);
  expect(tracker).toContain("| Pending | 653 |");
  expect(tracker).toContain("| In progress | 0 |");
  expect(tracker).toContain("| Complete | 72 |");
  expect(tracker).toContain("| Blocked | 3 |");
  expect(tracker).toContain("`653/0/72/3`");
  expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "20", "0", "48", "0"]);
  expect(active.map(([task]) => task)).toEqual([]);
  expect(complete.filter(([task]) => task === "M1-22")).toHaveLength(1);
  expect(complete.filter(([task]) => task === "M1-21")).toHaveLength(1);
  expect(active.filter(([task]) => task === "M1-23")).toHaveLength(0);
  expect(complete.filter(([task]) => task === "M1-23")).toHaveLength(1);
  expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
}

function verifyReadmeBoundary(readme: string) {
  const section = readme.match(/## SecurityEvent envelope[\s\S]*?## Neon pooled proof/)?.[0] ?? "";
  const prose = section.replace(/\s+/g, " ");

  expect(section).toMatch(/^npm run securityevent:test$/m);
  expect(prose).toContain("`Version`, `Scope`, `Source`, `Time`, `Evidence`, and `Correlation`");
  expect(prose).toContain("exactly version 1");
  for (const sourceName of ["runtime_gateway", "otlp", "tetragon", "attack_lab"]) {
    expect(section).toContain(`\`${sourceName}\``);
  }
  expect(prose).toContain("canonical UTC millisecond precision");
  expect(prose).toContain("typed product evidence reference");
  expect(prose).toContain("M1-21 product, trace, and span correlation");
  expect(prose).toContain("raw evidence, payloads, prompts, tool arguments, secrets, arbitrary metadata, and vendor identifiers are not envelope fields");
  expect(prose).toContain("no parser, OpenAPI, transport, adapter, queue, storage, provider, network, credential, database, Docker, filesystem, or environment I/O");
  expect(prose).toContain("M1-23 is Complete");
}

describe("M1-22 SecurityEvent envelope", () => {
  it("binds the source, scope rule, runtime flow, and closed design", async () => {
    const [source, prd, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_PRD_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-22-security-event-envelope-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-22-security-event-envelope-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-22 - event envelope\*\*[\s\S]*?\*\*M1-23 - OpenAPI root/)?.[0] ?? "";

    expect(section).toContain("Depends on: `M1-21`");
    expect(section).toContain("Define SecurityEvent envelope with version, scope, source, time, evidence and correlation fields");
    expect(section).toContain("Unscoped or unknown-version event is rejected");
    expect(prd).toContain("Every transactional row, event document, graph node/edge, artifact reference, queue job and API authorization context carries Organization scope");
    expect(source).toContain("Tetragon / OTLP / runtime gateway / Attack Lab evidence");
    for (const field of ["Version", "Scope", "Source", "Time", "Evidence", "Correlation"]) {
      expect(design).toContain(field);
    }
    for (const sourceName of ["runtime_gateway", "otlp", "tetragon", "attack_lab"]) {
      expect(design).toContain(sourceName);
    }
    expect(design).toContain("exactly `Version1`");
    expect(design).toContain("UTC");
    expect(design).toContain("millisecond precision");
    expect(design).toContain("one valid typed product evidence reference");
    expect(design).toContain("one valid M1-21 correlation value");
    expect(plan).toContain("M1-23 remains Pending");
  });

  it("completes only M1-22 and preserves its prerequisite, successor, and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    verifyM122CompleteStatus(tracker, readme);
  });

  it("exposes the exact hermetic command", async () => {
    const packageText = await readFile(resolve(repositoryRoot, "package.json"), "utf8");
    const packageJson = JSON.parse(packageText) as { scripts?: Record<string, string> };

    expect(packageJson.scripts?.["securityevent:test"]).toBe(
      "go test -C services/platform -race -count=1 ./securityevent",
    );
  });

  it("documents the exact public envelope boundary", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    verifyReadmeBoundary(readme);
  });

  it("rejects duplicate M1-22 Complete rows", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const forged = tracker.replace(
      "| M1-21 |",
      "| M1-22 | August 16, 2026 | forged duplicate |\n| M1-21 |",
    );

    expect(() => verifyM122CompleteStatus(forged, readme)).toThrow();
  });

  it("rejects README command drift", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const drifted = readme.replace("npm run securityevent:test", "npm run securityevent:test-wrong");

    expect(() => verifyReadmeBoundary(drifted)).toThrow();
  });
});

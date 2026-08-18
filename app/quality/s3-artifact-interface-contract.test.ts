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

describe("M1-12 S3 artifact interface contract", () => {
  it("binds the interface to the authoritative dependency and approved boundary", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-12-s3-artifact-interface-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-12-s3-artifact-interface-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-12 - S3 artifact interface\*\*[\s\S]*?\*\*M1-13 - SQS queue interface/)?.[0];

    expect(section).toContain("Depends on: `M1-11`");
    expect(section).toContain("ArtifactStore interface and S3 implementation skeleton");
    expect(section).toContain("Put/Get/Delete fixture passes against LocalStack");
    expect(design).toContain("services/platform/artifactstore");
    expect(design).toContain("M1-13 remains Pending");
    expect(plan).toContain("exact LocalStack lifecycle");
  });

  it("completes only M1-12 after reviewed live verification", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-12 is Complete");
    expect(readme).toContain("Organization-scoped ArtifactStore");
    expect(tracker).toContain("| Pending | 643 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 82 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`643/0/82/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "10", "0", "58", "0"]);
    expect(active.filter(([task]) => task === "M1-12")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-12")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-11")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-13")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-13")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes exact hermetic and live commands with the fixed result boundary", async () => {
    const [manifestText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(manifestText) as { scripts?: Record<string, string> };
    const section = readme.match(/## S3 artifact interface[\s\S]*?## Neon pooled proof/)?.[0];

    expect(manifest.scripts?.["artifact:store:test"]).toBe(
      "cd services/platform && go test -race -count=1 ./artifactstore && cd ../../proofs/localstack-storage && go test -race -count=1 ./... && node --test run.test.mjs artifact-run.test.mjs",
    );
    expect(manifest.scripts?.["artifact:store:run"]).toBe(
      "node proofs/localstack-storage/run-artifact-store.mjs",
    );
    expect(manifest.scripts?.["artifact:store:test"]).not.toMatch(/docker|credential|env-file|source/i);
    expect(section).toContain("npm run artifact:store:test");
    expect(section).toContain("npm run artifact:store:run");
    expect(section).toContain(
      "LocalStack artifact store passed: put=true get=true delete=true scoped=true encrypted=true cleanup=true audit=true container_cleanup=true.",
    );
  });
});

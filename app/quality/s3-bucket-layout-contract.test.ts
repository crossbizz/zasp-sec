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

describe("M1-34 S3 bucket layout", () => {
  it("binds the exact source task to the selected closed design", async () => {
    const [source, design, implementationPlan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-34-s3-bucket-layout-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-34-s3-bucket-layout-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-34 - S3 bucket layout\*\*[\s\S]*?\*\*M1-35 - base web shell/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-33`");
    expect(section).toContain("Deliverable: Define evidence/export/policy key prefixes and KMS configuration contract.");
    expect(section).toContain("Verify: Artifact key builder cannot escape organization/workspace prefix.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "services/platform/bucketlayout",
      "organizations/<organization-product-id>/workspaces/<workspace-product-id>/",
      "environments/<environment-product-id>/<class>/",
      "ClassEvidence",
      "ClassExport",
      "ClassPolicy",
      "zasp-product-data-<deployment-token>",
      "32 lowercase hexadecimal characters",
      "aws:kms",
      "S3 Bucket Key enabled",
      "M1-40",
      "M1A-03",
      "M8-02",
      "will not accept raw object keys",
      "There is no live command",
      "M1-35 remains Pending",
    ]) {
      expect(designProse).toContain(value);
    }
    expect(implementationPlan).toContain("Use genuine tests-first RED/GREEN");
  });

  it("preserves completed M1-34 while M1-35 completes", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-34 is Complete");
    expect(tracker).toContain("| Pending | 642 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 83 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`642/0/83/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "9", "0", "59", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete).toHaveLength(83);
    expect(active.filter(([task]) => task === "M1-34")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-34")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-33")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-35")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes one hermetic package command and the bounded layout contract", async () => {
    const [packageSource, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageManifest = JSON.parse(packageSource) as { scripts?: Record<string, string> };
    const scripts = packageManifest.scripts ?? {};
    const section = readme.match(/## S3 bucket layout[\s\S]*?## Assembled local development target/)?.[0] ?? "";
    const sectionProse = section.replace(/\s+/g, " ");

    expect(scripts["s3:bucket-layout:test"]).toBe(
      "go test -C services/platform -race -count=1 ./bucketlayout",
    );
    expect(scripts["s3:bucket-layout:run"]).toBeUndefined();
    for (const value of [
      "npm run s3:bucket-layout:test",
      "organizations/<organization-product-id>/workspaces/<workspace-product-id>/environments/<environment-product-id>/<class>/",
      "evidence",
      "exports",
      "policies",
      "zasp-product-data-<32-lowercase-hex>",
      "aws:kms",
      "S3 Bucket Key",
      "M1-33 is Complete",
      "M1-35 is Complete",
      "M1A-03",
      "M8-02",
    ]) {
      expect(sectionProse).toContain(value);
    }
    expect(sectionProse).toContain("does not perform provider I/O");
    expect(sectionProse).toContain("does not define IAM, versioning, retention, or lifecycle policy");
  });
});

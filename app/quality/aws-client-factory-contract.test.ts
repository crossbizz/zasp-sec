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

describe("M1-31 LocalStack client factory", () => {
  it("binds the exact source task to the strict selected design", async () => {
    const [source, design, implementationPlan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-17-m1-31-localstack-client-factory-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-17-m1-31-localstack-client-factory-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-31 - LocalStack client factory\*\*[\s\S]*?\*\*M1-32 - OpenSearch index template/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-30`");
    expect(section).toContain("Deliverable: Add AWS endpoint override in product AWS client factory for local/CI only.");
    expect(section).toContain("Verify: Test points SQS/S3/KMS/Secrets/OpenSearch clients at LocalStack.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "One strict factory with an explicit runtime mode and injected lookup (selected).",
      "AWS_ENDPOINT_URL",
      "AWS_ENDPOINT_URL_S3",
      "SQS, S3, KMS, Secrets Manager, and OpenSearch Service",
      "production, local, or CI",
      "fixed synthetic values",
      "uses `aws.NopRetryer`",
      "M1-32 remains Pending",
    ]) {
      expect(designProse).toContain(value);
    }
    expect(designProse).toContain("disables keep-alives and HTTP/2");
    expect(implementationPlan.replace(/\s+/g, " ")).toContain("keep-alives and forced HTTP/2 attempts disabled");
  });

  it("exposes the exact command, dependency inventory, and operator boundary", async () => {
    const [packageText, readme, dependencyLock] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "build/dependencies.lock.yaml"), "utf8"),
    ]);
    const scripts = (JSON.parse(packageText) as { scripts?: Record<string, string> }).scripts ?? {};
    const section = readme.match(/## LocalStack-aware AWS client factory[\s\S]*?(?=\n## )/)?.[0] ?? "";
    const sectionProse = section.replace(/\s+/g, " ");

    expect(scripts["aws:client:test"]).toBe("go test -C services/platform -race -count=1 ./awsclient");
    for (const value of [
      "production, local, and CI",
      "AWS_ENDPOINT_URL",
      "AWS_ENDPOINT_URL_S3",
      "SQS, S3, KMS, Secrets Manager, and OpenSearch Service",
      "synthetic",
      "ambient",
      "does not create a LocalStack lifecycle or provider resource",
      "does not claim LocalStack parity",
      "M1-30 is Complete",
      "M1-32 is Complete",
    ]) {
      expect(sectionProse).toContain(value);
    }

    for (const [name, version] of [
      ["github.com/aws/aws-sdk-go-v2", "v1.43.6"],
      ["github.com/aws/aws-sdk-go-v2/service/kms", "v1.55.6"],
      ["github.com/aws/aws-sdk-go-v2/service/opensearch", "v1.75.6"],
      ["github.com/aws/aws-sdk-go-v2/service/s3", "v1.107.2"],
      ["github.com/aws/aws-sdk-go-v2/service/secretsmanager", "v1.44.6"],
      ["github.com/aws/aws-sdk-go-v2/service/sqs", "v1.46.6"],
    ]) {
      const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const entries = dependencyLock.match(
        new RegExp(`  - ecosystem: go\\n    manifest: services/platform/go\\.mod\\n    name: ${escapedName}\\n    version: ${version.replaceAll(".", "\\.")}\\n    license: Apache-2\\.0\\n    owner: platform-data\\n    scope: runtime\\n    review: approved`, "g"),
      );
      expect(entries).toHaveLength(1);
    }
  });

  it("completes only M1-31 while preserving M1-30, M1-32, and exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-31 is Complete");
    expect(tracker).toContain("| Pending | 641 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 84 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`641/0/84/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "8", "0", "60", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete).toHaveLength(84);
    expect(active.filter(([task]) => task === "M1-31")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-31")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-32")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });
});

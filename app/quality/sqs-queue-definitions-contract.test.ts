import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const testCommand = "go test -C services/platform -race -count=1 ./queuedefinition && go test -C proofs/localstack-sqs -race -count=1 ./... && node --test proofs/localstack-sqs/queue-definitions-run.test.mjs proofs/localstack-storage/run.test.mjs";
const runCommand = "node proofs/localstack-sqs/run-queue-definitions.mjs";
const successLine = "LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true container_cleanup=true.";

type PackageManifest = { scripts?: Record<string, string> };

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

describe("M1-33 SQS queue definitions", () => {
  it("binds the exact source task to the selected closed design", async () => {
    const [source, design, implementationPlan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-33-sqs-queue-definitions-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-18-m1-33-sqs-queue-definitions-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-33 - SQS queue definitions\*\*[\s\S]*?\*\*M1-34 - S3 bucket layout/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-32`");
    expect(section).toContain("Deliverable: Define three queues and DLQs with message schema/retention settings.");
    expect(section).toContain("Verify: LocalStack provision test sees all queues/DLQs.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "services/platform/queuedefinition",
      "agentsec-background",
      "agentsec-background-dlq",
      "agentsec-runtime-events",
      "agentsec-runtime-events-dlq",
      "agentsec-tests",
      "agentsec-tests-dlq",
      "agentsec.background.v1",
      "agentsec.runtime-events.v1",
      "agentsec.tests.v1",
      "MessageRetentionPeriod=345600",
      "MessageRetentionPeriod=1209600",
      "ReceiveMessageWaitTimeSeconds=20",
      "MaximumMessageSize=262144",
      "maxReceiveCount=5",
      "zasp.proof=m1-33",
      "M1-41 remains responsible",
      "M8-03",
      "M1A-04",
      "No real AWS",
      "shared LocalStack container",
      "M1-34 remains Pending",
    ]) {
      expect(designProse).toContain(value);
    }
    expect(implementationPlan).toContain("Use genuine tests-first RED/GREEN");
    expect(implementationPlan).toContain("LocalStack queue definitions passed: queues=3 dlqs=3 schemas=3 retention=true redrive=true cleanup=true audit=true.");
  });

  it("preserves completed M1-33 and M1-34 with exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-33 is Complete");
    expect(tracker).toContain("| Pending | 653 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 72 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`653/0/72/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "20", "0", "48", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete).toHaveLength(72);
    expect(active.filter(([task]) => task === "M1-33")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-33")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-32")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-34")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-34")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes the exact hermetic and disposable live proof boundary", async () => {
    const [manifestText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const manifest = JSON.parse(manifestText) as PackageManifest;
    const section = readme.match(/## SQS queue definitions proof[\s\S]*?## Assembled local development target/)?.[0];
    const sectionProse = section?.replace(/\s+/g, " ");

    expect(manifest.scripts?.["sqs:definitions:test"]).toBe(testCommand);
    expect(manifest.scripts?.["sqs:definitions:run"]).toBe(runCommand);
    expect(section).toBeDefined();
    for (const value of [
      "agentsec-background",
      "agentsec-background-dlq",
      "agentsec-runtime-events",
      "agentsec-runtime-events-dlq",
      "agentsec-tests",
      "agentsec-tests-dlq",
      "agentsec.background.v1",
      "agentsec.runtime-events.v1",
      "agentsec.tests.v1",
      "345600",
      "1209600",
      "300 / 120 / 900",
      "30-second DLQ visibility",
      "20-second long polling",
      "262144-byte maximum messages",
      "maxReceiveCount=5",
      "npm run sqs:definitions:test",
      "npm run sqs:definitions:run",
      successLine,
      "disposable LocalStack container",
      "does not read or mutate a shared LocalStack container",
      "M1-41",
      "M1A-04",
      "M8-03",
      "M1-32 is Complete",
      "M1-34 is Complete",
    ]) expect(sectionProse).toContain(value);
  });
});

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

describe("M1-13 SQS queue interface contract", () => {
  it("binds the interface to the authoritative dependency and approved boundary", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-13-sqs-queue-interface-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-13-sqs-queue-interface-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-13 - SQS queue interface\*\*[\s\S]*?\*\*M1-14 - OpenSearch EventStore/)?.[0];

    expect(section).toContain("Depends on: `M1-12`");
    expect(section).toContain("JobQueue interface and SQS batch implementation skeleton");
    expect(section).toContain("Batch publish/consume fixture passes against LocalStack");
    expect(design).toContain("services/platform/jobqueue");
    expect(design).toContain("M1-14 remains Pending");
    expect(plan).toContain("exact disposable LocalStack lifecycle");
  });

  it("retains M1-13 completion after M1-14 completes", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-13 is Complete");
    expect(readme).toContain("Organization-scoped JobQueue");
    expect(tracker).toContain("| Pending | 640 |");
    expect(tracker).toContain("| In progress | 1 |");
    expect(tracker).toContain("| Complete | 84 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`640/1/84/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "7", "1", "60", "0"]);
    expect(active.map(([task]) => task)).toEqual(["M1-43"]);
    expect(complete.filter(([task]) => task === "M1-13")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-14")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-12")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-15")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes hermetic and disposable root commands without ambient cloud configuration", async () => {
    const [manifest, readme, module] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "proofs/localstack-sqs/go.mod"), "utf8"),
    ]);
    const scripts = (JSON.parse(manifest) as { scripts?: Record<string, string> }).scripts;
    expect(scripts?.["job:queue:test"]).toBe(
      "go test -C services/platform -race -count=1 ./jobqueue && go test -C proofs/localstack-sqs -race -count=1 ./... && node --test proofs/localstack-sqs/job-run.test.mjs proofs/localstack-storage/run.test.mjs",
    );
    expect(scripts?.["job:queue:run"]).toBe("node proofs/localstack-sqs/run-job-queue.mjs");
    const section = readme.match(/## SQS job queue interface[\s\S]*?```bash\n([\s\S]*?)\n```/)?.[1];
    expect(section?.split("\n")).toEqual(["npm run job:queue:test", "npm run job:queue:run"]);
    expect(readme).toContain("disposable LocalStack SQS compatibility only");
    expect(readme).toContain("does not read dotenv, cloud profiles, proxies, or real AWS credentials");
    expect(module).toContain("github.com/zasp-ai/zasp-sec/services/platform v0.0.0");
    expect(module).toContain("replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform");
  });
});

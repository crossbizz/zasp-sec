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
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-13")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-14")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-12")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-15")).toHaveLength(0);
    expect(blocked.map(([task]) => task)).toEqual(["M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
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

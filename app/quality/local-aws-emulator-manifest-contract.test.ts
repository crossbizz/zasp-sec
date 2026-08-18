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

describe("M1-30d local AWS emulator manifest", () => {
  it("binds the exact source task to the selected internal S3 endpoint design", async () => {
    const [source, design] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-17-m1-30d-local-aws-emulator-manifest-design.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-30d - local AWS emulator manifest\*\*[\s\S]*?\*\*M1-30 - local dev manifests/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-30c`");
    expect(section).toContain("Deliverable: Add LocalStack service and endpoint environment variables for local AWS clients.");
    expect(section).toContain("Verify: A test S3 call uses the LocalStack endpoint.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "Add a separate LocalStack core overlay and staged S3 Job (selected).",
      "one `ConfigMap` named `local-aws-endpoints`",
      "one single-replica `Deployment` named `localstack`",
      "one internal `ClusterIP` `Service` named `localstack`",
      "one `Job` named `localstack-s3-probe`",
      "AWS_ENDPOINT_URL=http://localstack.zasp-local.svc.cluster.local:4566",
      "AWS_ENDPOINT_URL_S3=http://localstack.zasp-local.svc.cluster.local:4566",
      "localstack/localstack:4.7.0@sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
      "performs `s3api list-buckets`",
      "never reads the ambient kubeconfig or current context",
      "Cleanup runs in reverse dependency order",
      "Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.",
    ]) {
      expect(designProse).toContain(value);
    }
  });

  it("completes only M1-30d and preserves completed dependencies and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-30d is Complete");
    expect(readme).toContain("M1-30 is Complete");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete.length).toBeGreaterThan(0);
    expect(active.filter(([task]) => task === "M1-30d")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30d")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30c")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30a")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-30")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("keeps endpoint wiring synthetic and defers product client behavior", async () => {
    const design = (await readFile(
      resolve(repositoryRoot, "docs/internal/2026-08-17-m1-30d-local-aws-emulator-manifest-design.md"),
      "utf8",
    )).replace(/\s+/g, " ");

    for (const value of [
      "No current product binary has the M1-31 client factory",
      "M1-31 can consume the same names and values",
      "fixed synthetic local values",
      "no token, session credential, profile, role, web-identity file, proxy, dotenv value, ambient host environment, or Kubernetes API credential",
      "never targets a shared Kubernetes or LocalStack instance",
    ]) {
      expect(design).toContain(value);
    }
  });

  it("exposes only the exact hermetic, live, and license commands with bounded operator guidance", async () => {
    const [packageSource, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const scripts = JSON.parse(packageSource).scripts as Record<string, string>;
    const section = readme.match(/## Local AWS emulator Kubernetes manifest proof[\s\S]*?(?=\n## )/)?.[0] ?? "";

    expect(scripts["local:aws-emulator:test"]).toBe(
      "node --test deploy/local/manifests.test.mjs deploy/local/run.test.mjs deploy/local/graph-manifest.test.mjs deploy/local/graph-run.test.mjs deploy/local/graph-license-audit.test.mjs deploy/local/observability-manifest.test.mjs deploy/local/observability-run.test.mjs deploy/local/observability-license-audit.test.mjs deploy/local/aws-emulator-manifest.test.mjs deploy/local/aws-emulator-run.test.mjs deploy/local/aws-emulator-license-audit.test.mjs",
    );
    expect(scripts["local:aws-emulator:run"]).toBe("node deploy/local/aws-emulator-run.mjs");
    expect(scripts["local:aws-emulator:license"]).toBe("node deploy/local/aws-emulator-license-audit.mjs");
    for (const value of [
      "npm run local:aws-emulator:test",
      "npm run local:aws-emulator:license",
      "npm run local:aws-emulator:run",
      "Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.",
      "Local AWS emulator manifest failed: <category> rejected.",
      "AWS_ENDPOINT_URL",
      "AWS_ENDPOINT_URL_S3",
      "localstack-s3-probe",
      "synthetic credentials",
      "LocalStack Community",
      "M1-31",
    ]) {
      expect(section).toContain(value);
    }
    for (const forbidden of [
      "production AWS parity",
      "shared LocalStack is modified",
      "reads the ambient kubeconfig",
      "product AWS clients are wired",
    ]) {
      expect(section).not.toContain(forbidden);
    }
  });
});

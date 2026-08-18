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
    expect(tracker).toContain("| Pending | 643 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 82 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`643/0/82/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "10", "0", "58", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete).toHaveLength(82);
    expect(active.filter(([task]) => task === "M1-30d")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30d")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30c")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30a")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-30")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
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

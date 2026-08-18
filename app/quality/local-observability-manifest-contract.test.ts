import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { OBSERVABILITY_FAILURE_CATEGORIES } from "../../deploy/local/observability-run.mjs";

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

describe("M1-30c local observability manifest", () => {
  it("binds the exact source task to the reviewed local observability design", async () => {
    const [source, design] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-30c-local-observability-manifest-design.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-30c - local observability manifest\*\*[\s\S]*?\*\*M1-30d/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-30b`");
    expect(section).toContain("Deliverable: Add local OpenTelemetry Collector with a no-egress debug/test sink.");
    expect(section).toContain("Verify: A test span reaches the local sink.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "Add a separate Collector overlay with a file-backed test sink (selected).",
      "exactly four namespaced resources",
      "ConfigMap",
      "Deployment",
      "ClusterIP",
      "one one-shot `Job`",
      "observability-core, and test-span manifests in fixed order",
      "only after the Collector pod and EndpointSlice are exact and Ready",
      "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
      "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
      "configuration contains only a local file exporter and no remote exporter, destination, credential, proxy, or backend",
      "seven ordered resource attributes match the M1-21 product observability contract",
      "create a false enforcement claim, so this task does not do that",
      "Cleanup runs in reverse dependency order",
      "Local observability manifest passed: ready=true internal=true no_egress=true spans=1 sink=true cleanup=true.",
    ]) {
      expect(designProse).toContain(value);
    }
  });

  it("preserves M1-30c completion while M1-30d completes", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-30c is Complete");
    expect(readme).toContain("M1-30d is Complete");
    expect(tracker).toContain("| Pending | 655 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 70 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`655/0/70/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "22", "0", "46", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete).toHaveLength(70);
    expect(active.filter(([task]) => task === "M1-30c")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30c")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30a")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-30d")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30d")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes exact hermetic, live, and license commands with the local-only observability boundary", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts?: Record<string, unknown> };
    const section = (readme.match(/## Local observability Kubernetes manifest proof[\s\S]*?(?=\n## |$)/)?.[0] ?? "").replace(/\s+/g, " ");

    expect(packageJson.scripts).toMatchObject({
      "local:observability:test": "node --test deploy/local/manifests.test.mjs deploy/local/run.test.mjs deploy/local/graph-manifest.test.mjs deploy/local/graph-run.test.mjs deploy/local/graph-license-audit.test.mjs deploy/local/observability-manifest.test.mjs deploy/local/observability-run.test.mjs deploy/local/observability-license-audit.test.mjs",
      "local:observability:run": "node deploy/local/observability-run.mjs",
      "local:observability:license": "node deploy/local/observability-license-audit.mjs",
    });
    for (const text of [
      "M1-30c is Complete",
      "M1-30d is Complete",
      "Node.js 22.23.1 and npm 10.9.8",
      "Local observability manifest passed: ready=true internal=true no_egress=true spans=1 sink=true cleanup=true.",
      "Local observability manifest failed: <category> rejected.",
      "only after the Collector pod and EndpointSlice are exact and Ready",
      "exactly one fixed synthetic M1-21 span",
      "cluster-internal ClusterIP OTLP Service",
      "no host-published OTLP port",
      "file-backed `emptyDir` sink",
      "configuration-level claim",
      "not NetworkPolicy or firewall enforcement",
      "does not read `.env`, ambient kubeconfig, cloud credentials, profiles, proxy variables, or provider data",
      "shared images are read-only baselines and are never cleaned",
      "otel/opentelemetry-collector-contrib:0.158.0@sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
      "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
      "Apache-2.0",
      "GPL-2.0-only",
      "opt-in local development",
      "does not approve redistribution or production packaging",
    ]) {
      expect(section).toContain(text);
    }
    const failureCategories = section.match(/The only failure categories, in order, are `([^`]+)`\./)?.[1]?.split(", ");
    expect(failureCategories).toEqual(OBSERVABILITY_FAILURE_CATEGORIES);
    for (const forbidden of [
      "ambient kubeconfig is reused",
      "host-published OTLP port is required",
      "NetworkPolicy enforcement is proved",
      "remote telemetry backend",
      "production packaging is approved",
      "shared images are removed",
    ]) {
      expect(section).not.toContain(forbidden);
    }
  });
});

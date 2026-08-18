import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { GRAPH_FAILURE_CATEGORIES } from "../../deploy/local/graph-run.mjs";

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

describe("M1-30b local graph manifest", () => {
  it("binds the exact source task to the selected local graph design", async () => {
    const [source, design] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-30b-local-graph-manifest-design.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-30b - local graph manifest\*\*[\s\S]*?\*\*M1-30c/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-30a`");
    expect(section).toContain("Deliverable: Add local Neo4j service and persistent test volume configuration.");
    expect(section).toContain("Verify: Graph health is reachable only inside the local cluster.");
    for (const value of [
      "Add a separate graph overlay and combined disposable runner (selected).",
      "exactly five resources",
      "PersistentVolume",
      "PersistentVolumeClaim",
      "Deployment",
      "ClusterIP",
      "one one-shot `Job`",
      "neo4j:5.26.28-community@sha256:ff32db30b2baff97971e441b46bfd9c832c1b62c970398ef579244c06b21d357",
      "registry.k8s.io/e2e-test-images/busybox:1.36.1-1@sha256:a9155b13325b2abef48e71de77bb8ac015412a566829f621d06bfae5c699b1b9",
      "reachable through a `ClusterIP` Service from inside the cluster",
      "one synthetic graph marker across a pod replacement",
      "Neo4j Community is GPL-3.0-only, and BusyBox is GPL-2.0-only",
      "Cleanup runs in reverse dependency order",
      "Local graph manifest passed: ready=true internal=true persistent=true cleanup=true.",
    ]) {
      expect(designProse).toContain(value);
    }
  });

  it("completes only M1-30b and preserves its dependent work and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-30b is Complete");
    expect(readme).toContain("M1-30c is Complete");
    expect(readme).toContain("M1-30d is Complete");
    expect(tracker).toContain("| Pending | 644 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 81 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`644/0/81/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "11", "0", "57", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete).toHaveLength(81);
    expect(active.filter(([task]) => task === "M1-30b")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30b")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-30a")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-30c")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30c")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-30d")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30d")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes the hermetic, live, and license graph commands with their local-only operator boundary", async () => {
    const [packageText, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const packageJson = JSON.parse(packageText) as { scripts?: Record<string, unknown> };
    const localGraph = (readme.match(/## Local graph Kubernetes manifest proof[\s\S]*?(?=\n## |$)/)?.[0] ?? "").replace(/\s+/g, " ");

    expect(packageJson.scripts).toMatchObject({
      "local:graph:test": "node --test deploy/local/manifests.test.mjs deploy/local/run.test.mjs deploy/local/graph-manifest.test.mjs deploy/local/graph-run.test.mjs deploy/local/graph-license-audit.test.mjs",
      "local:graph:run": "node deploy/local/graph-run.mjs",
      "local:graph:license": "node deploy/local/graph-license-audit.mjs",
    });
    for (const text of [
      "Node.js 22.23.1 and npm 10.9.8",
      "Local graph manifest passed: ready=true internal=true persistent=true cleanup=true.",
      "Local graph manifest failed: <category> rejected.",
      "only inside the disposable local cluster",
      "does not read `.env`, ambient kubeconfig, cloud credentials, profiles, proxy variables, provider data",
      "PVC preserves the synthetic marker across an owned Neo4j pod replacement",
      "data is disposable with the owned kind cluster",
      "GPL-3.0-only",
      "GPL-2.0-only",
      "opt-in local development",
      "does not approve redistribution or production packaging",
      "M1-30b is Complete",
      "M1-30c is Complete",
      "M1-30d is Complete",
    ]) {
      expect(localGraph).toContain(text);
    }
    const failureCategories = localGraph.match(/The only failure categories, in order, are `([^`]+)`\./)?.[1]?.split(", ");
    expect(failureCategories).toEqual(GRAPH_FAILURE_CATEGORIES);
    expect(localGraph).toContain("The runner creates and uses its own kubeconfig;");
    expect(localGraph).not.toMatch(/host port|Ingress|NodePort|LoadBalancer/i);
  });
});

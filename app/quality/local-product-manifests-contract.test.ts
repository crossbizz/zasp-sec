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

describe("M1-30a local product manifests", () => {
  it("binds the exact source task to the disposable real-command design and plan", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-30a-local-product-manifests-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-30a-local-product-manifests-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-30a - local product manifests\*\*[\s\S]*?\*\*M1-30b/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");
    const planProse = plan.replace(/^>\s?/gm, "").replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-29`");
    expect(section).toContain(
      "Create local Kubernetes manifests for product API, worker, event-ingest and runtime-gateway stubs",
    );
    expect(section).toContain("All four pods become Ready in local Kubernetes");
    for (const value of [
      "disposable kind cluster",
      "`agentsec-api`",
      "`agentsec-worker`",
      "`event-ingest`",
      "`runtime-gateway`",
      "one `Namespace`, four `Deployment` objects, and four internal `ClusterIP` `Service` objects",
      "`scratch` images",
      "never targets the ambient OrbStack cluster",
      "pods=4 ready=4 services=4 internal=true cleanup=true",
      "`661/1/63/3`",
      "`68/28/1/39/0`",
    ]) {
      expect(designProse).toContain(value);
    }
    expect(planProse).toContain("Every behavior or status change requires a witnessed tests-only RED first");
    expect(planProse).toContain("Publish no host port and create no Ingress, NodePort, LoadBalancer");
    expect(planProse).toContain("M1-30b remains Pending");
  });

  it("completes only M1-30a after review and preserves exact blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-30a is Complete");
    expect(readme).toContain("M1-30b is Complete");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).not.toHaveLength(0);
    expect(active.filter(([task]) => task === "M1-30a")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30a")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-29")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-30b")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30b")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-30d")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30d")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("preserves the exact hermetic and disposable live commands after later profiles complete", async () => {
    const [readme, packageText, runner, manifest] = await Promise.all([
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "deploy/local/run.mjs"), "utf8"),
      readFile(resolve(repositoryRoot, "deploy/local/product-stubs.yaml"), "utf8"),
    ]);
    const scripts = JSON.parse(packageText).scripts as Record<string, string>;
    const section = readme.match(/## Local product Kubernetes manifests[\s\S]*?(?=\n## )/)?.[0] ?? "";
    const sectionProse = section.replace(/\s+/g, " ");

    expect(scripts["local:product:test"]).toBe(
      "node --test deploy/local/manifests.test.mjs deploy/local/run.test.mjs",
    );
    expect(scripts["local:product:run"]).toBe("node deploy/local/run.mjs");
    for (const value of [
      "agentsec-api",
      "agentsec-worker",
      "event-ingest",
      "runtime-gateway",
      "cluster-internal",
      "Docker 29.4.0",
      "Go 1.25.6",
      "kubectl 1.35",
      "macOS or Linux",
      "outbound HTTPS access to the pinned kind GitHub release asset",
      "npm run local:product:test",
      "npm run local:product:run",
      "Local product manifests passed: pods=4 ready=4 services=4 internal=true cleanup=true.",
      "exact-owned disposable kind cluster",
      "reverse cleanup",
      "M1-30b is Complete",
    ]) expect(sectionProse).toContain(value);
    expect(runner).toContain("await runMain();");
    expect(manifest).toContain("kind: Deployment");
    expect(section).not.toMatch(/NodePort|LoadBalancer|Ingress|ambient kubeconfig/i);
  });
});

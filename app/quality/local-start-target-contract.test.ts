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

describe("M1-30 assembled local start target", () => {
  it("binds the exact source task to one disposable assembled start target", async () => {
    const [source, design] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-17-m1-30-local-dev-manifests-design.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-30 - local dev manifests\*\*[\s\S]*?\*\*M1-31 - LocalStack client factory/)?.[0] ?? "";
    const designProse = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-30d`");
    expect(section).toContain("Deliverable: Add one local start target for the assembled manifests.");
    expect(section).toContain("Verify: Local environment starts without vendor dashboards exposed.");
    expect(section).toContain("Timebox: <=15 minutes.");
    for (const value of [
      "Add a thin canonical start target over the reviewed M1-30d lifecycle (selected).",
      "npm run local:start",
      "the exact delegated profile `m1-30d`",
      "zero `Ingress` resources",
      "zero `NodePort`, `LoadBalancer`, or `ExternalName` Services",
      "zero container `hostPort` fields",
      "does not leave a mutable cluster running after success",
      "Product AWS endpoint consumption remains M1-31",
      "Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.",
    ]) {
      expect(designProse).toContain(value);
    }
  });

  it("completes only M1-30 while preserving completed profiles, pending work, and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-30 is Complete");
    expect(readme).toContain("M1-31");
    expect(tracker).toContain("| Pending | 561 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 164 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`561/0/164/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete).toHaveLength(164);
    expect(active.filter(([task]) => task === "M1-30")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-30")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-31")).toHaveLength(1);
    for (const dependency of ["M1-30a", "M1-30b", "M1-30c", "M1-30d"]) {
      expect(complete.filter(([task]) => task === dependency)).toHaveLength(1);
    }
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("exposes one bounded assembled root command without claiming persistent or product AWS behavior", async () => {
    const [packageSource, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "package.json"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const scripts = JSON.parse(packageSource).scripts as Record<string, string>;
    const section = readme.match(/## Assembled local development target[\s\S]*?(?=\n## )/)?.[0] ?? "";
    const sectionProse = section.replace(/\s+/g, " ");

    expect(scripts["local:start"]).toBe("node deploy/local/start.mjs");
    for (const value of [
      "M1-30 is Complete",
      "M1-30a, M1-30b, M1-30c, and M1-30d",
      "Node.js `22.23.1` and npm `10.9.8`",
      "npm run local:start",
      "opt-in",
      "start-and-verify",
      "one disposable kind cluster",
      "ClusterIP-only",
      "no Ingress, NodePort, LoadBalancer, or host workload port",
      "never reads the ambient kubeconfig",
      "reverse cleanup",
      "reuses the reviewed graph, observability, and AWS emulator immutable license audits",
      "Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.",
      "Local AWS emulator manifest failed: <category> rejected.",
      "M1-31",
    ]) {
      expect(sectionProse).toContain(value);
    }
    for (const forbidden of [
      "persistent local cluster",
      "vendor dashboard is exposed",
      "production parity",
      "product AWS clients are wired",
      "shared resource is modified",
    ]) {
      expect(sectionProse).not.toContain(forbidden);
    }
  });
});

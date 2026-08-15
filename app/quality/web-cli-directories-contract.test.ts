import { readdir, readFile } from "node:fs/promises";
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

describe("M1-01c web and CLI directories repository contract", () => {
  it("binds the source task to the existing web build and standalone CLI", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01c-web-cli-directories-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-15-m1-01c-web-cli-directories-implementation-plan.md"), "utf8"),
    ]);
    const sourceSection = source.match(/\*\*M1-01c - web and CLI directories\*\*[\s\S]*?\*\*M1-01 - repo skeleton/)?.[0];

    expect(sourceSection).toContain("Depends on: `M1-01b`");
    expect(sourceSection).toContain("Create Next.js web shell and agentsecctl command skeleton");
    expect(sourceSection).toContain("Web build and agentsecctl version command succeed");
    expect(source).toContain("apps/web                       Next.js/React product UI");
    expect(source).toContain("cmd/agentsecctl                edge/single-tenant preflight, recovery and diagnostics");
    expect(design).toContain("apps/web/package.json");
    expect(design).toContain("cmd/agentsecctl/go.mod");
    expect(design).toContain("agentsecctl version <version>");
    expect(design).toContain("existing runnable product UI without copying or forking it");
    expect(plan).toContain("Every behavior or status change has a witnessed tests-only RED");
    expect(plan).toContain("M1-01 remains Pending");
  });

  it("completes only M1-01c after completed worker directories", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const summary = markdownRows(tracker.match(/## Status summary[\s\S]*?## Milestone summary/)?.[0] ?? "").slice(2);
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);
    const m0 = milestones.find(([milestone]) => milestone === "M0");
    const m1 = milestones.find(([milestone]) => milestone === "M1");

    expect(readme).toContain("M1-01c is Complete");
    expect(readme).toContain("npm --prefix apps/web run build");
    expect(readme).toContain("agentsecctl version <version>");
    expect(readme).toContain("does not implement preflight");
    expect(tracker).toContain("| Pending | 691 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 34 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`691/0/34/3`");
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "58", "0", "10", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-01c")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01b")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-01")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("keeps web dependency ownership at root and the CLI boundary no-I/O", async () => {
    const [webPackageText, webFiles, goModule, cliSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "apps/web/package.json"), "utf8"),
      readdir(resolve(repositoryRoot, "apps/web")),
      readFile(resolve(repositoryRoot, "cmd/agentsecctl/go.mod"), "utf8"),
      readFile(resolve(repositoryRoot, "cmd/agentsecctl/main.go"), "utf8"),
    ]);
    const webPackage = JSON.parse(webPackageText) as Record<string, unknown>;

    expect(webPackage).toEqual({
      name: "@zasp/web",
      version: "0.0.0",
      private: true,
      engines: { node: "22.23.1" },
      scripts: { build: "npm --prefix ../.. run build" },
    });
    expect(webFiles.sort()).toEqual(["README.md", "package.json"]);
    expect(goModule).toBe("module github.com/zasp-ai/zasp-sec/cmd/agentsecctl\n\ngo 1.25.0\n");
    expect(cliSource).toContain('"agentsecctl version " + version + "\\n"');
    for (const forbidden of ["os.Getenv", "net/http", "net.Listen", "AWS_", "KUBECONFIG", "STYTCH_"]) {
      expect(cliSource).not.toContain(forbidden);
    }
  });
});

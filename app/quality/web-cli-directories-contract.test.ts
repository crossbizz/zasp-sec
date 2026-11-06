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
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(m0).toEqual(["M0", "27", "0", "0", "24", "3"]);
    expect(m1).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(summary.reduce((sum, [, count]) => sum + Number(count), 0)).toBe(728);
    expect(active).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-01c")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-01b")).toHaveLength(1);
    expect([...active, ...complete].filter(([task]) => task === "M1-01")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
    expect(tracker).toContain("R-03 remains incomplete");
    expect(tracker).toContain("R-11 remains Not run");
  });

  it("keeps web dependency ownership at root and the CLI boundary no-I/O", async () => {
    const [webPackageText, webFiles, goModule, platformModule, cliSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "apps/web/package.json"), "utf8"),
      readdir(resolve(repositoryRoot, "apps/web")),
      readFile(resolve(repositoryRoot, "cmd/agentsecctl/go.mod"), "utf8"),
      readFile(resolve(repositoryRoot, "services/platform/go.mod"), "utf8"),
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
    expect(webFiles.sort()).toEqual(["README.md", "api", "package.json"]);
    // The version entrypoint remains no-I/O; live preflight now delegates to
    // the reviewed platform module instead of the original empty CLI skeleton.
    const lines = goModule.split("\n").map(line => line.trim()).filter(Boolean);
    expect(lines.filter(line => line.startsWith("module "))).toEqual(["module github.com/zasp-ai/zasp-sec/cmd/agentsecctl"]);
    expect(lines.filter(line => line.startsWith("go "))).toEqual(["go 1.26.0"]);
    expect(lines.filter(line => line.startsWith("replace ")).sort()).toEqual([
      "replace github.com/zasp-ai/zasp-sec/services/health => ../../services/health",
      "replace github.com/zasp-ai/zasp-sec/services/platform => ../../services/platform",
    ]);
    const requirement = /^(?:require\s+)?(\S+)\s+(v[\w.+-]+)(?:\s+\/\/ (indirect))?$/;
    const requirements = lines.flatMap(line => {
      const match = requirement.exec(line);
      return match ? [{ name: match[1], version: match[2], indirect: match[3] === "indirect" }] : [];
    });
    expect(requirements.filter(entry => !entry.indirect)).toEqual([
      { name: "github.com/zasp-ai/zasp-sec/services/platform", version: "v0.0.0", indirect: false },
    ]);
    expect(new Set(requirements.map(entry => entry.name)).size).toBe(requirements.length);
    const platformPins = new Map(platformModule.split("\n").flatMap(line => {
      const match = requirement.exec(line.trim());
      return match ? [[match[1], match[2]] as const] : [];
    }));
    const indirect = requirements.filter(entry => entry.indirect);
    expect(indirect.length).toBeGreaterThan(0);
    for (const entry of indirect) {
      expect(entry.name).toMatch(/^(?:github\.com\/aws\/(?:aws-sdk-go-v2(?:\/[a-z0-9/.-]+)?|smithy-go)|github\.com\/jackc\/(?:pgx\/v5|pgpassfile|pgservicefile|puddle\/v2)|golang\.org\/x\/(?:sync|text))$/);
      expect(entry.version).toBe(platformPins.get(entry.name));
    }
    expect(lines.filter(line => !requirement.test(line) && !/^(?:module |go |replace |require \($|\)$)/.test(line))).toEqual([]);
    expect(cliSource).toContain('"agentsecctl version " + version + "\\n"');
    for (const forbidden of ["os.Getenv", "net/http", "net.Listen", "AWS_", "KUBECONFIG", "STYTCH_"]) {
      expect(cliSource).not.toContain(forbidden);
    }
  });
});

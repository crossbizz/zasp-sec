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

describe("M1-24 generated TypeScript client", () => {
  it("binds the source, public API rule, dependency, and closed design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-24-generated-ts-client-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-24-generated-ts-client-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-24 - generated TS client\*\*[\s\S]*?\*\*M1-25 - UI API map seed/)?.[0] ?? "";

    expect(section).toContain("Depends on: `M1-23`");
    expect(section).toContain("Generate the frontend API client from OpenAPI");
    expect(section).toContain("Generated package compiles and is reproducible");
    expect(source).toContain("Normal UI code may not hand-write `/api/v1/` fetch URLs");
    const designProse = design.replace(/\s+/g, " ");
    for (const text of [
      "openapi-typescript` 7.13.0",
      "openapi-fetch` 0.17.0",
      "apps/web/api/generated.ts",
      "apps/web/api/client.ts",
      "openapi:generate",
      "openapi:check",
      "--check",
      "no callable endpoint",
      "no default remote server",
      "M1-25 remains Pending",
    ]) {
      expect(designProse).toContain(text);
    }
    expect(plan).toContain("Every source/status behavior change has a witnessed tests-only RED");
    expect(plan).toContain("M1-25 remains Pending");
  });

  it("completes only M1-24 and preserves its prerequisite, successor, and blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-24 is Complete");
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "0", "0", "68", "0"]);
    expect(active).not.toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-24")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-23")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-25")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-25")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("documents the exact generated-client and zero-operation boundary", async () => {
    const [readme, clientSource] = await Promise.all([
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
      readFile(resolve(repositoryRoot, "apps/web/api/client.ts"), "utf8"),
    ]);
    const section = readme.match(/## OpenAPI root[\s\S]*?## Neon pooled proof/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    for (const path of ["apps/web/api/generated.ts", "apps/web/api/client.ts"]) {
      expect(section).toContain(`\`${path}\``);
    }
    expect(section).toMatch(/^npm run openapi:generate$/m);
    expect(section).toMatch(/^npm run openapi:check$/m);
    expect(prose).toContain("`openapi-typescript` 7.13.0");
    expect(prose).toContain("`openapi-fetch` 0.17.0");
    expect(prose).toContain("no callable endpoint");
    expect(prose).toContain("no default remote server");
    expect(prose).toContain("performs no I/O during construction");
    expect(prose).toContain("does not hand-write `/api/v1/` URLs");
    expect(prose).toContain("M1-24 is Complete");
    expect(prose).toContain("M1-25 is Complete");
    expect(clientSource).not.toContain("/api/v1/");
    expect(clientSource).not.toContain("process.env");
  });
});

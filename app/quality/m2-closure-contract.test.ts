import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const closingTasks = [
  "M2-44", "M2-45", "M2-46a", "M2-46b", "M2-46c", "M2-46",
  "M2-47a", "M2-47b", "M2-47c", "M2-47d", "M2-47e",
  "M2-48", "M2-49", "M2-50", "M2-47",
] as const;

function rows(tracker: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return section.split("\n").filter((line) => line.startsWith("|")).slice(2)
    .map((line) => line.split("|").slice(1, -1).map((cell) => cell.trim()));
}

describe("M2 identity and authorization milestone closure", () => {
  it("moves all fifteen remaining M2 tasks to Complete in one reviewed batch", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const complete = rows(tracker, "Complete").map(([task]) => task);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toContain("| M2 | 72 | 0 | 0 | 72 | 0 |");
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(complete.length).toBeGreaterThan(0);
    expect(new Set(complete).size).toBe(complete.length);
    for (const task of closingTasks) expect(complete.filter((value) => value === task)).toHaveLength(1);
    expect(rows(tracker, "In progress")).toHaveLength(0);
    expect(rows(tracker, "Blocked").map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("binds the final product UI to the generated API and records the M2 gate PASS", async () => {
    const [app, tokenView, scopeView, map, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "app/components/ZaspProductionApp.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/APIAccessView.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/ScopeOnboardingView.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    expect(app).toContain('path === "/administration/api-access"');
    expect(tokenView).toContain("client ? createAPIAccessAPI(client)");
    expect(scopeView).toContain("client ? createScopeAdminAPI(client)");
    expect(tokenView).not.toContain("createAPIClient()");
    expect(scopeView).not.toContain("createAPIClient()");
    expect(map.match(/availability: planned/g)).toHaveLength(49);
    expect(map.match(/availability: available/g)).toHaveLength(84);
    expect(map.match(/availability: api_available/g)).toHaveLength(7);
    expect(readme).toContain("M2-01 through M2-50 and the M2-47 gate are Complete");
    expect(readme).toContain("M2 gate: PASS");
    expect(readme).toContain("M3-01 through M3-13 are Complete");
  });
});

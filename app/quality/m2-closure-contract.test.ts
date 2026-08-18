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
    expect(rows(tracker, "In progress")).not.toHaveLength(0);
    expect(rows(tracker, "Blocked").map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("binds the final product UI to the generated API and records the M2 gate PASS", async () => {
    const [app, tokenView, scopeView, map, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "app/components/ZaspApp.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/APIAccessView.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/ScopeOnboardingView.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    expect(app).toContain('route.path === "/administration/api-access"');
    expect(tokenView).toContain("createAPIClient()");
    expect(scopeView).toContain("createAPIClient()");
    expect(map.match(/availability: available/g)).toHaveLength(20);
    expect(map.match(/availability: api_available/g)).toHaveLength(84);
    expect(readme).toContain("M2-01 through M2-50 and the M2-47 gate are Complete");
    expect(readme).toContain("M2 gate: PASS");
    expect(readme).toContain("M3-01 through M3-13 are Complete");
  });
});

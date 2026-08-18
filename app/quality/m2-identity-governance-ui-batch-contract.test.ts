import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
const batch = [
  "M2-31", "M2-32", "M2-33", "M2-34", "M2-35", "M2-36", "M2-37", "M2-38",
  "M2-39a", "M2-39b", "M2-39", "M2-40", "M2-41", "M2-42",
  "M2-43a", "M2-43b", "M2-43c", "M2-43d", "M2-43e", "M2-43",
] as const;

function taskRows(tracker: string, heading: "In progress" | "Complete" | "Blocked") {
  const end = heading === "In progress" ? "Complete" : heading === "Complete" ? "Blocked" : "Review findings";
  const section = tracker.match(new RegExp(`## ${heading}[\\s\\S]*?## ${end}`))?.[0] ?? "";
  return section.split("\n").filter((line) => line.startsWith("|")).slice(2)
    .map((line) => line.split("|").slice(1, -1).map((cell) => cell.trim()));
}

describe("M2 identity governance and UI batch", () => {
  it("moves exactly twenty related source tasks to Complete", async () => {
    const tracker = await readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8");
    const complete = taskRows(tracker, "Complete").map(([task]) => task);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Blocked \| \d+ \|/m);
    expect(tracker).toContain("| M2 | 72 | 0 | 0 | 72 | 0 |");
    expect(tracker).toMatch(/`\d+\/\d+\/\d+\/\d+`/);
    expect(complete.length).toBeGreaterThan(0);
    expect(new Set(complete).size).toBe(complete.length);
    for (const task of batch) expect(complete.filter((value) => value === task)).toHaveLength(1);
    expect(taskRows(tracker, "In progress")).not.toHaveLength(0);
    expect(taskRows(tracker, "Blocked").map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("binds all eight governance operations to OpenAPI and honest UI lifecycle", async () => {
    const [openapi, map, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    for (const operation of [
      "listGroupMappings", "updateGroupMappings", "listAPITokens", "createAPIToken",
      "revokeAPIToken", "listAuditEvents", "createAuditExport", "getAuditExport",
    ]) expect(openapi).toContain(`operationId: ${operation}`);
    expect(map.match(/availability: available/g)).toHaveLength(20);
    expect(map.match(/availability: api_available/g)).toHaveLength(47);
    expect(readme).toContain("M2-01 through M2-50 and the M2-47 gate are Complete");
    expect(readme).toContain("M3-01 through M3-13 are Complete");
  });

  it("ships one actual five-panel Identity route over the generated API client", async () => {
    const [app, view, provider] = await Promise.all([
      readFile(resolve(repositoryRoot, "app/components/ZaspApp.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/IdentityAccessView.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/IdentityAPIProvider.tsx"), "utf8"),
    ]);
    expect(app).toContain('route.path === "/administration/identity-access"');
    for (const heading of ["Members", "Built-in roles", "SSO connections", "SCIM provisioning", "Group mappings"]) {
      expect(view).toContain(`<h2>${heading}</h2>`);
    }
    expect(provider).toContain("createAPIClient()");
    expect(provider).not.toMatch(/mock|fixture/i);
  });
});

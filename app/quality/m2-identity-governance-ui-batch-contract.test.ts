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
    expect(taskRows(tracker, "In progress")).toHaveLength(0);
    expect(taskRows(tracker, "Blocked").map(([task]) => task)).toEqual(["M1A-10", "M1A-09", "M1A-08", "M1A-07", "M3-52", "M3-14", "M8-54", "M8-63", "M8-63e", "M8-63d", "M8-63c", "M8-63b", "M8-63a", "M8-62", "M8-62e", "M8-62d", "M8-62c", "M8-62b", "M8-62a", "M8-61", "M8-61a", "M8-60", "M8-60b", "M8-59", "M8-59b", "M8-58", "M8-58b", "M8-53", "M8-52", "M8-52d", "M8-52c", "M8-52b", "M8-52a", "M8-51", "M8-51e", "M8-51d", "M8-51c", "M8-51b", "M8-51a", "M8-46", "M8-45", "M8-39", "M8-38", "M8-38b", "M8-37", "M8-36", "M8-36b", "M8-35", "M8-34", "M8-33", "M8-32", "M8-31", "M8-30", "M8-29", "M8-28", "M8-27", "M8-26", "M8-25", "M0-09", "M0-18", "M0-19"]);
  });

  it("binds mounted governance operations and keeps exports planned", async () => {
    const [openapi, map, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "openapi/openapi.yaml"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    for (const operation of [
      "listAPITokens", "createAPIToken", "listAPITokenRevealGrants", "revealAPIToken",
      "acknowledgeAPITokenRevealGrant", "rotateAPIToken", "revokeAPIToken", "listAuditEvents",
    ]) expect(openapi).toContain(`operationId: ${operation}`);
    for (const mounted of ["listGroupMappings", "updateGroupMappings"]) expect(openapi).toContain(`operationId: ${mounted}`);
    for (const hidden of ["createAuditExport", "getAuditExport"]) expect(openapi).not.toContain(`operationId: ${hidden}`);
    expect(map.match(/availability: planned/g)).toHaveLength(21);
    expect(map.match(/availability: available/g)).toHaveLength(117);
    expect(map.match(/availability: api_available/g)).toHaveLength(6);
    expect(readme).toContain("M2-01 through M2-50 and the M2-47 gate are Complete");
    expect(readme).toContain("M3-01 through M3-13 are Complete");
  });

  it("ships the durable Identity route over the shared generated API client", async () => {
    const [app, view, provider] = await Promise.all([
      readFile(resolve(repositoryRoot, "app/components/ZaspProductionApp.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/IdentityAccessView.tsx"), "utf8"),
      readFile(resolve(repositoryRoot, "app/features/identity/IdentityAPIProvider.tsx"), "utf8"),
    ]);
    expect(app).toContain('path === "/administration/identity-access"');
    for (const heading of ["Members", "Built-in roles", "Enterprise identity", "Group mappings"]) {
      expect(view).toContain(`<h2>${heading}</h2>`);
    }
    expect(view).toContain("Add SSO connection");
    expect(view).toContain("Add SCIM connection");
    expect(view).toContain("Map a verified SCIM group");
    expect(view).toContain("Save group mapping");
    expect(provider).toContain("client ? createIdentityAdminAPI(client)");
    expect(provider).not.toContain("createAPIClient()");
    expect(provider).not.toMatch(/mock|fixture/i);
  });
});

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { JSON_SCHEMA, load } from "js-yaml";
import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../..");
type MapAction = { id: string; operation_id: string; availability: string };
type MapScreen = { id: string; label: string; actions: MapAction[] };
type MapDocument = { schema_version: number; screens: MapScreen[] };

const expectedMap: MapDocument = {
  schema_version: 1,
  screens: [
    {
      id: "home",
      label: "Home",
      actions: [
        { id: "view_home_summary", operation_id: "getHomeSummary", availability: "planned" },
        { id: "search_all_entities", operation_id: "globalSearch", availability: "planned" },
      ],
    },
    {
      id: "system_health",
      label: "System Health",
      actions: [
        { id: "view_system_status", operation_id: "getSystemStatus", availability: "planned" },
        { id: "view_system_components", operation_id: "listSystemComponents", availability: "planned" },
        { id: "view_system_version", operation_id: "getSystemVersion", availability: "planned" },
      ],
    },
  ],
};

function exactKeys(value: unknown, expected: string[]) {
  expect(value).not.toBeNull();
  expect(Array.isArray(value)).toBe(false);
  expect(typeof value).toBe("object");
  expect(Object.keys(value as object).sort()).toEqual([...expected].sort());
}

function validateMap(value: unknown) {
  exactKeys(value, ["schema_version", "screens"]);
  const document = value as { schema_version: unknown; screens: unknown };
  expect(document.schema_version).toBe(1);
  expect(document.screens).toEqual(expectedMap.screens);

  const screenIDs = new Set<string>();
  const labels = new Set<string>();
  const actionIDs = new Set<string>();
  const operationIDs = new Set<string>();
  for (const screen of document.screens as Array<Record<string, unknown>>) {
    exactKeys(screen, ["id", "label", "actions"]);
    expect(screen.id).toMatch(/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/);
    expect(screen.label).toMatch(/^[A-Za-z][A-Za-z ]+$/);
    expect(screenIDs.has(screen.id as string)).toBe(false);
    expect(labels.has(screen.label as string)).toBe(false);
    screenIDs.add(screen.id as string);
    labels.add(screen.label as string);

    expect(Array.isArray(screen.actions)).toBe(true);
    for (const action of screen.actions as Array<Record<string, unknown>>) {
      exactKeys(action, ["id", "operation_id", "availability"]);
      expect(action.id).toMatch(/^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$/);
      expect(action.operation_id).toMatch(/^[a-z][A-Za-z0-9]*$/);
      expect(action.availability).toBe("planned");
      expect(actionIDs.has(action.id as string)).toBe(false);
      expect(operationIDs.has(action.operation_id as string)).toBe(false);
      actionIDs.add(action.id as string);
      operationIDs.add(action.operation_id as string);
    }
  }
  return [...operationIDs];
}

function parseStrictMap(source: string) {
  expect(Buffer.byteLength(source, "utf8")).toBeLessThanOrEqual(16 * 1024);
  expect(source).not.toMatch(/[&*][A-Za-z0-9_-]+/);
  expect(source).not.toMatch(/^\s*<<\s*:/m);
  const parsed = load(source, { schema: JSON_SCHEMA, json: false });
  validateMap(parsed);
  return parsed;
}

function resolveAgainst(operationIDs: string[], available: Set<string>) {
  for (const operationID of operationIDs) {
    expect(available.has(operationID)).toBe(true);
  }
  return operationIDs;
}

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

describe("M1-25 UI API map seed", () => {
  it("binds the source task to the strict planned-map design", async () => {
    const [source, design, plan] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/agent_security_platform_Technical_Implementation_Plan_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-25-ui-api-map-seed-design.md"), "utf8"),
      readFile(resolve(repositoryRoot, "docs/internal/2026-08-16-m1-25-ui-api-map-seed-implementation-plan.md"), "utf8"),
    ]);
    const section = source.match(/\*\*M1-25 - UI API map seed\*\*[\s\S]*?\*\*M1-26 - UI API coverage CI/)?.[0] ?? "";
    const compactDesign = design.replace(/\s+/g, " ");

    expect(section).toContain("Depends on: `M1-24`");
    expect(section).toContain("Create `docs/product/ui-api-map.yaml`");
    expect(section).toContain("concrete Home and System Health entries");
    expect(section).toContain("Coverage script resolves both operation IDs once defined");
    for (const operationID of [
      "getHomeSummary",
      "globalSearch",
      "getSystemStatus",
      "listSystemComponents",
      "getSystemVersion",
    ]) {
      expect(compactDesign).toContain(operationID);
    }
    expect(compactDesign).toContain("Every action is explicitly `planned`");
    expect(compactDesign).toContain("no API is claimed implemented or callable");
    expect(plan).toContain("Every artifact or status behavior change has a witnessed tests-only RED");
    expect(plan).toContain("M1-26 remains Pending");
  });

  it("completes only M1-25 after M1-24 and preserves the blockers", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(repositoryRoot, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(repositoryRoot, "README.md"), "utf8"),
    ]);
    const active = taskRows(tracker, "In progress");
    const complete = taskRows(tracker, "Complete");
    const blocked = taskRows(tracker, "Blocked");
    const milestones = markdownRows(tracker.match(/## Milestone summary[\s\S]*?## Execution invariants/)?.[0] ?? "").slice(2);

    expect(readme).toContain("M1-25 is Complete");
    expect(tracker).toContain("| Pending | 649 |");
    expect(tracker).toContain("| In progress | 0 |");
    expect(tracker).toContain("| Complete | 76 |");
    expect(tracker).toContain("| Blocked | 3 |");
    expect(tracker).toContain("`649/0/76/3`");
    expect(milestones.find(([milestone]) => milestone === "M1")).toEqual(["M1", "68", "16", "0", "52", "0"]);
    expect(active.map(([task]) => task)).toEqual([]);
    expect(complete.filter(([task]) => task === "M1-24")).toHaveLength(1);
    expect(complete.filter(([task]) => task === "M1-25")).toHaveLength(1);
    expect(active.filter(([task]) => task === "M1-26")).toHaveLength(0);
    expect(complete.filter(([task]) => task === "M1-26")).toHaveLength(1);
    expect(blocked.map(([task]) => task)).toEqual(["M0-09", "M0-18", "M0-19"]);
  });

  it("accepts only the exact two-screen, five-action planned map", async () => {
    const source = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8").catch(() => "");

    expect(parseStrictMap(source)).toEqual(expectedMap);
  });

  it("rejects hostile YAML and semantic seed mutations", async () => {
    const source = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8").catch(() => "");
    expect(() => parseStrictMap(`${source}\nschema_version: 1\n`)).toThrow();
    expect(() => parseStrictMap("schema_version: &version 1\ncopy: *version\n")).toThrow();
    expect(() => parseStrictMap("schema_version: 1\nscreens:\n  - <<: {id: home}\n")).toThrow();

    for (const mutate of [
      (value: typeof expectedMap) => Object.assign(value, { extra: true }),
      (value: typeof expectedMap) => value.screens.reverse(),
      (value: typeof expectedMap) => value.screens[0].actions.pop(),
      (value: typeof expectedMap) => Object.assign(value.screens[0], { route: "/invented" }),
      (value: typeof expectedMap) => Object.assign(value.screens[0].actions[0], { availability: "active" }),
      (value: typeof expectedMap) => Object.assign(value.screens[1].actions[0], { operation_id: "getHomeSummary" }),
    ]) {
      const value = structuredClone(expectedMap);
      mutate(value);
      expect(() => validateMap(value)).toThrow();
    }
  });

  it("resolves every forward reference when all five operations are defined", async () => {
    const source = await readFile(resolve(repositoryRoot, "docs/product/ui-api-map.yaml"), "utf8").catch(() => "");
    const operationIDs = validateMap(parseStrictMap(source));
    const available = new Set(operationIDs);

    expect(resolveAgainst(operationIDs, available)).toEqual([
      "getHomeSummary",
      "globalSearch",
      "getSystemStatus",
      "listSystemComponents",
      "getSystemVersion",
    ]);
    available.delete("globalSearch");
    expect(() => resolveAgainst(operationIDs, available)).toThrow();
  });

  it("documents the planned seed without claiming current API coverage", async () => {
    const readme = await readFile(resolve(repositoryRoot, "README.md"), "utf8");
    const section = readme.match(/## UI-to-API map seed[\s\S]*?## Neon pooled proof/)?.[0] ?? "";
    const prose = section.replace(/\s+/g, " ");

    expect(section).toContain("`docs/product/ui-api-map.yaml`");
    expect(prose).toContain("Home");
    expect(prose).toContain("`getHomeSummary`");
    expect(prose).toContain("`globalSearch`");
    expect(prose).toContain("System Health");
    expect(prose).toContain("`getSystemStatus`");
    expect(prose).toContain("`listSystemComponents`");
    expect(prose).toContain("`getSystemVersion`");
    expect(prose).toContain("all five actions are `planned`");
    expect(prose).toContain("does not add or claim a current OpenAPI operation");
    expect(prose).toContain("M1-26 is Complete");
  });
});

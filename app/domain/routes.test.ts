import { describe, expect, it } from "vitest";
import { allRoutes, NAV_GROUPS, resolveRoute } from "./routes";

const expectedNavigation = [
  ["Home", [["Overview", "/"]]],
  ["Inventory", [["Agents", "/discovery/assets"], ["Tools & MCP", "/inventory/tools"], ["Identities", "/identities"], ["Runtimes", "/inventory/runtimes"]]],
  ["Exposure", [["Findings", "/violations"], ["Attack Paths", "/exposure/attack-paths"]]],
  ["Test", [["Red Team", "/red-team/results"], ["Attack Lab", "/test/attack-lab"]]],
  ["Protect", [["Policies", "/policies"], ["Security Agents", "/protect/security-agents"], ["Approvals", "/protect/approvals"]]],
  ["Investigate", [["Sessions", "/investigate/sessions"]]],
  ["Compliance", [["Evidence", "/compliance/evidence"]]],
  ["Integrations", [["Connections", "/connectors"], ["Sensors", "/integrations/sensors"]]],
  ["Administration", [["Identity & Access", "/administration/identity-access"], ["Audit Log", "/administration/audit-log"], ["Data & Retention", "/administration/data-retention"], ["External Data Flows", "/administration/external-data-flows"], ["System Health", "/administration/system-health"], ["API Access", "/administration/api-access"]]],
] as const;

const forbiddenLabels = ["Cartography", "Prowler", "Nango", "Promptfoo", "Neo4j", "Tetragon", "OpenTelemetry", "LocalStack", "Stytch"] as const;

describe("base shell route registry", () => {
  it("defines the exact immutable PRD information architecture", () => {
    expect(NAV_GROUPS.map((group) => [
      group.label,
      group.items.map((route) => [route.label, route.path]),
    ])).toEqual(expectedNavigation);
    expect(NAV_GROUPS).toHaveLength(9);
    expect(allRoutes).toHaveLength(22);
    expect(Object.isFrozen(NAV_GROUPS)).toBe(true);
    expect(Object.isFrozen(allRoutes)).toBe(true);
    for (const group of NAV_GROUPS) {
      expect(Object.isFrozen(group)).toBe(true);
      expect(Object.isFrozen(group.items)).toBe(true);
      for (const route of group.items) expect(Object.isFrozen(route)).toBe(true);
    }
  });

  it("uses unique product-only labels and canonical absolute paths", () => {
    const groups = NAV_GROUPS.map((group) => group.label);
    const labels = allRoutes.map((route) => route.label);
    const paths = allRoutes.map((route) => route.path);
    expect(new Set(groups).size).toBe(groups.length);
    expect(new Set(labels).size).toBe(labels.length);
    expect(new Set(paths).size).toBe(paths.length);
    for (const path of paths) expect(path).toMatch(/^\/(?:[a-z0-9-]+(?:\/[a-z0-9-]+)*)?$/);
    const productText = [...groups, ...labels].join(" ").toLowerCase();
    for (const label of forbiddenLabels) expect(productText).not.toContain(label.toLowerCase());
  });

  it("resolves every exact route and falls back to Overview", () => {
    for (const route of allRoutes) expect(resolveRoute(route.path)).toBe(route);
    expect(resolveRoute("/not-a-route")).toBe(allRoutes[0]);
    expect(resolveRoute("/not-a-route").label).toBe("Overview");
  });
});

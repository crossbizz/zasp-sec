import type { AppRoute, NavGroup } from "./types";

function route(value: AppRoute): AppRoute {
  return Object.freeze(value);
}

function group(label: string, items: AppRoute[]): NavGroup {
  return Object.freeze({ label, items: Object.freeze(items) });
}

export const NAV_GROUPS: readonly NavGroup[] = Object.freeze([
  group("Home", [
    route({ path: "/", label: "Overview", title: "Security overview", icon: "LayoutDashboard" }),
  ]),
  group("Inventory", [
    route({ path: "/discovery/assets", label: "Agents", title: "Agents", icon: "Boxes" }),
    route({ path: "/inventory/tools", label: "Tools & MCP", title: "Tools and MCP", icon: "Wrench" }),
    route({ path: "/identities", label: "Identities", title: "Non-human identities", icon: "KeyRound" }),
    route({ path: "/inventory/runtimes", label: "Runtimes", title: "Runtimes", icon: "Container" }),
  ]),
  group("Exposure", [
    route({ path: "/violations", label: "Findings", title: "Exposure findings", icon: "TriangleAlert" }),
    route({ path: "/exposure/attack-paths", label: "Attack Paths", title: "Attack paths", icon: "Route" }),
  ]),
  group("Test", [
    route({ path: "/red-team/results", label: "Red Team", title: "Red team", icon: "ScanSearch" }),
    route({ path: "/test/attack-lab", label: "Attack Lab", title: "Attack lab", icon: "FlaskConical" }),
  ]),
  group("Protect", [
    route({ path: "/policies", label: "Policies", title: "Policies", icon: "FileSliders" }),
    route({ path: "/protect/security-agents", label: "Security Agents", title: "Security agents", icon: "ShieldCheck" }),
    route({ path: "/protect/approvals", label: "Approvals", title: "Approvals", icon: "BadgeCheck" }),
  ]),
  group("Investigate", [
    route({ path: "/investigate/sessions", label: "Sessions", title: "Sessions", icon: "Search" }),
  ]),
  group("Compliance", [
    route({ path: "/compliance/evidence", label: "Evidence", title: "Compliance evidence", icon: "FileCheck2" }),
  ]),
  group("Integrations", [
    route({ path: "/connectors", label: "Connections", title: "Connections", icon: "PlugZap" }),
    route({ path: "/integrations/sensors", label: "Sensors", title: "Sensors", icon: "RadioTower" }),
  ]),
  group("Administration", [
    route({ path: "/administration/identity-access", label: "Identity & Access", title: "Identity and access", icon: "UsersRound" }),
    route({ path: "/administration/audit-log", label: "Audit Log", title: "Audit log", icon: "ScrollText" }),
    route({ path: "/administration/data-retention", label: "Data & Retention", title: "Data and retention", icon: "Database" }),
    route({ path: "/administration/external-data-flows", label: "External Data Flows", title: "External data flows", icon: "Network" }),
    route({ path: "/administration/system-health", label: "System Health", title: "System health", icon: "HeartPulse" }),
    route({ path: "/administration/api-access", label: "API Access", title: "API access", icon: "Braces" }),
  ]),
]);

export const allRoutes: readonly AppRoute[] = Object.freeze(NAV_GROUPS.flatMap((entry) => entry.items));

export function resolveRoute(pathname: string): AppRoute {
  return allRoutes.find((entry) => entry.path === pathname) ?? NAV_GROUPS[0].items[0];
}

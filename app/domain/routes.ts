import type { AppRoute, NavGroup } from "./types";

export const NAV_GROUPS: NavGroup[] = [
  {
    items: [
      { path: "/", label: "Overview", title: "Security overview", icon: "LayoutDashboard" },
      { path: "/discovery/assets", label: "Agentic assets", title: "Agentic assets", icon: "Boxes", parent: "Discovery" },
      { path: "/discovery/endpoints", label: "Endpoints", title: "Agent endpoints", icon: "Waypoints", parent: "Discovery" },
      { path: "/discovery/sensitive-data", label: "Sensitive data", title: "Sensitive data", icon: "Fingerprint", parent: "Discovery" },
      { path: "/discovery/recent-changes", label: "Recent changes", title: "Recent changes", icon: "History", parent: "Discovery" },
    ],
  },
  {
    label: "Identity governance",
    items: [
      { path: "/identities", label: "Identities", title: "Non-human identities", icon: "KeyRound" },
      { path: "/violations", label: "Violations", title: "Identity violations", icon: "TriangleAlert" },
      { path: "/policies", label: "Policies", title: "Identity policies", icon: "FileSliders" },
    ],
  },
  {
    label: "Runtime protection",
    items: [
      { path: "/guardrails/dashboard", label: "Guardrails", title: "Guardrail dashboard", icon: "ShieldCheck", parent: "Guardrails" },
      { path: "/guardrails/activity", label: "Guardrail activity", title: "Guardrail activity", icon: "Activity", parent: "Guardrails" },
      { path: "/guardrails/actors", label: "Actors", title: "Guardrail actors", icon: "Users", parent: "Guardrails" },
      { path: "/guardrails/components", label: "Protected components", title: "Protected components", icon: "Blocks", parent: "Guardrails" },
      { path: "/guardrails/policies", label: "Guardrail policies", title: "Guardrail policies", icon: "ShieldEllipsis", parent: "Guardrails" },
    ],
  },
  {
    label: "Assurance",
    items: [
      { path: "/red-team/results", label: "Red team results", title: "Red team results", icon: "ScanSearch", parent: "Red teaming" },
      { path: "/red-team/scans", label: "Scan runs", title: "Red team scans", icon: "Radar", parent: "Red teaming" },
      { path: "/connectors", label: "Connectors", title: "Connectors", icon: "PlugZap" },
      { path: "/prompt-hardening", label: "Prompt hardening", title: "Prompt hardening", icon: "WandSparkles" },
      { path: "/reports", label: "Reports", title: "Reports", icon: "ChartNoAxesCombined" },
    ],
  },
];

export const allRoutes: AppRoute[] = NAV_GROUPS.flatMap((group) => group.items);

export function resolveRoute(pathname: string): AppRoute {
  return allRoutes.find((route) => route.path === pathname) ?? allRoutes[0];
}

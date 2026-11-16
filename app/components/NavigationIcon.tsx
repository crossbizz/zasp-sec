import { LayoutDashboard, Boxes, Wrench, KeyRound, Container, TriangleAlert, Route, FileCheck2, ScanSearch, FlaskConical, FileSliders, ShieldCheck, BadgeCheck, Search, ScrollText, PlugZap, RadioTower, UsersRound, Braces, Database, DatabaseBackup, Network, HeartPulse, Shield } from "lucide-react";

const icons = {
  "/": LayoutDashboard, "/discovery/assets": Boxes, "/inventory/tools": Wrench,
  "/identities": KeyRound, "/inventory/runtimes": Container, "/violations": TriangleAlert,
  "/exposure/attack-paths": Route, "/compliance/evidence": FileCheck2,
  "/red-team/results": ScanSearch, "/test/attack-lab": FlaskConical,
  "/policies": FileSliders, "/protect/guardrails": Shield,
  "/protect/security-agents": ShieldCheck, "/protect/approvals": BadgeCheck,
  "/investigate/sessions": Search, "/administration/audit-log": ScrollText,
  "/connectors": PlugZap, "/integrations/sensors": RadioTower,
  "/administration/identity-access": UsersRound, "/administration/api-access": Braces,
  "/administration/data-retention": Database, "/administration/recovery": DatabaseBackup,
  "/administration/external-data-flows": Network, "/administration/system-health": HeartPulse,
};

export function NavigationIcon({ path }: { path: string }) {
  const Icon = icons[path as keyof typeof icons] ?? Shield;
  return <Icon className="navigation-icon" size={18} strokeWidth={1.8} aria-hidden="true" />;
}

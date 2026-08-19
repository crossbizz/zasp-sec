"use client";

import { useCallback, useEffect, useState } from "react";

import { APIAccessView } from "../features/identity/APIAccessView";
import { IdentityAPIProvider } from "../features/identity/IdentityAPIProvider";
import { IdentityAccessView } from "../features/identity/IdentityAccessView";
import { ScopeOnboardingView } from "../features/identity/ScopeOnboardingView";
import { AgentSecurityView, fixtureAgentSecurityAPI } from "../features/agents/AgentSecurityView";
import { AdminOperationsView } from "../features/administration/AdminOperationsView";
import { ConnectorView } from "../features/connectors/ConnectorViews";
import { DiscoveryView } from "../features/discovery/DiscoveryViews";
import { GovernanceView } from "../features/governance/GovernanceViews";
import { GuardrailView } from "../features/guardrails/GuardrailViews";
import { OverviewView } from "../features/overview/OverviewView";
import { PoliciesView } from "../features/policies/PoliciesView";
import { AttackLabView } from "../features/redteam/AttackLabView";
import { RedTeamView } from "../features/redteam/RedTeamViews";
import { SecurityAgentsView } from "../features/securityagents/SecurityAgentsView";
import { SensorView } from "../features/sensors/SensorView";
import { SessionsComplianceView } from "../features/sessions/SessionsComplianceView";
import { ToolView } from "../features/tools/ToolViews";
import { resolveRoute } from "../domain/routes";
import { ZaspStoreProvider, useZaspStore } from "../domain/store";
import type { AppRoute } from "../domain/types";
import { AppShell } from "./AppShell";
import { Button, Modal, Toast } from "./ui";

function DemoRouteSurface({ route, onNavigate, onToast }: { route: AppRoute; onNavigate(path: string): void; onToast(message: string): void }) {
  if (route.path === "/") return <OverviewView onNavigate={onNavigate} />;
  if (route.path === "/discovery/assets") return <><DiscoveryView route={route} /><AgentSecurityView path={route.path} api={fixtureAgentSecurityAPI()} onNavigate={onNavigate} /></>;
  if (["/identities", "/violations"].includes(route.path)) return <><GovernanceView route={route} onToast={onToast} /><AgentSecurityView path={route.path} api={fixtureAgentSecurityAPI()} onNavigate={onNavigate} /></>;
  if (["/inventory/tools", "/inventory/runtimes", "/exposure/attack-paths"].includes(route.path)) return <AgentSecurityView path={route.path} api={fixtureAgentSecurityAPI()} onNavigate={onNavigate} />;
  if (route.path.startsWith("/discovery/")) return <DiscoveryView route={route} />;
  if (route.path === "/policies") return <><GovernanceView route={route} onToast={onToast} /><PoliciesView embedded /></>;
  if (route.path === "/protect/security-agents" || route.path === "/protect/approvals") return <SecurityAgentsView />;
  if (route.path === "/investigate/sessions") return <SessionsComplianceView surface="sessions" />;
  if (route.path === "/compliance/evidence") return <SessionsComplianceView surface="compliance" />;
  if (route.path === "/administration/data-retention") return <SessionsComplianceView surface="data-controls" />;
  if (route.path === "/administration/system-health") return <AdminOperationsView surface="health" />;
  if (route.path === "/administration/external-data-flows") return <AdminOperationsView surface="external" />;
  if (route.path === "/administration/audit-log") return <AdminOperationsView surface="audit" />;
  if (route.path.startsWith("/guardrails/")) return <GuardrailView route={route} onNavigate={onNavigate} onToast={onToast} />;
  if (route.path.startsWith("/red-team/")) return <RedTeamView route={route} onNavigate={onNavigate} onToast={onToast} />;
  if (route.path === "/test/attack-lab") return <AttackLabView />;
  if (route.path === "/connectors") return <ConnectorView onToast={onToast} />;
  if (route.path === "/integrations/sensors") return <SensorView onToast={onToast} />;
  if (["/prompt-hardening", "/reports"].includes(route.path)) return <ToolView route={route} onToast={onToast} />;
  if (route.path === "/administration/identity-access") return <IdentityAPIProvider><IdentityAccessView /><ScopeOnboardingView /></IdentityAPIProvider>;
  if (route.path === "/administration/api-access") return <APIAccessView />;
  return <div className="page"><h1>{route.title}</h1></div>;
}

function DemoAppContent() {
  const { dispatch } = useZaspStore();
  const [route, setRoute] = useState(() => resolveRoute(typeof window === "undefined" ? "/" : window.location.pathname));
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const navigate = useCallback((path: string) => { window.history.pushState({}, "", path); setRoute(resolveRoute(new URL(path, window.location.origin).pathname)); window.scrollTo({ top: 0, behavior: "smooth" }); }, []);
  useEffect(() => { const handler = () => setRoute(resolveRoute(window.location.pathname)); window.addEventListener("popstate", handler); return () => window.removeEventListener("popstate", handler); }, []);
  return <AppShell route={route} onNavigate={navigate} onSettings={() => setSettingsOpen(true)}><DemoRouteSurface route={route} onNavigate={navigate} onToast={setToast} /><Modal open={settingsOpen} title="Workspace settings" onClose={() => setSettingsOpen(false)} footer={<Button variant="primary" onClick={() => setSettingsOpen(false)}>Done</Button>}><div className="settings-list"><div><strong>Demo environment</strong><p>All actions modify browser-local demonstration data.</p></div><Button variant="danger" onClick={() => { dispatch({ type: "reset" }); window.localStorage.removeItem("zasp-demo-state"); setToast("Demo data reset"); setSettingsOpen(false); }}>Reset demo data</Button></div></Modal>{toast && <Toast message={toast} onClose={() => setToast(null)} />}</AppShell>;
}

export function ZaspDemoApp() {
  return <ZaspStoreProvider><DemoAppContent /></ZaspStoreProvider>;
}

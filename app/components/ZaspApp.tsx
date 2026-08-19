"use client";

import { useCallback, useEffect, useState } from "react";
import { AppShell } from "./AppShell";
import { Button, Modal, Toast } from "./ui";
import { resolveRoute } from "../domain/routes";
import { ZaspStoreProvider, useZaspStore } from "../domain/store";
import type { AppRoute } from "../domain/types";
import { OverviewView } from "../features/overview/OverviewView";
import { DiscoveryView } from "../features/discovery/DiscoveryViews";
import { GovernanceView } from "../features/governance/GovernanceViews";
import { GuardrailView } from "../features/guardrails/GuardrailViews";
import { RedTeamView } from "../features/redteam/RedTeamViews";
import { ConnectorView } from "../features/connectors/ConnectorViews";
import { SensorView } from "../features/sensors/SensorView";
import { ToolView } from "../features/tools/ToolViews";
import { IdentityAccessView } from "../features/identity/IdentityAccessView";
import { IdentityAPIProvider } from "../features/identity/IdentityAPIProvider";
import { APIAccessView } from "../features/identity/APIAccessView";
import { ScopeOnboardingView } from "../features/identity/ScopeOnboardingView";
import { AgentSecurityView, fixtureAgentSecurityAPI } from "../features/agents/AgentSecurityView";
import { AttackLabView } from "../features/redteam/AttackLabView";
import { PoliciesView } from "../features/policies/PoliciesView";
import { SessionsComplianceView } from "../features/sessions/SessionsComplianceView";
import { AdminOperationsView } from "../features/administration/AdminOperationsView";
import { SecurityAgentsView } from "../features/securityagents/SecurityAgentsView";
import { APIProvider } from "../api/APIProvider";
import { SessionProvider, useSession } from "../auth/SessionProvider";
import type { APIClient } from "../../apps/web/api/client";

function RouteSurface({ route, onNavigate, onToast }: { route: AppRoute; onNavigate: (path: string) => void; onToast: (message: string) => void }) {
  if (route.path === "/") return <OverviewView onNavigate={onNavigate} />;
  if (route.path === "/discovery/assets") return <><DiscoveryView route={route} /><AgentSecurityView path={route.path} api={fixtureAgentSecurityAPI()} onNavigate={onNavigate} /></>;
  if (["/identities", "/violations"].includes(route.path)) return <><GovernanceView route={route} onToast={onToast} /><AgentSecurityView path={route.path} api={fixtureAgentSecurityAPI()} onNavigate={onNavigate} /></>;
  if (["/inventory/tools", "/inventory/runtimes", "/exposure/attack-paths"].includes(route.path)) return <AgentSecurityView path={route.path} api={fixtureAgentSecurityAPI()} onNavigate={onNavigate} />;
  if (route.path.startsWith("/discovery/")) return <DiscoveryView route={route} />;
  if (route.path === "/policies") return <><GovernanceView route={route} onToast={onToast} /><PoliciesView embedded /></>;
  if (route.path === "/protect/security-agents") {
    const queryTab = typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("tab");
    const initialTab = queryTab === "runs" || queryTab === "approvals" ? queryTab : "agents";
    return <SecurityAgentsView key={initialTab} initialTab={initialTab} />;
  }
  if (route.path === "/protect/approvals") return <SecurityAgentsView key="approvals" initialTab="approvals" />;
  if (route.path === "/investigate/sessions") return <SessionsComplianceView surface="sessions" />;
  if (route.path === "/compliance/evidence") return <SessionsComplianceView surface="compliance" />;
  if (route.path === "/administration/data-retention") return <SessionsComplianceView surface="data-controls" />;
  if (route.path === "/administration/system-health") return <AdminOperationsView surface="health" />;
  if (route.path === "/administration/external-data-flows") return <AdminOperationsView surface="external" />;
  if (route.path === "/administration/audit-log") return <AdminOperationsView surface="audit" />;
  if (["/identities", "/violations"].includes(route.path)) return <GovernanceView route={route} onToast={onToast} />;
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

function AppContent() {
  const { dispatch } = useZaspStore();
  const [route, setRoute] = useState(() => resolveRoute(typeof window === "undefined" ? "/" : window.location.pathname));
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const navigate = useCallback((path: string) => {
    window.history.pushState({}, "", path);
    setRoute(resolveRoute(new URL(path, window.location.origin).pathname));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);
  useEffect(() => { const handler = () => setRoute(resolveRoute(window.location.pathname)); window.addEventListener("popstate", handler); return () => window.removeEventListener("popstate", handler); }, []);
  return <AppShell route={route} onNavigate={navigate} onSettings={() => setSettingsOpen(true)}><RouteSurface route={route} onNavigate={navigate} onToast={setToast} /><Modal open={settingsOpen} title="Workspace settings" onClose={() => setSettingsOpen(false)} footer={<Button variant="primary" onClick={() => setSettingsOpen(false)}>Done</Button>}><div className="settings-list"><div><strong>Demo environment</strong><p>All actions modify browser-local demonstration data.</p></div><Button variant="danger" onClick={() => { dispatch({ type: "reset" }); window.localStorage.removeItem("zasp-demo-state"); setToast("Demo data reset"); setSettingsOpen(false); }}>Reset demo data</Button></div></Modal>{toast && <Toast message={toast} onClose={() => setToast(null)} />}</AppShell>;
}

export function ZaspDemoApp() { return <ZaspStoreProvider><AppContent /></ZaspStoreProvider>; }

const productionRoutes = [
  { path: "/", label: "Overview", capability: "inventory.read" },
  { path: "/discovery/assets", label: "Agents", capability: "inventory.read" },
  { path: "/inventory/tools", label: "Tools & MCP", capability: "inventory.read" },
  { path: "/identities", label: "Identities", capability: "inventory.read" },
  { path: "/inventory/runtimes", label: "Runtimes", capability: "inventory.read" },
] as const;

function ProductionAppContent() {
  const session = useSession();
  const [path, setPath] = useState(() => {
    const candidate = typeof window === "undefined" ? "/" : window.location.pathname;
    return productionRoutes.some((route) => route.path === candidate) ? candidate : "/";
  });
	useEffect(() => {
		if (!productionRoutes.some((route) => route.path === window.location.pathname)) window.history.replaceState({}, "", "/");
	}, []);
	useEffect(() => {
		const handlePopState = () => {
			const candidate = window.location.pathname;
			const allowed = session.status === "authenticated" && productionRoutes.some((route) => route.path === candidate && session.hasCapability(route.capability));
			if (allowed) {
				setPath(candidate);
				return;
			}
			window.history.replaceState({}, "", "/");
			setPath("/");
		};
		window.addEventListener("popstate", handlePopState);
		return () => window.removeEventListener("popstate", handlePopState);
	}, [session]);
  if (session.status === "loading") return <main className="page"><h1>Loading Zasp</h1><p role="status">Loading authenticated session…</p></main>;
  if (session.status === "unauthenticated") return <main className="page"><h1>Sign in to Zasp</h1><Button onClick={() => session.signIn(path)}>Sign in</Button></main>;
  if (session.status === "forbidden") return <main className="page"><h1>Scope unavailable</h1><p role="alert">Authorization rejected</p></main>;
  if (session.status === "error") return <main className="page"><h1>Session unavailable</h1><Button onClick={() => void session.retry()}>Retry</Button></main>;
  if (session.status !== "authenticated") return null;
  const routes = productionRoutes.filter((route) => session.hasCapability(route.capability));
	const visiblePath = routes.some((route) => route.path === path) ? path : "/";
  const navigate = (nextPath: string) => {
    if (!routes.some((route) => route.path === nextPath)) return;
    window.history.pushState({}, "", nextPath);
    setPath(nextPath);
  };
  const selectedScope = `${session.workspaceID}/${session.environmentID}`;
  return <div className="app-shell production-app">
    <header className="topbar"><button className="brand" onClick={() => navigate("/")} aria-label="Zasp overview">Zasp</button><span>Agent Security</span>{session.hasCapability("scope.switch") && session.scopes.length > 1 && <select aria-label="Authorized scope" value={selectedScope} onChange={(event) => { const scope = session.scopes.find((item) => `${item.workspace_id}/${item.environment_id}` === event.target.value); if (scope) void session.switchScope(scope.workspace_id, scope.environment_id); }}>{session.scopes.map((scope) => <option key={`${scope.workspace_id}/${scope.environment_id}`} value={`${scope.workspace_id}/${scope.environment_id}`}>{scope.label}</option>)}</select>}<Button onClick={() => void session.signOut()}>Sign out</Button></header>
    <aside className="sidebar"><nav aria-label="Main navigation">{routes.map((route) => <a key={route.path} href={route.path} aria-label={route.label} aria-current={visiblePath === route.path ? "page" : undefined} onClick={(event) => { event.preventDefault(); navigate(route.path); }}>{route.label}</a>)}</nav></aside>
    <main className="main-content"><AgentSecurityView path={visiblePath} onNavigate={navigate} /></main>
  </div>;
}

export function ZaspApp({ client }: { client?: APIClient } = {}) {
  return <APIProvider client={client}><SessionProvider><ProductionAppContent /></SessionProvider></APIProvider>;
}

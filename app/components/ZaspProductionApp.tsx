"use client";

import { useEffect, useState } from "react";

import type { APIClient } from "../../apps/web/api/client";
import { APIProvider, useAPI } from "../api/APIProvider";
import { SessionProvider, useSession } from "../auth/SessionProvider";
import { AdminOperationsView } from "../features/administration/AdminOperationsView";
import { ProductionAgentSecurityView } from "../features/agents/ProductionAgentSecurityView";
import { APIAccessView } from "../features/identity/APIAccessView";
import { IdentityAPIProvider } from "../features/identity/IdentityAPIProvider";
import { IdentityAccessView } from "../features/identity/IdentityAccessView";
import { ScopeOnboardingView } from "../features/identity/ScopeOnboardingView";
import { ProductionRiskView } from "../features/risk/ProductionRiskView";
import { ProductionSecurityAgentsView } from "../features/securityagents/SecurityAgentsView";
import { SessionsComplianceView } from "../features/sessions/SessionsComplianceView";
import { ProductionIntegrationsView, ProductionPoliciesView } from "../features/workflows/ProductionWorkflowViews";
import { ProductionWorkflowMutationProvider, useWorkflowMutationScopeLock } from "../features/workflows/useRetainedWorkflowMutation";
import { Button, LoadingState } from "./ui";

const productionRoutes = [
  { path: "/", label: "Overview", capability: "inventory.read" },
  { path: "/discovery/assets", label: "Agents", capability: "inventory.read" },
  { path: "/inventory/tools", label: "Tools & MCP", capability: "inventory.read" },
  { path: "/identities", label: "Identities", capability: "inventory.read" },
  { path: "/inventory/runtimes", label: "Runtimes", capability: "inventory.read" },
  { path: "/violations", label: "Findings", capability: "findings.read" },
  { path: "/exposure/attack-paths", label: "Attack Paths", capability: "attack-paths.read" },
  { path: "/policies", label: "Policies", capability: "policies.read" },
  { path: "/connectors", label: "Integrations", capability: "integrations.read" },
  { path: "/protect/security-agents", label: "Security agents", capability: "security-agents.read" },
  { path: "/administration/identity-access", label: "Identity & Access", capability: "identity.manage" },
  { path: "/administration/api-access", label: "API Access", capability: "api-access.manage" },
  { path: "/investigate/sessions", label: "Sessions", capability: "sessions.read" },
  { path: "/administration/audit-log", label: "Audit Log", capability: "audit.read" },
  { path: "/compliance/evidence", label: "Compliance", capability: "compliance.read" },
  { path: "/administration/data-retention", label: "Data & Retention", capability: "compliance.read" },
  { path: "/administration/external-data-flows", label: "External Data Flows", capability: "system.read" },
  { path: "/administration/system-health", label: "System Health", capability: "system.read" },
] as const;

function ProductionRouteSurface({ path, navigate }: { path: string; navigate(path: string): void }) {
  const session = useSession();
  const { client } = useAPI();
  if (session.status !== "authenticated") return null;
  if (path === "/violations" || path === "/exposure/attack-paths") return <ProductionRiskView path={path} canWrite={session.hasCapability("findings.write")} />;
  if (path === "/policies") return <ProductionPoliciesView canWrite={session.hasCapability("policies.write")} />;
  if (path === "/connectors") return <ProductionIntegrationsView canWrite={session.hasCapability("integrations.write")} />;
  if (path === "/protect/security-agents") return <ProductionSecurityAgentsView environmentID={session.environmentID} />;
  if (path === "/administration/identity-access") return <IdentityAPIProvider client={client}><IdentityAccessView /><ScopeOnboardingView client={client} /></IdentityAPIProvider>;
  if (path === "/administration/api-access") return <APIAccessView client={client} />;
  if (path === "/investigate/sessions") return <SessionsComplianceView surface="sessions" client={client} canMutate={session.hasCapability("sessions.revoke")} />;
  if (path === "/compliance/evidence") return <SessionsComplianceView surface="compliance" client={client} />;
  if (path === "/administration/data-retention") return <SessionsComplianceView surface="data-controls" client={client} canMutate={session.hasCapability("data-controls.manage")} />;
  if (path === "/administration/system-health") return <AdminOperationsView surface="health" client={client} />;
  if (path === "/administration/external-data-flows") return <AdminOperationsView surface="external" client={client} />;
  if (path === "/administration/audit-log") return <AdminOperationsView surface="audit" client={client} />;
  return <ProductionAgentSecurityView path={path} onNavigate={navigate} />;
}

function ProductionScopeSelector() {
  const session = useSession();
  const mutationLocked = useWorkflowMutationScopeLock();
  if (session.status !== "authenticated" || !session.hasCapability("scope.switch") || session.scopes.length < 2) return null;
  const selectedScope = `${session.workspaceID}/${session.environmentID}`;
  return <><select aria-label="Authorized scope" value={selectedScope} disabled={mutationLocked || session.scopeSwitch.status === "pending"} onChange={(event) => { const scope = session.scopes.find((item) => `${item.workspace_id}/${item.environment_id}` === event.target.value); if (scope) void session.switchScope(scope.workspace_id, scope.environment_id); }}>{session.scopes.map((scope) => <option key={`${scope.workspace_id}/${scope.environment_id}`} value={`${scope.workspace_id}/${scope.environment_id}`}>{scope.label}</option>)}</select>{session.scopeSwitch.status === "pending" && <span role="status">Switching scope…</span>}{session.scopeSwitch.status === "error" && <span role="alert">Scope switch failed <Button onClick={() => void session.scopeSwitch.retry()}>Retry</Button></span>}</>;
}

function ProductionAppContent() {
  const session = useSession();
  const [path, setPath] = useState(() => { const candidate = typeof window === "undefined" ? "/" : window.location.pathname; return productionRoutes.some((route) => route.path === candidate) ? candidate : "/"; });
  useEffect(() => { if (!productionRoutes.some((route) => route.path === window.location.pathname)) window.history.replaceState({}, "", "/"); }, []);
  useEffect(() => {
    const handlePopState = () => {
      const candidate = window.location.pathname;
      const allowed = session.status === "authenticated" && productionRoutes.some((route) => route.path === candidate && session.hasCapability(route.capability));
      if (allowed) { setPath(candidate); return; }
      window.history.replaceState({}, "", "/"); setPath("/");
    };
    window.addEventListener("popstate", handlePopState); return () => window.removeEventListener("popstate", handlePopState);
  }, [session]);
  useEffect(() => {
    if (session.status !== "authenticated") return;
    const allowed = productionRoutes.some((route) => route.path === window.location.pathname && session.hasCapability(route.capability));
    if (!allowed) { window.history.replaceState({}, "", "/"); queueMicrotask(() => setPath("/")); }
  }, [session]);
  if (session.status === "loading") return <main className="page"><h1>Loading Zasp</h1><p role="status">Loading authenticated session…</p></main>;
  if (session.status === "unauthenticated") return <main className="page"><h1>Sign in to Zasp</h1><Button onClick={() => session.signIn(path)}>Sign in</Button></main>;
  if (session.status === "forbidden") return <main className="page"><h1>Scope unavailable</h1><p role="alert">Authorization rejected</p></main>;
  if (session.status === "error") return <main className="page"><h1>Session unavailable</h1>{session.scopeSwitch.status === "error" ? <><p role="alert">{session.scopeSwitch.error?.message ?? "Scope reconciliation failed"}</p><Button onClick={() => void session.scopeSwitch.retry()}>Retry scope reconciliation</Button></> : <Button onClick={() => void session.retry()}>Retry</Button>}</main>;
  if (session.status !== "authenticated") return null;
  const routes = productionRoutes.filter((route) => session.hasCapability(route.capability));
  if (routes.length === 0) return <main className="page"><h1>No product capabilities</h1><p>Your account has no enabled product routes.</p><Button onClick={() => void session.signOut()}>Sign out</Button></main>;
  const visiblePath = routes.some((route) => route.path === path) ? path : routes[0].path;
  const navigate = (nextPath: string) => { if (!routes.some((route) => route.path === nextPath)) return; window.history.pushState({}, "", nextPath); setPath(nextPath); };
  const workflowScopeKey = `${session.principal.id}/${session.organizationID}/${session.workspaceID}/${session.environmentID}`;
  const expectedScope = `${session.organizationID}/${session.workspaceID}/${session.environmentID}`;
  return <ProductionWorkflowMutationProvider scopeKey={workflowScopeKey} expectedScope={expectedScope}><div className="app-shell production-app"><header className="topbar"><button className="brand" onClick={() => navigate("/")} aria-label="Zasp overview">Zasp</button><span>Agent Security</span><ProductionScopeSelector /><Button onClick={() => void session.signOut()}>Sign out</Button></header><aside className="sidebar"><nav aria-label="Main navigation">{routes.map((route) => <a key={route.path} href={route.path} aria-label={route.label} aria-current={visiblePath === route.path ? "page" : undefined} onClick={(event) => { event.preventDefault(); navigate(route.path); }}>{route.label}</a>)}</nav></aside><main className="main-content">{session.scopeSwitch.status === "pending" ? <LoadingState label="Switching authorized scope…" /> : <ProductionRouteSurface key={`${session.organizationID}/${session.workspaceID}/${session.environmentID}`} path={visiblePath} navigate={navigate} />}</main></div></ProductionWorkflowMutationProvider>;
}

export function ZaspProductionApp({ client }: { client?: APIClient } = {}) {
  return <APIProvider client={client}><SessionProvider><ProductionAppContent /></SessionProvider></APIProvider>;
}

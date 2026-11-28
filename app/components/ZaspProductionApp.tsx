"use client";

import { DeploymentSignInLink } from "./DeploymentSignInLink";
import { isSaaSCallback } from "../features/workflows/saasSignIn";
import { AuthPage } from "./AuthPage";
import { useEffect, useMemo, useRef, useState } from "react";
import { Menu, X } from "lucide-react";
import { NavigationIcon } from "./NavigationIcon";
import { ThemeControl } from "./ThemeControl";
import { BrandLogo } from "./BrandLogo";

import type { APIClient } from "../../apps/web/api/client";
import { APIProvider, useAPI } from "../api/APIProvider";
import { SessionProvider, useSession, type SessionContextValue } from "../auth/SessionProvider";
import { AIControlsView } from "../features/administration/AIControlsView";
import { AdminOperationsView } from "../features/administration/AdminOperationsView";
import { AuditExportSaveNotice } from "../features/administration/AuditExportPanel";
import { parseAuditExportLink, type AuditExportIdentity } from "../features/administration/audit-export-resume";
import { ProductionAgentSecurityView } from "../features/agents/ProductionAgentSecurityView";
import { ProductionGuardrailsView } from "../features/guardrails/ProductionGuardrailsView";
import { APIAccessView } from "../features/identity/APIAccessView";
import { IdentityAPIProvider } from "../features/identity/IdentityAPIProvider";
import { IdentityAccessView } from "../features/identity/IdentityAccessView";
import { ScopeOnboardingView } from "../features/identity/ScopeOnboardingView";
import { ProductionRiskView } from "../features/risk/ProductionRiskView";
import { ProductionAttackLabView } from "../features/redteam/ProductionAttackLabView";
import { ProductionRedTeamView } from "../features/redteam/ProductionRedTeamView";
import { RecoveryOperationsView } from "../features/recovery/RecoveryOperationsView";
import { ProductionSecurityAgentsView } from "../features/securityagents/SecurityAgentsView";
import { SecurityAgentAuditView } from "../features/securityagents/SecurityAgentAuditView";
import { SessionsComplianceView } from "../features/sessions/SessionsComplianceView";
import { ProductionSessionsView } from "../features/sessions/RuntimeSessionsView";
import { ProductionSensorSurface } from "../features/sensors/ProductionSensorView";
import { ProductionIntegrationsView, ProductionPoliciesView } from "../features/workflows/ProductionWorkflowViews";
import { ProductionWorkflowMutationProvider, useWorkflowMutationScopeLock } from "../features/workflows/useRetainedWorkflowMutation";
import { Button, LoadingState } from "./ui";
import { ProductionGlobalSearch } from "./ProductionGlobalSearch";
import { enrollSensorLocation, parseActivityLink } from "../domain/activity-links";
import { parseCatalogLink } from "../domain/coverage-links";
import { parseComplianceLink } from "../domain/compliance-links";

// The sidebar follows the order a security team works in: see what exists,
// see what is wrong with it, test it, protect it, investigate, then the
// plumbing (sources and settings).
const productionRoutes = [
  { path: "/", label: "Overview", capability: "inventory.read", group: "" },
  { path: "/discovery/assets", label: "Agents", capability: "inventory.read", group: "Inventory" },
  { path: "/inventory/tools", label: "Tools & MCP", capability: "inventory.read", group: "Inventory" },
  { path: "/identities", label: "Identities", capability: "inventory.read", group: "Inventory" },
  { path: "/inventory/runtimes", label: "Runtimes", capability: "inventory.read", group: "Inventory" },
  { path: "/violations", label: "Findings", capability: "findings.read", group: "Risk" },
  { path: "/exposure/attack-paths", label: "Attack Paths", capability: "attack-paths.read", group: "Risk" },
  { path: "/compliance/evidence", label: "Compliance", capability: "compliance.read", group: "Risk" },
  { path: "/red-team/results", label: "Red Team", capability: "red-team.read", group: "Test" },
  { path: "/test/attack-lab", label: "Attack Lab", capability: "red-team.read", group: "Test" },
  { path: "/policies", label: "Policies", capability: "policies.read", group: "Protect" },
  { path: "/protect/guardrails", label: "Guardrails", capability: "policies.read", group: "Protect" },
  { path: "/protect/security-agents", label: "Security agents", capability: "security-agents.read", group: "Protect" },
  { path: "/protect/approvals", label: "Approvals", capability: "security-agents.read", group: "Protect" },
  { path: "/investigate/sessions", label: "Sessions", capability: "sessions.read", group: "Investigate" },
  { path: "/administration/audit-log", label: "Audit Log", capability: "audit.read", group: "Investigate" },
  { path: "/connectors", label: "Integrations", capability: "integrations.read", group: "Sources" },
  { path: "/integrations/sensors", label: "Sensors", capability: "sensors.read", group: "Sources" },
  { path: "/administration/identity-access", label: "Identity & Access", capability: "identity.manage", group: "Settings" },
  { path: "/administration/api-access", label: "API Access", capability: "api-access.manage", group: "Settings" },
  { path: "/administration/data-retention", label: "Data & Retention", capability: "compliance.read", group: "Settings" },
  { path: "/administration/ai-controls", label: "AI & Models", capability: "compliance.read", group: "Settings" },
  { path: "/administration/recovery", label: "Recovery", capability: "recovery.read", group: "Settings" },
  { path: "/administration/external-data-flows", label: "External Data Flows", capability: "system.read", group: "Settings" },
  { path: "/administration/system-health", label: "System Health", capability: "system.read", group: "Settings" },
] as const;

function ProductionRouteSurface({ path, location, navigate }: { path: string; location: string; navigate(path: string): void }) {
  const session = useSession();
  const { client, auditExports, queryScopeKey, queryGeneration, getSessionInvalidationGeneration, getScopeStaleGeneration } = useAPI();
  if (session.status !== "authenticated") return null;
  if (path === "/compliance/evidence") {
    const catalog = parseCatalogLink(location, session);
    if (catalog.state === "scope_mismatch") return <div className="page" role="alert">This catalog link belongs to a different organization, workspace or environment. Select its authorized scope explicitly.</div>;
    if (catalog.state === "invalid") return <div className="page" role="alert">This catalog link is invalid. Open the framework in Compliance.</div>;
    const compliance = catalog.state === "selected" ? { state: "none" as const } : parseComplianceLink(location, { ...session, principalID: session.principal.id });
    if (compliance.state === "scope_mismatch") return <div className="page" role="alert">This compliance link belongs to a different organization, workspace or environment. Select its authorized scope explicitly.</div>;
    if (compliance.state === "invalid") return <div className="page" role="alert">This compliance link is invalid. Open evidence from the authorized list.</div>;
    const expiry = getSessionInvalidationGeneration(), stale = getScopeStaleGeneration();
    return <SessionsComplianceView surface="compliance" client={client} selectedExport={compliance.state === "export" ? compliance.id : undefined} selectedCatalog={catalog.state === "selected" ? catalog.target : undefined} selectedSource={compliance.state === "selected" ? compliance.target : undefined} onNavigate={navigate} complianceBoundary={{
      principalID: session.principal.id, organizationID: session.organizationID, workspaceID: session.workspaceID, environmentID: session.environmentID, generation: queryGeneration,
      permitted: queryScopeKey !== null && session.hasCapability("compliance.read") && ["view", "view_audit", "view_compliance"].every(permission => session.permissions.includes(permission)),
      fresh: session.isFreshAuthenticated, reauthenticate: session.reauthenticate,
      isCurrent: () => expiry === getSessionInvalidationGeneration() && stale === getScopeStaleGeneration(),
    }} />;
  }
  if (path === "/connectors" && isSaaSCallback(location)) return <ProductionIntegrationsView canWrite={false} location={location} />;
  const activity = parseActivityLink(location, { ...session, principalID: session.principal.id });
  if (activity.state === "scope_mismatch") return <div className="page" role="alert">This activity link belongs to a different organization, workspace or environment. Select the authorized scope explicitly before opening it.</div>;
  if (activity.state === "invalid") return <div className="page" role="alert">This activity link is invalid. Open the record from an authorized product page.</div>;
  const selected = activity.state === "selected" ? activity.target : undefined;
  if (selected && queryScopeKey === null) return <LoadingState label="Revalidating activity access…" />;
  if (selected?.kind === "audit") return <SecurityAgentAuditView key={`${session.principal.id}/${queryGeneration}/${selected.id}`} auditID={selected.id} scope={session} permitted={session.hasCapability("audit.read")} canReadRuns={session.hasCapability("security-agents.read")} onNavigate={navigate} />;
  if (path === "/violations" || path === "/exposure/attack-paths") return <ProductionRiskView path={path} canWrite={session.hasCapability("findings.write")} canRemediate={session.hasCapability("security-agents.write")} canReadRuns={session.hasCapability("security-agents.read")} onNavigate={navigate} selectedID={selected?.id} activityScope={session} />;
  if (path === "/red-team/results") return <ProductionRedTeamView selectedID={selected?.kind === "test_run" ? selected.id : undefined} scopeKey={`${session.principal.id}/${session.organizationID}/${session.workspaceID}/${session.environmentID}`} canWrite={session.hasCapability("red-team.write")} onNavigate={navigate} />;
  if (path === "/test/attack-lab") return <ProductionAttackLabView key={`${session.principal.id}/${queryGeneration}`} canWrite={session.hasCapability("red-team.write")} selectedID={selected?.kind === "attack_lab_run" ? selected.id : undefined} />;
  if (path === "/policies") return <ProductionPoliciesView key={`${queryScopeKey}/${queryGeneration}/${selected?.id ?? "all"}`} initialPolicy={selected?.kind === "policy_draft" ? selected.id : undefined} initialAgent={selected?.kind === "purpose" ? selected.id : undefined} canWrite={session.hasCapability("policies.write")} />;
  if (path === "/protect/guardrails") {
    const initialSection = new URL(location, "https://zasp.invalid").searchParams.get("tab") === "calibration" ? "calibration" : "rules";
    return <ProductionGuardrailsView key={`${session.principal.id}/${session.organizationID}/${session.workspaceID}/${session.environmentID}/${queryGeneration}/${initialSection}`} initialSection={initialSection} canWrite={session.hasCapability("policies.write")} onNavigate={navigate} />;
  }
  if (path === "/connectors") return <ProductionIntegrationsView location={location} canWrite={session.hasCapability("integrations.write")} navigate={navigate} />;
  if (path === "/integrations/sensors") return <ProductionSensorSurface startEnrollment={location === enrollSensorLocation} canManagePolicy={session.permissions.includes("manage_workflows")} canWrite={session.hasCapability("sensors.write")} fresh={session.isFreshAuthenticated} onReauthenticate={session.reauthenticate} />;
  if (path === "/protect/security-agents") return <ProductionSecurityAgentsView environmentID={session.environmentID} selectedID={selected?.id} onNavigate={navigate} />;
  if (path === "/protect/approvals") return <ProductionSecurityAgentsView environmentID={session.environmentID} surface="approvals" selectedID={selected?.kind === "approval" ? selected.id : undefined} onNavigate={navigate} />;
  if (path === "/administration/identity-access") {
    if (queryScopeKey === null) return <LoadingState label="Checking identity access…" />;
    return <IdentityAdministration key={`${session.principal.id}/${queryScopeKey}/${queryGeneration}`} client={client} session={session} />;
  }
  if (path === "/administration/api-access") return <APIAccessView client={client} />;
  if (path === "/investigate/sessions") return <ProductionSessionsView enableInvestigation={session.hasCapability("sessions.read")} key={`${session.principal.id}/${session.organizationID}/${session.workspaceID}/${session.environmentID}/${queryGeneration}`} client={client} canRevokeConsole={session.hasCapability("sessions.revoke")} selectedID={selected?.id} onNavigate={navigate} activityScope={session} canReadRuns={session.hasCapability("security-agents.read")} />;
  if (path === "/administration/ai-controls") return <AIControlsView expectedScope={`${session.organizationID}/${session.workspaceID}/${session.environmentID}`} key={`${session.principal.id}/${queryGeneration}`} client={client} canEditOrganization={session.hasCapability("identity.manage")} canEditEnvironment={session.hasCapability("data-controls.manage")} fresh={session.isFreshAuthenticated} reauthenticate={session.reauthenticate} />;
  if (path === "/administration/data-retention") return <SessionsComplianceView surface="data-controls" client={client} onNavigate={navigate} canMutate={session.hasCapability("data-controls.manage")} />;
  if (path === "/administration/recovery") return <RecoveryOperationsView key={`${session.principal.id}/${location}`} client={client} expectedScope={`${session.organizationID}/${session.workspaceID}/${session.environmentID}`} canWrite={session.hasCapability("recovery.write")} fresh={session.isFreshAuthenticated} onReauthenticate={session.reauthenticate} />;
  if (path === "/administration/system-health") return <AdminOperationsView surface="health" client={client} />;
  if (path === "/administration/external-data-flows") return <AdminOperationsView surface="external" client={client} />;
  if (path === "/administration/audit-log") {
    const expiry = getSessionInvalidationGeneration(), stale = getScopeStaleGeneration();
    return <AdminOperationsView surface="audit" client={client} auditExport={session.hasCapability("audit.exports") ? {
      api: auditExports, authority: { principalID: session.principal.id, organizationID: session.organizationID, workspaceID: session.workspaceID, environmentID: session.environmentID, generation: queryGeneration, permitted: queryScopeKey !== null && session.hasCapability("audit.read"), fresh: session.isFreshAuthenticated,
        isCurrent: () => expiry === getSessionInvalidationGeneration() && stale === getScopeStaleGeneration() },
      retrySession: session.retry, reauthenticate: session.reauthenticate,
    } : undefined} auditBoundary={{
    identityKey: queryScopeKey === null ? null : `${session.principal.id}/${session.organizationID}/${session.workspaceID}/${session.environmentID}/${queryGeneration}`,
    getSessionInvalidationGeneration,
    getScopeStaleGeneration,
  }} />;
  }
  return <ProductionAgentSecurityView path={path} onNavigate={navigate} canWrite={session.hasCapability("inventory.write")} />;
}

function IdentityAdministration({ client, session }: { client: APIClient; session: SessionContextValue }) {
  const [organizationName, setOrganizationName] = useState<string>();
  const manageOrganization = session.hasCapability("identity.manage");
  const readOrganization = manageOrganization || session.hasCapability("identity.scopes.manage");
  return <IdentityAPIProvider client={client}>
    {(manageOrganization || session.hasCapability("identity.groups.manage")) &&
      <IdentityAccessView organizationName={readOrganization ? organizationName : undefined} />}
    {readOrganization && <ScopeOnboardingView client={client} onOrganizationNameChange={setOrganizationName} />}
  </IdentityAPIProvider>;
}

function ProductionScopeSelector() {
  const session = useSession();
  const mutationLocked = useWorkflowMutationScopeLock();
  if (session.status !== "authenticated" || !session.hasCapability("scope.switch") || session.scopes.length < 2) return null;
  const selectedScope = `${session.workspaceID}/${session.environmentID}`;
  return <><select aria-label="Authorized scope" value={selectedScope} disabled={mutationLocked || session.scopeSwitch.status === "pending"} onChange={(event) => { const scope = session.scopes.find((item) => `${item.workspace_id}/${item.environment_id}` === event.target.value); if (scope) void session.switchScope(scope.workspace_id, scope.environment_id); }}>{session.scopes.map((scope) => <option key={`${scope.workspace_id}/${scope.environment_id}`} value={`${scope.workspace_id}/${scope.environment_id}`}>{scope.label}</option>)}</select>{session.scopeSwitch.status === "pending" && <span role="status">Switching scope…</span>}{session.scopeSwitch.status === "error" && <span role="alert">Scope switch failed <Button onClick={() => void session.scopeSwitch.retry()}>Retry</Button></span>}</>;
}

function ProductionSignOutControl() {
  const session = useSession();
  const [state, setState] = useState<"idle" | "pending" | "error">("idle");
  const inFlight = useRef(false);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  const signOut = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setState("pending");
    try {
      await session.signOut();
      if (mounted.current) setState("idle");
    } catch {
      if (mounted.current) setState("error");
    } finally {
      inFlight.current = false;
    }
  };
  return <><Button disabled={state === "pending"} onClick={() => void signOut()}>{state === "pending" ? "Signing out…" : "Sign out"}</Button>{state === "error" && <p role="alert">Sign out failed. Please try again.</p>}</>;
}

function ProductionAppContent() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [searchHost, setSearchHost] = useState<HTMLDivElement | null>(null);
  const menuButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!mobileOpen) return;
    const closeOnEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setMobileOpen(false); menuButton.current?.focus(); }
    };
    document.addEventListener("keydown", closeOnEscape);
    return () => document.removeEventListener("keydown", closeOnEscape);
  }, [mobileOpen]);
  const mainContent = useRef<HTMLElement>(null);
  useEffect(() => {
    if (!window.matchMedia) return;
    const desktop = window.matchMedia("(min-width: 761px)");
    const closeOnDesktop = () => { if (desktop.matches) setMobileOpen(false); };
    desktop.addEventListener("change", closeOnDesktop);
    return () => desktop.removeEventListener("change", closeOnDesktop);
  }, []);
  const session = useSession();
  const { client } = useAPI();
  const [location, setLocation] = useState(() => { const candidate = typeof window === "undefined" ? "/" : window.location.pathname; return productionRoutes.some((route) => route.path === candidate) ? `${candidate}${typeof window === "undefined" ? "" : window.location.search + window.location.hash}` : "/"; });
  const path = location.split(/[?#]/, 1)[0];
  const lastAuthenticatedIdentity = useRef<AuditExportIdentity | null>(null);
  const routes = useMemo(() => session.status === "authenticated"
    ? productionRoutes.filter(route => hasProductionCapability(session, route.capability)) : [], [session]);
  useEffect(() => {
    const syncLocation = () => {
      const { pathname, search, hash } = window.location;
      // Preserve a recognized sign-in return URL until the session tells us which routes are available.
      const allowed = (session.status === "authenticated" ? routes : productionRoutes).some(route => route.path === pathname);
      const current = pathname + search + hash;
      let canonical = allowed ? current : (routes[0]?.path ?? "/");
      if (session.status === "authenticated") {
        const previous = lastAuthenticatedIdentity.current;
        const identity = { principalID: session.principal.id, organizationID: session.organizationID, workspaceID: session.workspaceID, environmentID: session.environmentID };
        // A retained export from this tab must not follow its former owner into a new session.
        if (allowed && previous && parseAuditExportLink(current, previous).state === "selected" &&
            parseAuditExportLink(current, identity).state === "scope_mismatch") canonical = pathname;
        lastAuthenticatedIdentity.current = identity;
      }
      if (canonical !== current) window.history.replaceState({}, "", canonical);
      setLocation(canonical);
    };
    let mounted = true;
    queueMicrotask(() => { if (mounted) syncLocation(); });
    const onPopState = () => { setMobileOpen(false); syncLocation(); };
    window.addEventListener("popstate", onPopState);
    return () => { mounted = false; window.removeEventListener("popstate", onPopState); };
  }, [routes, session]);
  // Right after sign-in or a role change the authorization projection can lag
  // for a few seconds. Reload the session a bounded number of times instead of
  // leaving the person on a manual retry screen.
  const authorizationPending = session.status === "error" && session.authorizationStatus === "pending" && session.scopeSwitch.status !== "error";
  const retrySession = session.retry;
  const pendingRetries = useRef(0);
  const [pendingAttempt, setPendingAttempt] = useState(0);
  useEffect(() => {
    if (!authorizationPending) { if (session.status === "authenticated") pendingRetries.current = 0; return; }
    if (pendingRetries.current >= 8) return;
    const timer = window.setTimeout(() => { pendingRetries.current++; setPendingAttempt((current) => current + 1); void retrySession(); }, 2000);
    return () => window.clearTimeout(timer);
  }, [authorizationPending, retrySession, session.status, pendingAttempt]);
  if (session.status === "loading") return <AuthPage><h1>Loading Zasp</h1><p role="status">Loading authenticated session…</p></AuthPage>;
  if (session.status === "unauthenticated") return <AuthPage><h1>Sign in to Zasp</h1><Button onClick={() => session.signIn(location)}>Sign in</Button><p><DeploymentSignInLink /></p></AuthPage>;
  if (session.status === "forbidden") return <AuthPage><h1>Scope unavailable</h1><p role="alert">Authorization rejected</p></AuthPage>;
  if (session.status === "error") return <AuthPage><h1>{session.authorizationStatus === "pending" ? "Authorization pending" : "Session unavailable"}</h1>{session.authorizationStatus === "pending" && <p role="status">Current access is being applied. This usually takes a few seconds; the page retries on its own. You can also retry now.</p>}{session.scopeSwitch.status === "error" ? <><p role="alert">{session.scopeSwitch.error?.message ?? "Scope reconciliation failed"}</p><Button onClick={() => void session.scopeSwitch.retry()}>Retry scope reconciliation</Button></> : <Button onClick={() => void session.retry()}>Retry</Button>}</AuthPage>;
  if (session.status !== "authenticated") return null;
  if (routes.length === 0) return <AuthPage><h1>No product capabilities</h1><p>Your account has no enabled product routes in this scope.</p><ProductionScopeSelector /><ProductionSignOutControl /></AuthPage>;
  const routeGroups = routes.reduce<{ label: string; routes: (typeof routes)[number][] }[]>((groups, route) => { const last = groups[groups.length - 1]; if (last && last.label === route.group) last.routes.push(route); else groups.push({ label: route.group, routes: [route] }); return groups; }, []);
  const visiblePath = routes.some((route) => route.path === path) ? path : routes[0].path;
  const navigate = (nextLocation: string) => {
    const nextPath = nextLocation.split(/[?#]/, 1)[0];
    if (!routes.some(route => route.path === nextPath)) return;
    window.history.pushState({}, "", nextLocation);
    setLocation(nextLocation);
    setMobileOpen(false);
    if (nextPath !== visiblePath && mainContent.current) mainContent.current.scrollTop = 0;
  };
  const workflowScopeKey = `${session.principal.id}/${session.organizationID}/${session.workspaceID}/${session.environmentID}`;
  const expectedScope = `${session.organizationID}/${session.workspaceID}/${session.environmentID}`;
  const navigation = <nav aria-label="Main navigation">{routeGroups.map((group) => <div key={group.label || "home"} className="nav-section" role="group" aria-label={group.label || "Home"}>
    {group.label && <div className="nav-group-label" aria-hidden="true">{group.label}</div>}
    {group.routes.map((route) => <a key={route.path} href={route.path} aria-label={route.label} aria-current={visiblePath === route.path ? "page" : undefined} onClick={(event) => {
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button !== 0) return;
      event.preventDefault();
      navigate(route.path);
    }}><NavigationIcon path={route.path} /><span>{route.label}</span></a>)}
  </div>)}</nav>;
  return <ProductionWorkflowMutationProvider scopeKey={workflowScopeKey} expectedScope={expectedScope}>
    <div className="app-shell production-app">
      <a className="skip-link" href="#main-content" onClick={event => {
        event.preventDefault();
        if (mainContent.current) {
          mainContent.current.focus({ preventScroll: true });
          mainContent.current.scrollTop = 0;
        }
      }}>Skip to content</a>
      <header className="topbar">
        <button ref={menuButton} className="mobile-menu icon-button" aria-label={mobileOpen ? "Close navigation" : "Open navigation"} aria-controls="product-navigation" aria-expanded={mobileOpen} onClick={() => setMobileOpen(!mobileOpen)}>{mobileOpen ? <X aria-hidden="true" /> : <Menu aria-hidden="true" />}</button>
        <button className="brand" onClick={() => navigate(routes[0].path)} aria-label={routes[0].path === "/" ? "Zasp overview" : `Zasp · ${routes[0].label}`}><BrandLogo /></button>
        <span className="shell-context">Agent Security</span>
        <ProductionGlobalSearch key={expectedScope + location} client={client} onNavigate={navigate} resultsHost={searchHost} scope={session} routes={routes} />
        <ProductionSignOutControl /><ThemeControl />
      </header>
      <aside id="product-navigation" className={`sidebar${mobileOpen ? " sidebar--expanded" : ""}`}><div className="scope-control"><ProductionScopeSelector /></div>{navigation}</aside>
      <main ref={mainContent} className="main-content" id="main-content" tabIndex={-1}><div ref={setSearchHost} id="product-search-results" />{session.scopeSwitch.status === "pending" ? <LoadingState label="Switching authorized scope…" /> : <ProductionRouteSurface key={`${session.organizationID}/${session.workspaceID}/${session.environmentID}`} path={visiblePath} location={visiblePath === path ? location : visiblePath} navigate={navigate} />}</main>
    </div>
  </ProductionWorkflowMutationProvider>;
}

function hasProductionCapability(session: SessionContextValue, capability: string): boolean {
  return session.hasCapability(capability) || capability === "identity.manage" && (session.hasCapability("identity.groups.manage") || session.hasCapability("identity.scopes.manage"));
}

export function ZaspProductionApp({ client }: { client?: APIClient } = {}) {
  return <APIProvider client={client}><SessionProvider><AuditExportSaveNotice /><ProductionAppContent /></SessionProvider></APIProvider>;
}

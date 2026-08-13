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
import { ToolView } from "../features/tools/ToolViews";

function RouteSurface({ route, onNavigate, onToast }: { route: AppRoute; onNavigate: (path: string) => void; onToast: (message: string) => void }) {
  if (route.path === "/") return <OverviewView onNavigate={onNavigate} />;
  if (route.path.startsWith("/discovery/")) return <DiscoveryView route={route} />;
  if (["/identities", "/violations", "/policies"].includes(route.path)) return <GovernanceView route={route} onToast={onToast} />;
  if (route.path.startsWith("/guardrails/")) return <GuardrailView route={route} onNavigate={onNavigate} onToast={onToast} />;
  if (route.path.startsWith("/red-team/")) return <RedTeamView route={route} onNavigate={onNavigate} onToast={onToast} />;
  if (route.path === "/connectors") return <ConnectorView onToast={onToast} />;
  if (["/prompt-hardening", "/reports"].includes(route.path)) return <ToolView route={route} onToast={onToast} />;
  return <div className="page"><h1>{route.title}</h1></div>;
}

function AppContent() {
  const { dispatch } = useZaspStore();
  const [route, setRoute] = useState(() => resolveRoute(typeof window === "undefined" ? "/" : window.location.pathname));
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const navigate = useCallback((path: string) => {
    window.history.pushState({}, "", path);
    setRoute(resolveRoute(path));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);
  useEffect(() => { const handler = () => setRoute(resolveRoute(window.location.pathname)); window.addEventListener("popstate", handler); return () => window.removeEventListener("popstate", handler); }, []);
  return <AppShell route={route} onNavigate={navigate} onSettings={() => setSettingsOpen(true)}><RouteSurface route={route} onNavigate={navigate} onToast={setToast} /><Modal open={settingsOpen} title="Workspace settings" onClose={() => setSettingsOpen(false)} footer={<Button variant="primary" onClick={() => setSettingsOpen(false)}>Done</Button>}><div className="settings-list"><div><strong>Demo environment</strong><p>All actions modify browser-local demonstration data.</p></div><Button variant="danger" onClick={() => { dispatch({ type: "reset" }); window.localStorage.removeItem("zasp-demo-state"); setToast("Demo data reset"); setSettingsOpen(false); }}>Reset demo data</Button></div></Modal>{toast && <Toast message={toast} onClose={() => setToast(null)} />}</AppShell>;
}

export function ZaspApp() { return <ZaspStoreProvider><AppContent /></ZaspStoreProvider>; }

"use client";

import * as Icons from "lucide-react";
import { useState, type ReactNode } from "react";
import type { AppRoute } from "../domain/types";
import { useZaspStore } from "../domain/store";
import { Badge, SearchBox } from "./ui";
import { LeftNav } from "./LeftNav";

export function AppShell({ route, onNavigate, children, onSettings }: { route: AppRoute; onNavigate: (path: string) => void; children: ReactNode; onSettings: () => void }) {
  const { state, dispatch } = useZaspStore();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [globalSearch, setGlobalSearch] = useState("");
  const unread = state.notifications.filter((item) => !item.read).length;
  const navigate = (path: string) => { onNavigate(path); setMobileOpen(false); };
  return <div className="app-shell">
    <header className="topbar">
      <button className="mobile-menu icon-button" aria-label="Open navigation" onClick={() => setMobileOpen(true)}><Icons.Menu /></button>
      <button className="brand" onClick={() => navigate("/")} aria-label="Zasp overview"><span className="brand-mark"><Icons.Shield size={20} /></span><span>Zasp</span></button>
      <button className="workspace-switcher" aria-label="Manage workspaces and environments" onClick={() => navigate("/administration/identity-access")}>Agent Security <Icons.ChevronDown size={15} /></button>
      <div className="global-search"><SearchBox value={globalSearch} onChange={(event) => setGlobalSearch(event.target.value)} placeholder="Search assets, identities, findings, and policies" />{globalSearch && <div className="global-results"><span>Search across Zasp</span>{[...state.assets.map((item) => ({ name: item.name, path: "/discovery/assets", type: item.type })), ...state.identities.map((item) => ({ name: item.name, path: "/identities", type: item.type }))].filter((item) => item.name.toLowerCase().includes(globalSearch.toLowerCase())).slice(0, 6).map((item) => <button key={item.name} onClick={() => { navigate(item.path); setGlobalSearch(""); }}><Icons.Search size={14} /><span>{item.name}<small>{item.type}</small></span></button>)}</div>}</div>
      <div className="topbar-actions"><button className="icon-button topbar-icon" aria-label="Notifications" onClick={() => setNotificationsOpen(!notificationsOpen)}><Icons.Bell />{unread > 0 && <i>{unread}</i>}</button><button className="icon-button topbar-icon" aria-label="Settings" onClick={onSettings}><Icons.Settings /></button><button className="avatar" aria-label="User menu">MM</button></div>
      {notificationsOpen && <div className="notification-panel"><div><strong>Notifications</strong><button onClick={() => dispatch({ type: "notifications.read" })}>Mark all read</button></div>{state.notifications.map((item) => <button key={item.id}><Badge tone={item.severity}>{item.severity}</Badge><span><strong>{item.title}</strong><small>{item.description}</small><em>{item.time}</em></span></button>)}</div>}
    </header>
    <aside className={`sidebar ${mobileOpen ? "sidebar--open" : ""}`}>
      <LeftNav route={route} openFindingCount={state.violations.filter((finding) => finding.status === "open").length} onNavigate={navigate} onClose={() => setMobileOpen(false)} />
    </aside>
    {mobileOpen && <button aria-label="Close navigation overlay" className="sidebar-overlay" onClick={() => setMobileOpen(false)} />}
    <main className="main-content">{children}</main>
  </div>;
}

"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import type { EnvironmentMutation, EnvironmentPage, WorkspaceMutation, WorkspacePage } from "../../../apps/web/api/generated";
import { decodeEnvironment, decodeEnvironmentPage, decodeOrganization, decodeWorkspace, decodeWorkspacePage } from "../../../apps/web/api/administration-decoders";
import { Button, Card, EmptyState, Field, LoadingState, Select } from "../../components/ui";
import { useOptionalSession } from "../../auth/SessionProvider";

export interface ScopeWorkspace { id: string; name: string; version?: number; initialEnvironmentId?: string }
export interface ScopeEnvironment { id: string; workspaceId: string; name: string; version?: number }
export interface ScopeAdminAPI {
  getOrganization?(): Promise<{ id: string; name: string; domain: string }>;
  listWorkspaces(): Promise<ScopeWorkspace[]>;
  createWorkspace(name: string): Promise<ScopeWorkspace>;
  updateWorkspace(id: string, name: string, version?: number): Promise<ScopeWorkspace>;
  listEnvironments(workspaceId: string): Promise<ScopeEnvironment[]>;
  createEnvironment(workspaceId: string, name: string): Promise<ScopeEnvironment>;
  updateEnvironment(id: string, name: string, version?: number): Promise<ScopeEnvironment>;
}

export function createScopeAdminAPI(client: APIClient): ScopeAdminAPI {
  return {
    async getOrganization() { const item = requireAPIData(await client.GET("/api/v1/organization"), decodeOrganization); return { id: item.id, name: item.name, domain: item.domain }; },
    async listWorkspaces() { const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<WorkspacePage>(await client.GET("/api/v1/workspaces", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeWorkspacePage), { maximumItems: 2_000, maximumPages: 20 }); return loaded.items.map((item) => ({ id: item.id, name: item.name, version: item.version })); },
    async createWorkspace(name) { const item = requireAPIData<WorkspaceMutation>(await client.POST("/api/v1/workspaces", { params: { header: { "X-CSRF-Token": "" } }, body: { name } }), decodeWorkspace); return { id: item.id, name: item.name, version: item.version, initialEnvironmentId: item.initial_environment_id }; },
    async updateWorkspace(id, name, version = 1) { const item = requireAPIData<WorkspaceMutation>(await client.PATCH("/api/v1/workspaces/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } }, body: { name } }), decodeWorkspace); return { id: item.id, name: item.name, version: item.version }; },
    async listEnvironments(workspaceId) { const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<EnvironmentPage>(await client.GET("/api/v1/environments", { params: { query: { workspace_id: workspaceId, limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeEnvironmentPage), { maximumItems: 2_000, maximumPages: 20 }); return loaded.items.map((item) => ({ id: item.id, workspaceId: item.workspace_id, name: item.name, version: item.version })); },
    async createEnvironment(workspaceId, name) { const item = requireAPIData<EnvironmentMutation>(await client.POST("/api/v1/environments", { params: { header: { "X-CSRF-Token": "" } }, body: { workspace_id: workspaceId, name } }), decodeEnvironment); return { id: item.id, workspaceId: item.workspace_id, name: item.name, version: item.version }; },
    async updateEnvironment(id, name, version = 1) { const item = requireAPIData<EnvironmentMutation>(await client.PATCH("/api/v1/environments/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } }, body: { name } }), decodeEnvironment); return { id: item.id, workspaceId: item.workspace_id, name: item.name, version: item.version }; },
  };
}

export function ScopeOnboardingView({ api: suppliedAPI, client, onScopeChange }: { api?: ScopeAdminAPI; client?: APIClient; onScopeChange?: (scope: { workspaceId: string; environmentId: string }) => void | Promise<void> }) {
  const liveAPI = useMemo(() => client ? createScopeAdminAPI(client) : null, [client]);
  const api = suppliedAPI ?? liveAPI;
  const session = useOptionalSession();
  const fresh = session?.status === "authenticated" ? session.isFreshAuthenticated : true;
  const [organization, setOrganization] = useState<{ name: string; domain: string } | null>(null);
  const [workspaces, setWorkspaces] = useState<ScopeWorkspace[]>([]);
  const [environments, setEnvironments] = useState<ScopeEnvironment[]>([]);
  const [workspaceId, setWorkspaceId] = useState("");
  const [environmentId, setEnvironmentId] = useState("");
  const [workspaceName, setWorkspaceName] = useState("");
  const [newWorkspaceName, setNewWorkspaceName] = useState("");
  const [environmentName, setEnvironmentName] = useState("");
  const [newEnvironmentName, setNewEnvironmentName] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const activeWorkspaceId = session?.status === "authenticated" ? session.workspaceID : workspaceId;
  const activeEnvironmentId = session?.status === "authenticated" && session.workspaceID === activeWorkspaceId ? session.environmentID : environmentId;
  const changeScope = useCallback(async (scope: { workspaceId: string; environmentId: string }) => {
    if (onScopeChange) await onScopeChange(scope);
    else if (session?.status === "authenticated") await session.switchScope(scope.workspaceId, scope.environmentId);
  }, [onScopeChange, session]);

  const loadWorkspaces = useCallback(async () => {
    try {
      if (!api) throw new Error("administration API unavailable");
      const [values, organizationValue] = await Promise.all([api.listWorkspaces(), api.getOrganization?.()]); setWorkspaces(values);
      if (organizationValue) setOrganization(organizationValue);
      const selected = session?.status === "authenticated" ? values.find((item) => item.id === session.workspaceID) : values[0];
      if (session?.status === "authenticated" && !selected) throw new Error("active workspace not authorized");
      if (selected) { setWorkspaceId(selected.id); setWorkspaceName(selected.name); }
    } catch { setError("Authorized scopes could not be loaded"); }
    finally { setLoading(false); }
  }, [api, session]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void loadWorkspaces(); }); return () => { active = false; }; }, [loadWorkspaces]);
  useEffect(() => {
    let active = true;
    if (!workspaceId) return () => { active = false; };
    if (!api) return () => { active = false; };
    void api.listEnvironments(workspaceId).then((values) => { if (!active) return; const requiresActive = session?.status === "authenticated" && session.workspaceID === workspaceId; const selected = requiresActive ? values.find((item) => item.id === session.environmentID) : values[0]; if (requiresActive && !selected) throw new Error("active environment not authorized"); setEnvironments(values); setEnvironmentId(selected?.id ?? ""); setEnvironmentName(selected?.name ?? ""); }).catch(() => { if (active) setError("Authorized environments could not be loaded"); });
    return () => { active = false; };
  }, [api, session, workspaceId]);
  if (loading) return <LoadingState label="Loading authorized scopes…" />;

  const run = async (operation: () => Promise<void>, message: string) => { setError(null); try { await operation(); setNotice(message); } catch { setError("Scope action could not be completed"); } };
  return <section id="scope-onboarding" className="page identity-access">
    {error && <div className="error-banner" role="alert">{error}</div>}{notice && <div className="success-banner" role="status">{notice}</div>}
    {!fresh && <div className="error-banner" role="alert">Fresh authentication expired. <Button onClick={() => session?.reauthenticate()}>Reauthenticate</Button></div>}
    <div className="identity-grid">
      {organization && <Card title={<h2>Organization</h2>}><p><strong>{organization.name}</strong></p><p>{organization.domain}</p></Card>}
      <Card title={<h2>Workspace onboarding</h2>}>
        {workspaces.length === 0 ? <EmptyState title="No authorized workspaces" description="Create the first Workspace to begin onboarding." /> : <Select label="Authorized workspace" value={activeWorkspaceId} onChange={(event) => { const id = event.target.value; const selected = workspaces.find((item) => item.id === id); setWorkspaceId(id); setWorkspaceName(selected?.name ?? ""); void run(async () => { if (!api) throw new Error(); const authorized = session?.status === "authenticated" ? session.scopes.find((scope) => scope.workspace_id === id) : undefined; if (authorized) { await changeScope({ workspaceId: authorized.workspace_id, environmentId: authorized.environment_id }); return; } const values = await api.listEnvironments(id); const firstEnvironment = values[0]; if (!firstEnvironment) throw new Error("workspace has no authorized environment"); await changeScope({ workspaceId: id, environmentId: firstEnvironment.id }); setEnvironments(values); setEnvironmentId(firstEnvironment.id); setEnvironmentName(firstEnvironment.name); }, "Active scope changed"); }}>{workspaces.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select>}
        <div className="identity-form-row"><Field disabled={!fresh} label="New workspace name" value={newWorkspaceName} onChange={(event) => setNewWorkspaceName(event.target.value)} /><Button disabled={!fresh} variant="primary" onClick={() => { if (!newWorkspaceName.trim()) { setError("Enter a workspace name"); return; } void run(async () => { if (!api) throw new Error(); const created = await api.createWorkspace(newWorkspaceName.trim()); if (!created.initialEnvironmentId) throw new Error("initial environment missing"); await changeScope({ workspaceId: created.id, environmentId: created.initialEnvironmentId }); const initialEnvironment = { id: created.initialEnvironmentId, workspaceId: created.id, name: "Development", version: 1 }; setWorkspaces((current) => [...current, created]); setEnvironments([initialEnvironment]); setWorkspaceId(created.id); setWorkspaceName(created.name); setEnvironmentId(initialEnvironment.id); setEnvironmentName(initialEnvironment.name); setNewWorkspaceName(""); }, "Workspace and initial environment created"); }}>Create workspace</Button></div>
        {workspaceId && <div className="identity-form-row"><Field disabled={!fresh} label="Workspace display name" value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} /><Button disabled={!fresh} onClick={() => void run(async () => { if (!api) throw new Error(); const current = workspaces.find((item) => item.id === workspaceId); const updated = await api.updateWorkspace(workspaceId, workspaceName.trim(), current?.version); setWorkspaces((values) => values.map((item) => item.id === updated.id ? updated : item)); }, "Workspace updated")}>Update workspace</Button></div>}
      </Card>
      <Card title={<h2>Environment onboarding</h2>}>
        {workspaceId && environments.length === 0 ? <EmptyState title="No authorized environments" /> : workspaceId && <Select label="Authorized environment" value={activeEnvironmentId} onChange={(event) => { const id = event.target.value; setEnvironmentId(id); setEnvironmentName(environments.find((item) => item.id === id)?.name ?? ""); void changeScope({ workspaceId, environmentId: id }); }}>{environments.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select>}
        {workspaceId && <div className="identity-form-row"><Field disabled={!fresh} label="New environment name" value={newEnvironmentName} onChange={(event) => setNewEnvironmentName(event.target.value)} /><Button disabled={!fresh} variant="primary" onClick={() => { if (!newEnvironmentName.trim()) { setError("Enter an environment name"); return; } void run(async () => { if (!api) throw new Error(); const created = await api.createEnvironment(workspaceId, newEnvironmentName.trim()); await changeScope({ workspaceId, environmentId: created.id }); setEnvironments((current) => [...current, created]); setEnvironmentId(created.id); setEnvironmentName(created.name); setNewEnvironmentName(""); }, "Environment created"); }}>Create environment</Button></div>}
        {environmentId && <div className="identity-form-row"><Field disabled={!fresh} label="Environment display name" value={environmentName} onChange={(event) => setEnvironmentName(event.target.value)} /><Button disabled={!fresh} onClick={() => void run(async () => { if (!api) throw new Error(); const current = environments.find((item) => item.id === environmentId); const updated = await api.updateEnvironment(environmentId, environmentName.trim(), current?.version); setEnvironments((values) => values.map((item) => item.id === updated.id ? updated : item)); }, "Environment updated")}>Update environment</Button></div>}
      </Card>
    </div>
  </section>;
}

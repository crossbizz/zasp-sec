"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { EnvironmentMutation, EnvironmentPage, WorkspaceMutation, WorkspacePage } from "../../../apps/web/api/generated";
import { decodeEnvironment, decodeEnvironmentPage, decodeOrganization, decodeWorkspace, decodeWorkspacePage } from "../../../apps/web/api/administration-decoders";
import { Button, Card, EmptyState, Field, LoadingState, Select } from "../../components/ui";

export interface ScopeWorkspace { id: string; name: string; version?: number }
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
    async listWorkspaces() { const page = requireAPIData<WorkspacePage>(await client.GET("/api/v1/workspaces"), decodeWorkspacePage); return page.items.map((item) => ({ id: item.id, name: item.name, version: item.version })); },
    async createWorkspace(name) { const item = requireAPIData<WorkspaceMutation>(await client.POST("/api/v1/workspaces", { params: { header: { "X-CSRF-Token": "" } }, body: { name } }), decodeWorkspace); return { id: item.id, name: item.name, version: item.version }; },
    async updateWorkspace(id, name, version = 1) { const item = requireAPIData<WorkspaceMutation>(await client.PATCH("/api/v1/workspaces/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } }, body: { name } }), decodeWorkspace); return { id: item.id, name: item.name, version: item.version }; },
    async listEnvironments(workspaceId) { const page = requireAPIData<EnvironmentPage>(await client.GET("/api/v1/environments", { params: { query: { workspace_id: workspaceId } } }), decodeEnvironmentPage); return page.items.map((item) => ({ id: item.id, workspaceId: item.workspace_id, name: item.name, version: item.version })); },
    async createEnvironment(workspaceId, name) { const item = requireAPIData<EnvironmentMutation>(await client.POST("/api/v1/environments", { params: { header: { "X-CSRF-Token": "" } }, body: { workspace_id: workspaceId, name } }), decodeEnvironment); return { id: item.id, workspaceId: item.workspace_id, name: item.name, version: item.version }; },
    async updateEnvironment(id, name, version = 1) { const item = requireAPIData<EnvironmentMutation>(await client.PATCH("/api/v1/environments/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } }, body: { name } }), decodeEnvironment); return { id: item.id, workspaceId: item.workspace_id, name: item.name, version: item.version }; },
  };
}

export function ScopeOnboardingView({ api: suppliedAPI, client, onScopeChange }: { api?: ScopeAdminAPI; client?: APIClient; onScopeChange?: (scope: { workspaceId: string; environmentId: string }) => void }) {
  const liveAPI = useMemo(() => client ? createScopeAdminAPI(client) : null, [client]);
  const api = suppliedAPI ?? liveAPI;
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

  const loadWorkspaces = useCallback(async () => {
    try {
      if (!api) throw new Error("administration API unavailable");
      const [values, organizationValue] = await Promise.all([api.listWorkspaces(), api.getOrganization?.()]); setWorkspaces(values);
      if (organizationValue) setOrganization(organizationValue);
      const selected = values[0];
      if (selected) { setWorkspaceId(selected.id); setWorkspaceName(selected.name); }
    } catch { setError("Authorized scopes could not be loaded"); }
    finally { setLoading(false); }
  }, [api]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void loadWorkspaces(); }); return () => { active = false; }; }, [loadWorkspaces]);
  useEffect(() => {
    let active = true;
    if (!workspaceId) return () => { active = false; };
    if (!api) return () => { active = false; };
    void api.listEnvironments(workspaceId).then((values) => { if (!active) return; const selected = values[0]; setEnvironments(values); setEnvironmentId(selected?.id ?? ""); setEnvironmentName(selected?.name ?? ""); }).catch(() => { if (active) setError("Authorized environments could not be loaded"); });
    return () => { active = false; };
  }, [api, workspaceId]);
  useEffect(() => { if (workspaceId && environmentId) onScopeChange?.({ workspaceId, environmentId }); }, [environmentId, onScopeChange, workspaceId]);
  if (loading) return <LoadingState label="Loading authorized scopes…" />;

  const run = async (operation: () => Promise<void>, message: string) => { setError(null); try { await operation(); setNotice(message); } catch { setError("Scope action could not be completed"); } };
  return <section id="scope-onboarding" className="page identity-access">
    {error && <div className="error-banner" role="alert">{error}</div>}{notice && <div className="success-banner" role="status">{notice}</div>}
    <div className="identity-grid">
      {organization && <Card title={<h2>Organization</h2>}><p><strong>{organization.name}</strong></p><p>{organization.domain}</p></Card>}
      <Card title={<h2>Workspace onboarding</h2>}>
        {workspaces.length === 0 ? <EmptyState title="No authorized workspaces" description="Create the first Workspace to begin onboarding." /> : <Select label="Authorized workspace" value={workspaceId} onChange={(event) => { const id = event.target.value; setWorkspaceId(id); setWorkspaceName(workspaces.find((item) => item.id === id)?.name ?? ""); }}>{workspaces.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select>}
        <div className="identity-form-row"><Field label="New workspace name" value={newWorkspaceName} onChange={(event) => setNewWorkspaceName(event.target.value)} /><Button variant="primary" onClick={() => { if (!newWorkspaceName.trim()) { setError("Enter a workspace name"); return; } void run(async () => { if (!api) throw new Error(); const created = await api.createWorkspace(newWorkspaceName.trim()); setWorkspaces((current) => [...current, created]); setWorkspaceId(created.id); setWorkspaceName(created.name); setNewWorkspaceName(""); }, "Workspace created"); }}>Create workspace</Button></div>
        {workspaceId && <div className="identity-form-row"><Field label="Workspace display name" value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} /><Button onClick={() => void run(async () => { if (!api) throw new Error(); const current = workspaces.find((item) => item.id === workspaceId); const updated = await api.updateWorkspace(workspaceId, workspaceName.trim(), current?.version); setWorkspaces((values) => values.map((item) => item.id === updated.id ? updated : item)); }, "Workspace updated")}>Update workspace</Button></div>}
      </Card>
      <Card title={<h2>Environment onboarding</h2>}>
        {workspaceId && environments.length === 0 ? <EmptyState title="No authorized environments" /> : workspaceId && <Select label="Authorized environment" value={environmentId} onChange={(event) => { const id = event.target.value; setEnvironmentId(id); setEnvironmentName(environments.find((item) => item.id === id)?.name ?? ""); }}>{environments.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select>}
        {workspaceId && <div className="identity-form-row"><Field label="New environment name" value={newEnvironmentName} onChange={(event) => setNewEnvironmentName(event.target.value)} /><Button variant="primary" onClick={() => { if (!newEnvironmentName.trim()) { setError("Enter an environment name"); return; } void run(async () => { if (!api) throw new Error(); const created = await api.createEnvironment(workspaceId, newEnvironmentName.trim()); setEnvironments((current) => [...current, created]); setEnvironmentId(created.id); setEnvironmentName(created.name); setNewEnvironmentName(""); }, "Environment created"); }}>Create environment</Button></div>}
        {environmentId && <div className="identity-form-row"><Field label="Environment display name" value={environmentName} onChange={(event) => setEnvironmentName(event.target.value)} /><Button onClick={() => void run(async () => { if (!api) throw new Error(); const current = environments.find((item) => item.id === environmentId); const updated = await api.updateEnvironment(environmentId, environmentName.trim(), current?.version); setEnvironments((values) => values.map((item) => item.id === updated.id ? updated : item)); }, "Environment updated")}>Update environment</Button></div>}
      </Card>
    </div>
  </section>;
}

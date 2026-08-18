"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { createAPIClient, type APIClient } from "../../../apps/web/api/client";
import type { EnvironmentMutation, EnvironmentPage, WorkspaceMutation, WorkspacePage } from "../../../apps/web/api/generated";
import { Button, Card, EmptyState, Field, LoadingState, Select } from "../../components/ui";

export interface ScopeWorkspace { id: string; name: string }
export interface ScopeEnvironment { id: string; workspaceId: string; name: string }
export interface ScopeAdminAPI {
  listWorkspaces(): Promise<ScopeWorkspace[]>;
  createWorkspace(name: string): Promise<ScopeWorkspace>;
  updateWorkspace(id: string, name: string): Promise<ScopeWorkspace>;
  listEnvironments(workspaceId: string): Promise<ScopeEnvironment[]>;
  createEnvironment(workspaceId: string, name: string): Promise<ScopeEnvironment>;
  updateEnvironment(id: string, name: string): Promise<ScopeEnvironment>;
}

const authorizedScopeStorageKey = "zasp-authorized-scope";

function savedScope(): { workspaceId: string; environmentId: string } | null {
  try {
    const value = JSON.parse(window.localStorage.getItem(authorizedScopeStorageKey) ?? "null") as unknown;
    if (value && typeof value === "object" && Object.keys(value).length === 2 &&
      Object.hasOwn(value, "workspaceId") && Object.hasOwn(value, "environmentId")) {
      const scope = value as { workspaceId: unknown; environmentId: unknown };
      if (typeof scope.workspaceId === "string" && typeof scope.environmentId === "string" &&
        scope.workspaceId.startsWith("pid_") && scope.environmentId.startsWith("pid_")) return scope as { workspaceId: string; environmentId: string };
    }
  } catch { /* malformed browser-local selection is ignored */ }
  return null;
}

function requireData<T>(value: { data?: unknown; error?: unknown }): T {
  if (value.error || value.data === undefined) throw new Error("product API rejected");
  return value.data as T;
}

export function createScopeAdminAPI(client: APIClient): ScopeAdminAPI {
  return {
    async listWorkspaces() { const page = requireData<WorkspacePage>(await client.GET("/api/v1/workspaces")); return page.items.map((item) => ({ id: item.id, name: item.name })); },
    async createWorkspace(name) { const item = requireData<WorkspaceMutation>(await client.POST("/api/v1/workspaces", { body: { name } })); return { id: item.id, name: item.name }; },
    async updateWorkspace(id, name) { const item = requireData<WorkspaceMutation>(await client.PATCH("/api/v1/workspaces/{id}", { params: { path: { id } }, body: { name } })); return { id: item.id, name: item.name }; },
    async listEnvironments(workspaceId) { const page = requireData<EnvironmentPage>(await client.GET("/api/v1/environments", { params: { query: { workspace_id: workspaceId } } })); return page.items.map((item) => ({ id: item.id, workspaceId: item.workspace_id, name: item.name })); },
    async createEnvironment(workspaceId, name) { const item = requireData<EnvironmentMutation>(await client.POST("/api/v1/environments", { body: { workspace_id: workspaceId, name } })); return { id: item.id, workspaceId: item.workspace_id, name: item.name }; },
    async updateEnvironment(id, name) { const item = requireData<EnvironmentMutation>(await client.PATCH("/api/v1/environments/{id}", { params: { path: { id } }, body: { name } })); return { id: item.id, workspaceId: item.workspace_id, name: item.name }; },
  };
}

export function ScopeOnboardingView({ api: suppliedAPI, onScopeChange }: { api?: ScopeAdminAPI; onScopeChange?: (scope: { workspaceId: string; environmentId: string }) => void }) {
  const liveAPI = useMemo(() => createScopeAdminAPI(createAPIClient()), []);
  const api = suppliedAPI ?? liveAPI;
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
      const values = await api.listWorkspaces(); setWorkspaces(values);
      const retained = savedScope();
      const selected = values.find((item) => item.id === retained?.workspaceId) ?? values[0];
      if (selected) { setWorkspaceId(selected.id); setWorkspaceName(selected.name); }
    } catch { setError("Authorized scopes could not be loaded"); }
    finally { setLoading(false); }
  }, [api]);
  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void loadWorkspaces(); }); return () => { active = false; }; }, [loadWorkspaces]);
  useEffect(() => {
    let active = true;
    if (!workspaceId) return () => { active = false; };
    void api.listEnvironments(workspaceId).then((values) => { if (!active) return; const retained = savedScope(); const selected = values.find((item) => item.id === retained?.environmentId) ?? values[0]; setEnvironments(values); setEnvironmentId(selected?.id ?? ""); setEnvironmentName(selected?.name ?? ""); }).catch(() => { if (active) setError("Authorized environments could not be loaded"); });
    return () => { active = false; };
  }, [api, workspaceId]);
  useEffect(() => { if (workspaceId && environmentId) { const scope = { workspaceId, environmentId }; try { window.localStorage.setItem(authorizedScopeStorageKey, JSON.stringify(scope)); } catch { /* scope remains valid in memory when storage is unavailable */ } onScopeChange?.(scope); } }, [environmentId, onScopeChange, workspaceId]);
  if (loading) return <LoadingState label="Loading authorized scopes…" />;

  const run = async (operation: () => Promise<void>, message: string) => { setError(null); try { await operation(); setNotice(message); } catch { setError("Scope action could not be completed"); } };
  return <section id="scope-onboarding" className="page identity-access">
    {error && <div className="error-banner" role="alert">{error}</div>}{notice && <div className="success-banner" role="status">{notice}</div>}
    <div className="identity-grid">
      <Card title={<h2>Workspace onboarding</h2>}>
        {workspaces.length === 0 ? <EmptyState title="No authorized workspaces" description="Create the first Workspace to begin onboarding." /> : <Select label="Authorized workspace" value={workspaceId} onChange={(event) => { const id = event.target.value; setWorkspaceId(id); setWorkspaceName(workspaces.find((item) => item.id === id)?.name ?? ""); }}>{workspaces.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select>}
        <div className="identity-form-row"><Field label="New workspace name" value={newWorkspaceName} onChange={(event) => setNewWorkspaceName(event.target.value)} /><Button variant="primary" onClick={() => { if (!newWorkspaceName.trim()) { setError("Enter a workspace name"); return; } void run(async () => { const created = await api.createWorkspace(newWorkspaceName.trim()); setWorkspaces((current) => [...current, created]); setWorkspaceId(created.id); setWorkspaceName(created.name); setNewWorkspaceName(""); }, "Workspace created"); }}>Create workspace</Button></div>
        {workspaceId && <div className="identity-form-row"><Field label="Workspace display name" value={workspaceName} onChange={(event) => setWorkspaceName(event.target.value)} /><Button onClick={() => void run(async () => { const updated = await api.updateWorkspace(workspaceId, workspaceName.trim()); setWorkspaces((current) => current.map((item) => item.id === updated.id ? updated : item)); }, "Workspace updated")}>Update workspace</Button></div>}
      </Card>
      <Card title={<h2>Environment onboarding</h2>}>
        {workspaceId && environments.length === 0 ? <EmptyState title="No authorized environments" /> : workspaceId && <Select label="Authorized environment" value={environmentId} onChange={(event) => { const id = event.target.value; setEnvironmentId(id); setEnvironmentName(environments.find((item) => item.id === id)?.name ?? ""); }}>{environments.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</Select>}
        {workspaceId && <div className="identity-form-row"><Field label="New environment name" value={newEnvironmentName} onChange={(event) => setNewEnvironmentName(event.target.value)} /><Button variant="primary" onClick={() => { if (!newEnvironmentName.trim()) { setError("Enter an environment name"); return; } void run(async () => { const created = await api.createEnvironment(workspaceId, newEnvironmentName.trim()); setEnvironments((current) => [...current, created]); setEnvironmentId(created.id); setEnvironmentName(created.name); setNewEnvironmentName(""); }, "Environment created"); }}>Create environment</Button></div>}
        {environmentId && <div className="identity-form-row"><Field label="Environment display name" value={environmentName} onChange={(event) => setEnvironmentName(event.target.value)} /><Button onClick={() => void run(async () => { const updated = await api.updateEnvironment(environmentId, environmentName.trim()); setEnvironments((current) => current.map((item) => item.id === updated.id ? updated : item)); }, "Environment updated")}>Update environment</Button></div>}
      </Card>
    </div>
  </section>;
}

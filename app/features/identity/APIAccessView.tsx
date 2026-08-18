"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { createAPIClient, type APIClient } from "../../../apps/web/api/client";
import type { ApiToken, ApiTokenCredential, ApiTokenPage } from "../../../apps/web/api/generated";
import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader } from "../../components/ui";

export interface APIAccessToken {
  id: string;
  name: string;
  workspaceId: string;
  environmentId: string;
  permissions: string[];
  expiresAt: string;
  revokedAt: string | null;
  rawToken?: string;
}

export interface APIAccessAPI {
  listTokens(): Promise<APIAccessToken[]>;
  createToken(input: Omit<APIAccessToken, "id" | "revokedAt" | "rawToken">): Promise<APIAccessToken>;
  revokeToken(id: string): Promise<APIAccessToken>;
}

function requireData<T>(value: { data?: unknown; error?: unknown }): T {
  if (value.error || value.data === undefined) throw new Error("product API rejected");
  return value.data as T;
}

function tokenView(token: ApiToken | ApiTokenCredential): APIAccessToken {
  return {
    id: token.id,
    name: token.name,
    workspaceId: token.workspace_id,
    environmentId: token.environment_id,
    permissions: [...token.permissions],
    expiresAt: token.expires_at,
    revokedAt: token.revoked_at,
    ...(Object.hasOwn(token, "raw_token") ? { rawToken: (token as ApiTokenCredential).raw_token } : {}),
  };
}

export function createAPIAccessAPI(client: APIClient): APIAccessAPI {
  return {
    async listTokens() {
      const page = requireData<ApiTokenPage>(await client.GET("/api/v1/admin/api-tokens"));
      return page.items.map(tokenView);
    },
    async createToken(input) {
      const token = requireData<ApiTokenCredential>(await client.POST("/api/v1/admin/api-tokens", { body: {
        name: input.name,
        workspace_id: input.workspaceId,
        environment_id: input.environmentId,
        permissions: input.permissions as ApiTokenCredential["permissions"],
        expires_at: input.expiresAt,
      } }));
      return tokenView(token);
    },
    async revokeToken(id) {
      return tokenView(requireData<ApiToken>(await client.DELETE("/api/v1/admin/api-tokens/{id}", { params: { path: { id } } })));
    },
  };
}

export function APIAccessView({ api: suppliedAPI }: { api?: APIAccessAPI }) {
  const liveAPI = useMemo(() => createAPIAccessAPI(createAPIClient()), []);
  const api = suppliedAPI ?? liveAPI;
  const [tokens, setTokens] = useState<APIAccessToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [rawToken, setRawToken] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [workspaceId, setWorkspaceId] = useState("");
  const [environmentId, setEnvironmentId] = useState("");

  const load = useCallback(async () => {
    try {
      setTokens(await api.listTokens());
    } catch {
      setError("API access could not be loaded");
    } finally {
      setLoading(false);
    }
  }, [api]);

  useEffect(() => { let active = true; queueMicrotask(() => { if (active) void load(); }); return () => { active = false; }; }, [load]);
  if (loading) return <div className="page"><LoadingState label="Loading API access…" /></div>;

  const expiresAt = () => new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  return <div className="page api-access">
    <PageHeader title="API Access" eyebrow="Administration" description="Create scoped automation credentials and revoke them without exposing stored secrets." />
    {error && <div className="error-banner" role="alert">{error}</div>}
    {notice && <div className="success-banner" role="status">{notice}</div>}
    {rawToken && <div className="credential-once"><strong>Shown only once.</strong> Save this token now: {rawToken} <Button onClick={() => setRawToken(null)}>Dismiss token</Button></div>}
    <Card title={<h2>Create API token</h2>}>
      <div className="identity-form-grid">
        <Field label="Token name" value={name} onChange={(event) => setName(event.target.value)} />
        <Field label="Workspace ID" value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)} />
        <Field label="Environment ID" value={environmentId} onChange={(event) => setEnvironmentId(event.target.value)} />
      </div>
      <Button variant="primary" onClick={() => void (async () => {
        setError(null); setNotice(null); setRawToken(null);
        if (!name.trim() || !workspaceId.startsWith("pid_") || !environmentId.startsWith("pid_")) { setError("Enter token name and canonical scope IDs"); return; }
        try {
          const created = await api.createToken({ name: name.trim(), workspaceId, environmentId, permissions: ["view"], expiresAt: expiresAt() });
          setTokens((current) => [...current, { ...created, rawToken: undefined }]); setRawToken(created.rawToken ?? null); setNotice("API token created");
        } catch { setError("API token could not be created"); }
      })()}>Create API token</Button>
    </Card>
    <Card title={<h2>Active API tokens</h2>}>
      {tokens.length === 0 ? <EmptyState title="No API tokens" description="Create a scoped credential for automation." /> : <ul className="identity-list">{tokens.map((token) => <li key={token.id}><span><strong>{token.name}</strong><small>{token.permissions.join(" · ")} · expires {token.expiresAt}</small></span><div className="row-actions"><Badge tone={token.revokedAt ? "neutral" : "success"}>{token.revokedAt ? "Revoked" : "Active"}</Badge>{!token.revokedAt && <Button variant="danger" aria-label={`Revoke ${token.name}`} onClick={() => { if (window.confirm(`Revoke ${token.name}?`)) void (async () => { try { const revoked = await api.revokeToken(token.id); setTokens((current) => current.map((item) => item.id === token.id ? revoked : item)); setNotice("API token revoked"); } catch { setError("API token could not be revoked"); } })(); }}>Revoke</Button>}</div></li>)}</ul>}
    </Card>
  </div>;
}

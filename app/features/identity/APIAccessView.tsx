"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { ApiToken, ApiTokenCredential, ApiTokenPage } from "../../../apps/web/api/generated";
import { decodeAPIToken, decodeAPITokenCredential, decodeAPITokenPage } from "../../../apps/web/api/administration-decoders";
import { Badge, Button, Card, EmptyState, Field, LoadingState, PageHeader } from "../../components/ui";

export interface APIAccessToken {
  id: string;
  name: string;
  workspaceId: string;
  environmentId: string;
  permissions: string[];
  expiresAt: string;
  revokedAt: string | null;
  version: number;
  rawToken?: string;
}

export interface APIAccessAPI {
  listTokens(): Promise<APIAccessToken[]>;
  createToken(input: Omit<APIAccessToken, "id" | "revokedAt" | "rawToken" | "version">): Promise<APIAccessToken>;
  rotateToken(id: string, version: number): Promise<APIAccessToken>;
  revokeToken(id: string, version: number): Promise<APIAccessToken>;
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
    version: token.version,
    ...(Object.hasOwn(token, "raw_token") ? { rawToken: (token as ApiTokenCredential).raw_token } : {}),
  };
}

export function createAPIAccessAPI(client: APIClient): APIAccessAPI {
  return {
    async listTokens() {
      const page = requireAPIData<ApiTokenPage>(await client.GET("/api/v1/admin/api-tokens"), decodeAPITokenPage);
      return page.items.map(tokenView);
    },
    async createToken(input) {
      const token = requireAPIData<ApiTokenCredential>(await client.POST("/api/v1/admin/api-tokens", { params: { header: { "X-CSRF-Token": "", "Idempotency-Key": `admin_${crypto.randomUUID()}` } }, body: {
        name: input.name,
        workspace_id: input.workspaceId,
        environment_id: input.environmentId,
        permissions: input.permissions as ApiTokenCredential["permissions"],
        expires_at: input.expiresAt,
      } }), decodeAPITokenCredential);
      return tokenView(token);
    },
    async rotateToken(id, version) {
      const token = requireAPIData<ApiTokenCredential>(await client.POST("/api/v1/admin/api-tokens/{id}/rotate", { params: { path: { id }, header: { "X-CSRF-Token": "", "Idempotency-Key": `admin_${crypto.randomUUID()}`, "If-Match": `"${version}"` } }, body: {} }), decodeAPITokenCredential);
      return tokenView(token);
    },
    async revokeToken(id, version) {
      return tokenView(requireAPIData<ApiToken>(await client.DELETE("/api/v1/admin/api-tokens/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } } }), decodeAPIToken));
    },
  };
}

export function APIAccessView({ api: suppliedAPI, client }: { api?: APIAccessAPI; client?: APIClient }) {
  const liveAPI = useMemo(() => client ? createAPIAccessAPI(client) : null, [client]);
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
      if (!api) throw new Error();
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
          if (!api) throw new Error();
          const created = await api.createToken({ name: name.trim(), workspaceId, environmentId, permissions: ["view"], expiresAt: expiresAt() });
          setTokens((current) => [...current, { ...created, rawToken: undefined }]); setRawToken(created.rawToken ?? null); setNotice("API token created");
        } catch { setError("API token could not be created"); }
      })()}>Create API token</Button>
    </Card>
    <Card title={<h2>Active API tokens</h2>}>
      {tokens.length === 0 ? <EmptyState title="No API tokens" description="Create a scoped credential for automation." /> : <ul className="identity-list">{tokens.map((token) => <li key={token.id}><span><strong>{token.name}</strong><small>{token.permissions.join(" · ")} · expires {token.expiresAt}</small></span><div className="row-actions"><Badge tone={token.revokedAt ? "neutral" : "success"}>{token.revokedAt ? "Revoked" : "Active"}</Badge>{!token.revokedAt && <><Button aria-label={`Rotate ${token.name}`} onClick={() => void (async () => { try { if (!api) throw new Error(); setRawToken(null); const rotated = await api.rotateToken(token.id, token.version); setTokens((current) => [...current.filter((item) => item.id !== token.id), { ...rotated, rawToken: undefined }]); setRawToken(rotated.rawToken ?? null); setNotice("API token rotated"); } catch { setError("API token could not be rotated; reload token inventory before retrying"); } })()}>Rotate</Button><Button variant="danger" aria-label={`Revoke ${token.name}`} onClick={() => { if (window.confirm(`Revoke ${token.name}?`)) void (async () => { try { if (!api) throw new Error(); const revoked = await api.revokeToken(token.id, token.version); setTokens((current) => current.map((item) => item.id === token.id ? revoked : item)); setNotice("API token revoked"); } catch { setError("API token could not be revoked"); } })(); }}>Revoke</Button></>}</div></li>)}</ul>}
    </Card>
  </div>;
}

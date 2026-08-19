"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import type { ApiToken, ApiTokenPage, ApiTokenRevealedCredential, ApiTokenRevealGrant, ApiTokenRevealGrantPage } from "../../../apps/web/api/generated";
import { decodeAPIToken, decodeAPITokenPage, decodeAPITokenRevealedCredential, decodeAPITokenRevealGrant, decodeAPITokenRevealGrantPage } from "../../../apps/web/api/administration-decoders";
import { useOptionalSession } from "../../auth/SessionProvider";
import { Badge, Button, Card, EmptyState, Field, LoadingState, Modal, PageHeader } from "../../components/ui";

const MAXIMUM_LIST_ITEMS = 2_000;
const MAXIMUM_LIST_PAGES = 20;

export interface APIAccessToken {
  id: string; name: string; workspaceId: string; environmentId: string; permissions: string[];
  expiresAt: string; revokedAt: string | null; version: number;
}
export interface APIAccessGrant { grantId: string; tokenId: string; operation: "createAPIToken" | "rotateAPIToken"; expiresAt: string; }
export interface APIAccessGrantResult { grant: APIAccessGrant; token: APIAccessToken; }
export interface APIAccessRevealedCredential { grantId: string; tokenId: string; rawToken: string; expiresAt: string; }

export interface APIAccessAPI {
  listTokens(signal?: AbortSignal): Promise<APIAccessToken[]>;
  listPendingGrants(signal?: AbortSignal): Promise<APIAccessGrant[]>;
  createToken(input: Omit<APIAccessToken, "id" | "revokedAt" | "version">, idempotencyKey: string): Promise<APIAccessGrantResult>;
  rotateToken(id: string, version: number, idempotencyKey: string): Promise<APIAccessGrantResult>;
  revealGrant(id: string): Promise<APIAccessRevealedCredential>;
  acknowledgeGrant(id: string): Promise<void>;
  revokeToken(id: string, version: number): Promise<APIAccessToken>;
}

function tokenView(token: ApiToken): APIAccessToken {
  return { id: token.id, name: token.name, workspaceId: token.workspace_id, environmentId: token.environment_id, permissions: [...token.permissions], expiresAt: token.expires_at, revokedAt: token.revoked_at, version: token.version };
}
function grantView(grant: { readonly grant_id: string; readonly token_id: string; readonly operation: "createAPIToken" | "rotateAPIToken"; readonly expires_at: string }): APIAccessGrant {
  return { grantId: grant.grant_id, tokenId: grant.token_id, operation: grant.operation, expiresAt: grant.expires_at };
}

export function createAPIAccessAPI(client: APIClient): APIAccessAPI {
  return {
    async listTokens(signal) {
      return loadAll(async (cursor) => requireAPIData<ApiTokenPage>(await client.GET("/api/v1/admin/api-tokens", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } }, signal }), decodeAPITokenPage), tokenView);
    },
    async listPendingGrants(signal) {
      return loadAll(async (cursor) => requireAPIData<ApiTokenRevealGrantPage>(await client.GET("/api/v1/admin/api-token-reveal-grants", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } }, signal }), decodeAPITokenRevealGrantPage), grantView);
    },
    async createToken(input, idempotencyKey) {
      const result = requireAPIData<ApiTokenRevealGrant>(await client.POST("/api/v1/admin/api-tokens", { params: { header: { "X-CSRF-Token": "", "Idempotency-Key": idempotencyKey } }, body: { name: input.name, workspace_id: input.workspaceId, environment_id: input.environmentId, permissions: input.permissions as ApiToken["permissions"], expires_at: input.expiresAt } }), decodeAPITokenRevealGrant);
      return { grant: { grantId: result.grant_id, tokenId: result.token.id, operation: "createAPIToken", expiresAt: result.expires_at }, token: tokenView(result.token) };
    },
    async rotateToken(id, version, idempotencyKey) {
      const result = requireAPIData<ApiTokenRevealGrant>(await client.POST("/api/v1/admin/api-tokens/{id}/rotate", { params: { path: { id }, header: { "X-CSRF-Token": "", "Idempotency-Key": idempotencyKey, "If-Match": `"${version}"` } }, body: {} }), decodeAPITokenRevealGrant);
      return { grant: { grantId: result.grant_id, tokenId: result.token.id, operation: "rotateAPIToken", expiresAt: result.expires_at }, token: tokenView(result.token) };
    },
    async revealGrant(id) {
      const value = requireAPIData<ApiTokenRevealedCredential>(await client.POST("/api/v1/admin/api-token-reveal-grants/{id}/reveal", { params: { path: { id }, header: { "X-CSRF-Token": "" } }, body: {} }), decodeAPITokenRevealedCredential);
      return { grantId: value.grant_id, tokenId: value.token_id, rawToken: value.raw_token, expiresAt: value.expires_at };
    },
    async acknowledgeGrant(id) {
      const result = await client.DELETE("/api/v1/admin/api-token-reveal-grants/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "" } }, body: {} });
      if (result.error || result.response.status !== 204) requireAPIData<never>(result);
    },
    async revokeToken(id, version) {
      return tokenView(requireAPIData<ApiToken>(await client.DELETE("/api/v1/admin/api-tokens/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } } }), decodeAPIToken));
    },
  };
}

async function loadAll<T, U>(read: (cursor?: string) => Promise<{ readonly items: readonly T[]; readonly page_info: { readonly next_cursor: string | null; readonly has_more: boolean } }>, map: (item: T) => U): Promise<U[]> {
  const result: U[] = []; let cursor: string | undefined;
  for (let page = 0; page < MAXIMUM_LIST_PAGES; page += 1) {
    const response = await read(cursor); result.push(...response.items.map(map));
    if (result.length > MAXIMUM_LIST_ITEMS) throw new Error("bounded list exceeded");
    if (!response.page_info.has_more) return result;
    if (!response.page_info.next_cursor || response.page_info.next_cursor === cursor) throw new Error("invalid list continuation");
    cursor = response.page_info.next_cursor;
  }
  throw new Error("bounded list page cap exceeded");
}

type PendingMutation = { kind: "create"; key: string; fingerprint: string } | { kind: "rotate"; key: string; tokenID: string };

export function APIAccessView({ api: suppliedAPI, client }: { api?: APIAccessAPI; client?: APIClient }) {
  const liveAPI = useMemo(() => client ? createAPIAccessAPI(client) : null, [client]);
  const api = suppliedAPI ?? liveAPI;
  const session = useOptionalSession();
  const fresh = session?.status === "authenticated" ? session.isFreshAuthenticated : true;
  const [tokens, setTokens] = useState<APIAccessToken[]>([]);
  const [grants, setGrants] = useState<APIAccessGrant[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<APIAccessRevealedCredential | null>(null);
  const [secretStatus, setSecretStatus] = useState("");
  const [acknowledging, setAcknowledging] = useState(false);
  const [name, setName] = useState(""); const [workspaceId, setWorkspaceId] = useState(""); const [environmentId, setEnvironmentId] = useState("");
  const pendingMutation = useRef<PendingMutation | null>(null);

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      if (!api) throw new Error();
      const [nextTokens, nextGrants] = await Promise.all([api.listTokens(signal), api.listPendingGrants(signal)]);
      setTokens(nextTokens); setGrants(nextGrants); setError(null);
    } catch (cause) { if ((cause as { name?: string }).name !== "AbortError") setError("API access could not be loaded"); }
    finally { if (!signal?.aborted) setLoading(false); }
  }, [api]);

  useEffect(() => { const controller = new AbortController(); queueMicrotask(() => void load(controller.signal)); return () => controller.abort(); }, [load]);
  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => { if (revealed || pendingMutation.current) event.preventDefault(); };
    window.addEventListener("beforeunload", warn); return () => window.removeEventListener("beforeunload", warn);
  }, [revealed]);
  if (loading) return <div className="page"><LoadingState label="Loading API access…" /></div>;

  const reveal = async (grant: APIAccessGrant) => {
    if (!api || !fresh) return;
    setError(null); setSecretStatus("");
    try { setRevealed(await api.revealGrant(grant.grantId)); }
    catch { setError("The API token reveal grant is unavailable or expired"); await load(); }
  };
  const closeSecret = async () => {
    if (!api || !revealed || acknowledging) return;
    setAcknowledging(true); setSecretStatus("Destroying the encrypted recovery copy…");
    try { await api.acknowledgeGrant(revealed.grantId); setGrants((current) => current.filter((grant) => grant.grantId !== revealed.grantId)); setRevealed(null); setSecretStatus(""); setNotice("API token saved and reveal grant acknowledged"); }
    catch { setSecretStatus("Acknowledgement failed. Keep this dialog open and retry."); }
    finally { setAcknowledging(false); }
  };
  const reconcileMutation = async () => { await load(); pendingMutation.current = null; };
  const expiresAt = () => new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
  return <div className="page api-access">
    <PageHeader title="API Access" eyebrow="Administration" description="Create scoped automation credentials with encrypted, restart-safe one-time reveal recovery." />
    {error && <div className="error-banner" role="alert">{error}</div>}{notice && <div className="success-banner" role="status">{notice}</div>}
    {!fresh && <div className="error-banner" role="alert">Fresh authentication expired. <Button onClick={() => session?.reauthenticate()}>Reauthenticate</Button></div>}
    <Modal open={revealed !== null} title="Save API token" closeDisabled={acknowledging} onClose={() => void closeSecret()} footer={<Button disabled={acknowledging} onClick={() => void closeSecret()}>I saved it — destroy recovery copy</Button>}>
      <p>This secret is recoverable only until you acknowledge it or the reveal grant expires.</p><pre aria-label="API token credential">{revealed?.rawToken}</pre>
      <Button disabled={!revealed || acknowledging} onClick={() => void (async () => { try { if (!revealed) return; await navigator.clipboard.writeText(revealed.rawToken); setSecretStatus("Token copied to clipboard"); } catch { setSecretStatus("Copy failed. Select and copy the token manually."); } })()}>Copy token</Button>
      <p role="status" aria-live="polite">{secretStatus}</p>
    </Modal>
    <Card title={<h2>Pending reveal grants</h2>}>
      {grants.length === 0 ? <EmptyState title="No pending credentials" description="Unacknowledged token credentials after create or rotate appear here across reloads." /> : <ul className="identity-list">{grants.map((grant) => <li key={grant.grantId}><span><strong>{grant.operation === "createAPIToken" ? "Created token" : "Rotated token"}</strong><small>expires {grant.expiresAt}</small></span><Button disabled={!fresh || revealed !== null} onClick={() => void reveal(grant)}>Reveal token</Button></li>)}</ul>}
    </Card>
    <Card title={<h2>Create API token</h2>}><div className="identity-form-grid"><Field disabled={!fresh} label="Token name" value={name} onChange={(event) => setName(event.target.value)} /><Field disabled={!fresh} label="Workspace ID" value={workspaceId} onChange={(event) => setWorkspaceId(event.target.value)} /><Field disabled={!fresh} label="Environment ID" value={environmentId} onChange={(event) => setEnvironmentId(event.target.value)} /></div>
      <Button variant="primary" disabled={!fresh || revealed !== null} onClick={() => void (async () => {
        setError(null); setNotice(null); if (!name.trim() || !workspaceId.startsWith("pid_") || !environmentId.startsWith("pid_")) { setError("Enter token name and canonical scope IDs"); return; } if (!api) { setError("API token could not be created"); return; }
        const fingerprint = JSON.stringify([name.trim(), workspaceId, environmentId]); const retained = pendingMutation.current; const key = retained?.kind === "create" && retained.fingerprint === fingerprint ? retained.key : `admin_${crypto.randomUUID()}`; pendingMutation.current = { kind: "create", key, fingerprint };
        try { const created = await api.createToken({ name: name.trim(), workspaceId, environmentId, permissions: ["view"], expiresAt: expiresAt() }, key); setTokens((current) => [...current.filter((item) => item.id !== created.token.id), created.token]); setGrants((current) => [...current.filter((item) => item.grantId !== created.grant.grantId), created.grant]); pendingMutation.current = null; setNotice("API token created; reveal it before the grant expires"); await reveal(created.grant); }
        catch { setError("Create response was interrupted. Reconciling the durable reveal grant before any retry."); await reconcileMutation(); }
      })()}>Create API token</Button>
    </Card>
    <Card title={<h2>API tokens</h2>}>{tokens.length === 0 ? <EmptyState title="No API tokens" description="Create a scoped credential for automation." /> : <ul className="identity-list">{tokens.map((token) => <li key={token.id}><span><strong>{token.name}</strong><small>{token.permissions.join(" · ")} · expires {token.expiresAt}</small></span><div className="row-actions"><Badge tone={token.revokedAt ? "neutral" : "success"}>{token.revokedAt ? "Revoked" : "Active"}</Badge>{!token.revokedAt && <><Button disabled={!fresh || revealed !== null} aria-label={`Rotate ${token.name}`} onClick={() => void (async () => { if (!api) return; const retained = pendingMutation.current; const key = retained?.kind === "rotate" && retained.tokenID === token.id ? retained.key : `admin_${crypto.randomUUID()}`; pendingMutation.current = { kind: "rotate", key, tokenID: token.id }; try { const rotated = await api.rotateToken(token.id, token.version, key); setTokens((current) => [...current.filter((item) => item.id !== token.id && item.id !== rotated.token.id), rotated.token]); setGrants((current) => [...current.filter((item) => item.grantId !== rotated.grant.grantId), rotated.grant]); pendingMutation.current = null; setNotice("API token rotated; the old token is revoked"); await reveal(rotated.grant); } catch { setError("Rotate response was interrupted. Reconciling before retry."); await reconcileMutation(); } })()}>Rotate</Button><Button disabled={!fresh || revealed !== null} variant="danger" aria-label={`Revoke ${token.name}`} onClick={() => { if (window.confirm(`Revoke ${token.name}?`)) void (async () => { try { if (!api) throw new Error(); const revoked = await api.revokeToken(token.id, token.version); setTokens((current) => current.map((item) => item.id === token.id ? revoked : item)); setGrants((current) => current.filter((grant) => grant.tokenId !== token.id)); setNotice("API token revoked"); } catch { setError("API token could not be revoked"); } })(); }}>Revoke</Button></>}</div></li>)}</ul>}</Card>
  </div>;
}

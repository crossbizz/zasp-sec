export type OperatorSession = { deployment_id: string; csrf_token: string; expires_at: string };
export type ServiceAccess = { api_url: string; dashboard_url: string; login_hint: string; credential_ref: string };
export type OperatorSettings = { deployment_id: string; version: number; nango: ServiceAccess; opensearch: ServiceAccess };

export class OperatorRequestError extends Error {
  constructor(readonly status: number) { super("Deployment administration request failed"); }
}

async function request(path: "session" | "settings", init: RequestInit): Promise<unknown> {
  // This fixed same-origin API authenticates deployment operators independently of the tenant API.
  // eslint-disable-next-line zasp/no-raw-fetch
  const response = await fetch(`/api/v1/deployment-admin/${path}`, {
    ...init,
    credentials: "same-origin", cache: "no-store", redirect: "error", referrerPolicy: "no-referrer",
    headers: { Accept: "application/json", ...(init.body ? { "Content-Type": "application/json" } : {}), ...init.headers },
    signal: init.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(15_000)]) : AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new OperatorRequestError(response.status);
  return response.status === 204 ? null : response.json();
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function session(value: unknown): OperatorSession {
  if (!record(value) || typeof value.deployment_id !== "string" || !value.deployment_id
    || typeof value.csrf_token !== "string" || !value.csrf_token || typeof value.expires_at !== "string" || !Number.isFinite(Date.parse(value.expires_at))) {
    throw new Error("Invalid deployment session");
  }
  if (Date.parse(value.expires_at) <= Date.now()) throw new OperatorRequestError(401);
  return { deployment_id: value.deployment_id, csrf_token: value.csrf_token, expires_at: value.expires_at };
}

function serviceAccess(value: unknown): ServiceAccess {
  if (!record(value) || typeof value.api_url !== "string" || typeof value.dashboard_url !== "string" || typeof value.login_hint !== "string" || typeof value.credential_ref !== "string") throw new Error("Invalid service settings");
  return { api_url: value.api_url, dashboard_url: value.dashboard_url, login_hint: value.login_hint, credential_ref: value.credential_ref };
}

function settings(value: unknown, deployment: string): OperatorSettings {
  if (!record(value) || value.deployment_id !== deployment || !Number.isSafeInteger(value.version) || typeof value.version !== "number" || value.version < 0) throw new Error("Invalid deployment settings");
  return { deployment_id: deployment, version: value.version, nango: serviceAccess(value.nango), opensearch: serviceAccess(value.opensearch) };
}

export const operatorAPI = {
  async session(signal: AbortSignal) { return session(await request("session", { signal })); },
  async signIn(password: string) { return session(await request("session", { method: "POST", body: JSON.stringify({ password }) })); },
  async signOut(current: OperatorSession) { await request("session", { method: "DELETE", headers: { "X-CSRF-Token": current.csrf_token } }); },
  async settings(current: OperatorSession, signal: AbortSignal) { return settings(await request("settings", { signal }), current.deployment_id); },
  async save(current: OperatorSession, draft: OperatorSettings) {
    const { version, nango, opensearch } = draft;
    return settings(await request("settings", { method: "PUT", headers: { "X-CSRF-Token": current.csrf_token }, body: JSON.stringify({ version, nango, opensearch }) }), current.deployment_id);
  },
};

export function dashboardLink(pointer: string): string | undefined {
  if (!pointer || !/^https?:\/\//i.test(pointer) || pointer.trim() !== pointer || /[\\\s?#]/u.test(pointer)) return undefined;
  try {
    const url = new URL(pointer);
    if (!url.hostname || url.username || url.password || url.hostname.includes("..")) return undefined;
    if (url.protocol === "http:" && !privateHTTPHost(url.hostname)) return undefined;
    return url.href;
  } catch { return undefined; }
}

function privateHTTPHost(host: string) {
  return host === "localhost" || host.endsWith(".svc") || host.endsWith(".svc.cluster.local") || host === "[::1]"
    || /^\[f[cd][0-9a-f]{2}:/i.test(host) || /^(?:(?:127|10)\.\d+|192\.168|172\.(?:1[6-9]|2[0-9]|3[01]))\.\d+\.\d+$/.test(host);
}

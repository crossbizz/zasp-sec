import { describe, expect, it, vi } from "vitest";
import { createAPIClient } from "./client";
import { createAuditLogAPI, normalizeAuditFilters } from "./audit-log";
import { auditExportVolumeMetadata } from "../../../scripts/audit-export-browser-proof.mjs";

const id = "pid_10000001-0000-4000-8000-000000000001";
const event = { id, workspace_id: id, environment_id: id, actor_id: id, action: "identity_provider.createSSOConnection", target_id: id, outcome: "succeeded", metadata: {}, occurred_at: "2026-09-12T00:00:00.123456Z" };
const page = { items: [event], page_info: { has_more: false, next_cursor: null } };
const signal = () => new AbortController().signal;
function json(value: unknown, status = 200) { return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } }); }

describe("generated audit page adapter", () => {
  it("accepts the actual large-export fixture without oversized metadata values", async () => {
    const metadata = { ...auditExportVolumeMetadata(), counter: "100001" };
    const fixture = { ...page, items: [{ ...event, metadata }] };
    const api = createAuditLogAPI(createAPIClient({ fetch: async () => json(fixture) }));
    const decoded = await api.page({}, undefined, 50, signal());
    expect(decoded.items[0].metadata).toEqual(metadata);
    expect(JSON.stringify(decoded.items[0]).length).toBeGreaterThan(1100);
  });

  it("shares read ownership across recreated adapters for one client without blocking another client", async () => {
    const requests: Request[] = [];
    let settle!: (response: Response) => void;
    const old = new Promise<Response>(resolve => { settle = resolve; });
    const client = createAPIClient({ fetch: async request => { requests.push(request); return requests.length === 1 ? old : json(page); } });
    const active = new AbortController();
    const activeResult = createAuditLogAPI(client).page({}, undefined, 50, active.signal).catch(error => error);
    active.abort();
    const obsolete = new AbortController();
    const obsoleteResult = createAuditLogAPI(client).page({ action: "audit.old-scope" }, undefined, 50, obsolete.signal).catch(error => error);
    obsolete.abort();
    const latest = createAuditLogAPI(client).page({ action: "audit.new-scope" }, undefined, 50, signal());
    try {
      expect(requests).toHaveLength(1);
      expect(await activeResult).toMatchObject({ name: "AbortError" });
      expect(await obsoleteResult).toMatchObject({ name: "AbortError" });
      const independent = createAuditLogAPI(createAPIClient({ fetch: async () => json(page) }));
      expect((await independent.page({}, undefined, 50, signal())).items).toHaveLength(1);
      expect(requests).toHaveLength(1);
    } finally { settle(json(page)); await Promise.all([activeResult, obsoleteResult, latest]); }
    expect(requests).toHaveLength(2);
    expect(new URL(requests[1].url).searchParams.get("action")).toBe("audit.new-scope");
  });

  it("joins the old physical read, releases aborted callers immediately, and keeps only the latest pending read", async () => {
    const requests: Request[] = [];
    let settle!: (response: Response) => void;
    const old = new Promise<Response>(resolve => { settle = resolve; });
    const api = createAuditLogAPI(createAPIClient({ fetch: async request => {
      requests.push(request); return requests.length === 1 ? old : json(page);
    } }));
    const first = new AbortController(); const second = new AbortController();
    const firstResult = api.page({ action: "audit.first" }, undefined, 50, first.signal);
    const firstRejected = expect(firstResult).rejects.toMatchObject({ name: "AbortError" });
    first.abort();
    const secondResult = api.page({ action: "audit.obsolete" }, undefined, 50, second.signal);
    const secondRejected = expect(secondResult).rejects.toMatchObject({ name: "AbortError" });
    second.abort();
    const latest = api.page({ action: "audit.latest" }, undefined, 50, signal());
    try {
      expect(requests).toHaveLength(1);
      await firstRejected;
      await secondRejected;
      expect(requests).toHaveLength(1);
    } finally { settle(json(page)); await firstRejected; await secondRejected; await latest; }
    await latest;
    expect(requests).toHaveLength(2);
    expect(new URL(requests[1].url).searchParams.get("action")).toBe("audit.latest");
  });

  it("replaces waiting requests without a growing queue and never starts an invalidated waiting scope", async () => {
    const requests: Request[] = [];
    let settle!: (response: Response) => void;
    const old = new Promise<Response>(resolve => { settle = resolve; });
    const api = createAuditLogAPI(createAPIClient({ fetch: async request => { requests.push(request); return old; } }));
    const active = new AbortController();
    const results: Promise<unknown>[] = [api.page({}, undefined, 50, active.signal).catch(error => error)];
    active.abort();
    for (let index = 0; index < 30; index++) results.push(api.page({ action: `audit.queued-${index}` }, undefined, 50, signal()).catch(error => error));
    const invalidated = new AbortController();
    results.push(api.page({ action: "audit.old-scope" }, undefined, 50, invalidated.signal).catch(error => error));
    invalidated.abort();
    try {
      const errors = await Promise.all(results);
      for (const error of errors) expect(error).toMatchObject({ name: "AbortError" });
    } finally { settle(json(page)); }
    await new Promise(resolve => setTimeout(resolve, 0));
    expect(requests).toHaveLength(1);
  });

  it.each(["createSSOConnection", "deleteSSOConnection", "testSSOConnection", "createSCIMConnection", "deleteSCIMConnection"])("preserves retained %s and every filter on first and continuation GET", async operation => {
    const requests: Request[] = [];
    const api = createAuditLogAPI(createAPIClient({ getCSRFToken: () => "not-needed-for-GET", getExpectedScope: () => `${id}/${id}/${id}`, fetch: async request => { requests.push(request); return json(page); } }));
    const filters = { actor_id: id, action: `identity_provider.${operation}`, outcome: "denied" as const, from: "0001-01-01T00:00:00Z", to: "2026-09-12T00:00:00.123456Z" };
    await api.page(filters, undefined, 50, signal());
    const result = await api.page(filters, "opaque-cursor", 50, signal());
    expect(result.items[0].action).toBe("identity_provider.createSSOConnection");
    expect(result.items[0].occurred_at).toBe("2026-09-12T00:00:00.123456Z");
    for (const [index, request] of requests.entries()) {
      expect(request.method).toBe("GET");
      expect(request.credentials).toBe("same-origin");
      expect(request.headers.get("X-Zasp-Expected-Scope")).toBe(`${id}/${id}/${id}`);
      expect(request.headers.has("X-CSRF-Token")).toBe(false);
      expect(new URL(request.url).pathname).toBe("/api/v1/audit-events");
      expect(Object.fromEntries(new URL(request.url).searchParams)).toEqual({ limit: "50", actor_id: id, action: `identity_provider.${operation}`, outcome: "denied", from: "0001-01-01T00:00:00.000000Z", to: "2026-09-12T00:00:00.123456Z", ...(index === 1 ? { cursor: "opaque-cursor" } : {}) });
    }
  });

  it("admits a legal large-key page exactly at one MiB with the existing decoder", async () => {
    const basic = JSON.stringify({ ...page, items: [{ ...event, metadata: { "": "" } }] });
    const body = JSON.stringify({ ...page, items: [{ ...event, metadata: { ["k".repeat(1_048_576 - basic.length)]: "" } }] });
    expect(new TextEncoder().encode(body)).toHaveLength(1_048_576);
    const api = createAuditLogAPI(createAPIClient({ fetch: async () => new Response(body, { headers: { "Content-Type": "application/json" } }) }));
    expect((await api.page({}, undefined, 50, signal())).items).toHaveLength(1);
  });

  it.each([true, false])("rejects a response one UTF-8 byte over one MiB (declared=%s)", async declared => {
    const body = new TextEncoder().encode(`{"padding":"${"é".repeat(524_281)} "}`);
    expect(body).toHaveLength(1_048_577);
    const api = createAuditLogAPI(createAPIClient({ fetch: async () => new Response(body, { headers: { "Content-Type": "application/json", ...(declared ? { "Content-Length": "1048577" } : {}) } }) }));
    await expect(api.page({}, undefined, 50, signal())).rejects.toMatchObject({ kind: "response_too_large" });
  });

  it.each([
    { ...page, extra: true },
    { ...page, items: [{ ...event, metadata: { key: null } }] },
    { ...page, items: [{ ...event, actor_id: "invalid" }] },
    { items: [], page_info: { has_more: true, next_cursor: "next" } },
    { ...page, page_info: { has_more: true, next_cursor: "same" } },
    { ...page, page_info: { has_more: false, next_cursor: "not-null" } },
  ])("rejects invalid page contracts %#", async body => {
    const api = createAuditLogAPI(createAPIClient({ fetch: async () => json(body) }));
    await expect(api.page({}, "same", 50, signal())).rejects.toMatchObject({ kind: "invalid_response" });
  });

  it("rejects a decoded page exceeding the requested row limit", async () => {
    const api = createAuditLogAPI(createAPIClient({ fetch: async () => json({ ...page, items: [event, event] }) }));
    await expect(api.page({}, undefined, 1, signal())).rejects.toMatchObject({ kind: "invalid_response" });
  });

  it.each([0, 101, 1.5])("refuses invalid page limit %s without a request", async limit => {
    const fetch = vi.fn(async () => json(page));
    const api = createAuditLogAPI(createAPIClient({ fetch }));
    await expect(api.page({}, undefined, limit, signal())).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("propagates caller abort through the generated transport and refuses late success", async () => {
    let request!: Request; let resolve!: (response: Response) => void;
    const response = new Promise<Response>(done => { resolve = done; });
    const api = createAuditLogAPI(createAPIClient({ fetch: async value => { request = value; return response; } }));
    const controller = new AbortController();
    const result = api.page({}, undefined, 50, controller.signal);
    const rejected = expect(result).rejects.toMatchObject({ name: "AbortError" });
    controller.abort();
    expect(request.signal.aborted).toBe(true);
    resolve(json(page));
    await rejected;
  });

  it.each([
    [401, "authentication_required", "Sign in required", false],
    [409, "scope_stale", "Session scope changed; rebootstrap required", true],
  ] as const)("preserves the shared %s invalidation callback", async (status, code, message, retryable) => {
    const expired = vi.fn(); const stale = vi.fn();
    const api = createAuditLogAPI(createAPIClient({ onSessionExpired: expired, onScopeStale: stale, fetch: async () => json({ code, message, retryable, correlation_id: id }, status) }));
    await expect(api.page({}, undefined, 50, signal())).rejects.toMatchObject({ status, correlationID: id });
    expect(expired).toHaveBeenCalledTimes(status === 401 ? 1 : 0);
    expect(stale).toHaveBeenCalledTimes(status === 409 ? 1 : 0);
  });
});

describe("exact audit filter normalization", () => {
  it("pads UTC fractions without losing a one-microsecond interval", () => {
    expect(normalizeAuditFilters({ from: "2024-02-29T23:59:59.1Z", to: "2024-02-29T23:59:59.100001Z" })).toEqual({ from: "2024-02-29T23:59:59.100000Z", to: "2024-02-29T23:59:59.100001Z" });
    expect(normalizeAuditFilters({})).toEqual({});
  });
  it.each([
    { from: "0000-01-01T00:00:00Z" }, { from: "1900-02-29T00:00:00Z" },
    { from: "2026-04-31T00:00:00Z" }, { from: "2026-01-01T24:00:00Z" },
    { from: "2026-01-01T00:00:60Z" }, { from: "2026-01-01T00:00:00.0000001Z" },
    { from: "2026-01-01T00:00:00+00:00" }, { from: "2026-01-01T00:00:00Z\n" },
    { from: "2026-01-01T00:00:00.123456Z", to: "2026-01-01T00:00:00.123455Z" },
    { from: "2026-01-01T00:00:00Z", to: "2026-01-01T00:00:00.000000Z" },
    { actor_id: `${id}\n` }, { action: "identity_provider.CreateSSOConnection" },
    { action: "policy.update\n" }, { action: "policy.*" }, { action: "a".repeat(128) },
    { action: "" }, { actor_id: "" }, { from: "" },
  ])("refuses invalid or lossy filters before any request %#", async filters => {
    const fetch = vi.fn(async () => json(page));
    const api = createAuditLogAPI(createAPIClient({ fetch }));
    await expect(api.page(filters, undefined, 50, signal())).rejects.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});

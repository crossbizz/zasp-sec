import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { act, renderHook } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../apps/web/api/client";
import { APIProvider, useAPI } from "./APIProvider";
const near = readFileSync("apps/web/api/testdata/audit-export-near-bound.json", "utf8");
const small = readFileSync("apps/web/api/testdata/audit-export-read.json", "utf8");
const page = JSON.parse(small);
const scope = [page.export.organization_id, page.export.workspace_id, page.export.environment_id].join("/");
const signal = () => new AbortController().signal;
const json = (body: string, headers: Record<string, string> = {}) => new Response(body, { headers: { "Content-Type": "application/json", ...headers } });
function setup(client?: ReturnType<typeof createAPIClient>) {
  const hook = renderHook(useAPI, { wrapper: ({ children }: { children: ReactNode }) => <APIProvider client={client}>{children}</APIProvider> });
  act(() => { hook.result.current.setRequestScope(scope); hook.result.current.setCSRFToken("c".repeat(32)); hook.result.current.setQueryScope(`principal/${scope}`); });
  return hook;
}
beforeEach(() => vi.stubGlobal("crypto", webcrypto));
afterEach(() => vi.unstubAllGlobals());

describe("APIProvider bounded export ownership", () => {
  it("accepts the real Go near-bound page privately while unrelated clients keep one MiB", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => json(near)));
    const { result } = setup();
    expect((await result.current.auditExports.read(page.export.id, undefined, signal())).export.status).toBe("ready");
    await expect(result.current.client.GET("/api/v1/audit-exports/{id}", { params: { path: { id: page.export.id } } })).rejects.toMatchObject({ kind: "response_too_large" });
  });
  it("accepts exactly 1064960 UTF8 bytes, including trailing JSON whitespace", async () => {
    const padded = near+" ".repeat(1064960-new TextEncoder().encode(near).byteLength);
    vi.stubGlobal("fetch", vi.fn(async () => json(padded, { "Content-Length": "1064960" })));
    const { result } = setup();
    expect((await result.current.auditExports.read(page.export.id, undefined, signal())).export.status).toBe("ready");
  });
  it.each(["declared", "streamed"])("refuses a %s body one byte over the export cap", async kind => {
    const body = `{"payload":"${"é".repeat(532473)}"}`;
    const bytes = new TextEncoder().encode(body);
    const oversized = new Uint8Array(1064961); oversized.fill(32); oversized.set(bytes.subarray(0, 1064961));
    vi.stubGlobal("fetch", vi.fn(async () => new Response(kind === "declared" ? "{}" : new ReadableStream({ start(c) { c.enqueue(oversized.subarray(0, 1064900)); c.enqueue(oversized.subarray(1064900)); c.close(); } }), { headers: { "Content-Type": "application/json", ...(kind === "declared" ? { "Content-Length": "1064961" } : {}) } })));
    const { result } = setup();
    await expect(result.current.auditExports.read(page.export.id, undefined, signal())).rejects.toMatchObject({ kind: "response_too_large" });
  });
  it("reuses supplied transport for both adapters without hidden fetch or changing its cap", async () => {
    const hidden = vi.fn(async () => { throw new Error("hidden fetch"); }); vi.stubGlobal("fetch", hidden);
    const client = createAPIClient({ fetch: async () => json(near) });
    const { result } = setup(client);
    expect(result.current.client).toBe(client);
    await expect(result.current.auditExports.read(page.export.id, undefined, signal())).rejects.toMatchObject({ kind: "response_too_large" });
    expect(hidden).not.toHaveBeenCalled();
  });
  it.each(["scope", "principal", "suspend", "clear"])("invalidates %s synchronously before a stale response can return", async kind => {
    let release!: () => void;
    vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(resolve => { release = () => resolve(json(small)); })));
    const { result } = setup();
    const read = result.current.auditExports.read(page.export.id, undefined, signal());
    const refused = expect(read).rejects.toMatchObject({ name: "AbortError" });
    act(() => {
      if (kind === "scope") result.current.setRequestScope(scope.replace("00000002", "00000022"));
      if (kind === "principal") result.current.setQueryScope(`other-principal/${scope}`);
      if (kind === "suspend") result.current.suspendQueryCache();
      if (kind === "clear") result.current.clearQueryCache();
      release();
    });
    await refused;
  });
  it.each([[401, "authentication_required", "Authentication required", false, "sessionExpiry"], [409, "scope_stale", "Session scope changed; rebootstrap required", true, "scopeStale"], [403, "fresh_auth_required", "Fresh authentication required", false, "freshAuthRequired"]] as const)("shares %s invalidation callbacks", async (status, code, message, retryable, field) => {
    const requests: Request[] = [];
    vi.stubGlobal("fetch", vi.fn(async (request: Request) => { requests.push(request); return Response.json({ code, message, retryable, correlation_id: page.export.audit_correlation_id }, { status }); }));
    const { result } = setup();
    await act(async () => { await expect(result.current.auditExports.create("audit_export_retained_key", signal())).rejects.toThrow(); });
    expect(result.current[field]).toBe(1);
    expect(requests[0].headers.get("X-CSRF-Token")).toBe("c".repeat(32));
    expect(requests[0].headers.get("X-Zasp-Expected-Scope")).toBe(scope);
  });
});

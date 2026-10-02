import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { createAPIClient } from "./client";
import { createAuditExportsAPI } from "./audit-exports";
const wire = readFileSync("apps/web/api/testdata/audit-export-read.json", "utf8");
const page = JSON.parse(wire);
const scope = [page.export.organization_id, page.export.workspace_id, page.export.environment_id].join("/");
const boundary = () => ({ generation: 0, scope, csrf: "c".repeat(32), signal: new AbortController().signal });
beforeEach(() => vi.stubGlobal("crypto", webcrypto));

describe("fixed generated export adapter", () => {
  it.each(["queued", "processing", "failed"])("refuses array-coerced %s status on both operations", async status => {
    const descriptor = { ...page.export, status: [status], event_count: null };
    for (const key of ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"]) delete descriptor[key];
    const client = createAPIClient({ fetch: async request => Response.json(request.method === "POST" ? descriptor : { export: descriptor, contents: null }, { status: request.method === "POST" ? 201 : 200 }) });
    const api = createAuditExportsAPI(client, boundary);
    const signal = new AbortController().signal;
    await expect.soft(api.create("audit_export_retained_key", signal)).rejects.toMatchObject({ kind: "invalid_response" });
    await expect.soft(api.read(page.export.id, undefined, signal)).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it.each(["capacity_exceeded", "invalid_source", "execution_failed"])("preserves string %s and refuses an array failure code on both operations", async failure_code => {
    const descriptor = { ...page.export, status: "failed", event_count: null, failure_code };
    for (const key of ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"]) delete descriptor[key];
    const client = createAPIClient({ fetch: async request => Response.json(request.method === "POST" ? descriptor : { export: descriptor, contents: null }, { status: request.method === "POST" ? 201 : 200 }) });
    const api = createAuditExportsAPI(client, boundary);
    const signal = new AbortController().signal;
    expect(await api.create("audit_export_retained_key", signal)).toEqual(descriptor);
    expect(await api.read(page.export.id, undefined, signal)).toEqual({ export: descriptor, contents: null });
    descriptor.failure_code = [failure_code];
    await expect.soft(api.create("audit_export_retained_key", signal)).rejects.toMatchObject({ kind: "invalid_response" });
    await expect.soft(api.read(page.export.id, undefined, signal)).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it.each(["succeeded", "failed", "denied"])("refuses an array %s outcome at the read boundary", async outcome => {
    const changed = JSON.parse(wire);
    changed.contents.chunk.events[0].outcome = [outcome];
    const client = createAPIClient({ fetch: async () => Response.json(changed) });
    await expect(createAuditExportsAPI(client, boundary).read(page.export.id, undefined, new AbortController().signal)).rejects.toMatchObject({ kind: "invalid_response" });
  });
  it("returns queued status without contents and preserves generic forbidden/unavailable errors", async () => {
    const descriptor = { ...page.export, status: "queued", event_count: null };
    for (const key of ["captured_at", "chunk_count", "chunk_bytes", "manifest_sha256"]) delete descriptor[key];
    const client = createAPIClient({ fetch: async () => Response.json({ export: descriptor, contents: null }) });
    expect(await createAuditExportsAPI(client, boundary).read(page.export.id, undefined, new AbortController().signal)).toEqual({ export: descriptor, contents: null });
    for (const [status, code] of [[403, "forbidden"], [503, "service_unavailable"]] as const) {
      const failed = createAPIClient({ fetch: async () => Response.json({ code, message: "Operation unavailable", retryable: status === 503, correlation_id: page.export.audit_correlation_id }, { status }) });
      await expect(createAuditExportsAPI(failed, boundary).read(page.export.id, undefined, new AbortController().signal)).rejects.toMatchObject({ status, product: { code } });
    }
  });
  it("sends exact create/read routes, empty body, retained key and opaque cursor", async () => {
    const requests: Request[] = [];
    const client = createAPIClient({ fetch: async request => { requests.push(request); return Response.json(request.method === "POST" ? page.export : page, { status: request.method === "POST" ? 201 : 200 }); } });
    const api = createAuditExportsAPI(client, boundary);
    const signal = new AbortController().signal;
    expect(await api.create("audit_export_retained_key", signal)).toEqual(page.export);
    expect(await api.read(page.export.id, undefined, signal)).toEqual(page);
    expect(await api.read(page.export.id, "opaque_AAAA", signal)).toEqual(page);
    expect(await requests[0].text()).toBe("{}");
    expect(requests[0].headers.get("Idempotency-Key")).toBe("audit_export_retained_key");
    expect(requests[0].headers.get("X-CSRF-Token")).toBe("c".repeat(32));
    expect(requests.every(r => r.headers.get("X-Zasp-Expected-Scope") === scope)).toBe(true);
    expect(requests.map(r => new URL(r.url).pathname+new URL(r.url).search)).toEqual(["/api/v1/audit-exports", `/api/v1/audit-exports/${page.export.id}`, `/api/v1/audit-exports/${page.export.id}?cursor=opaque_AAAA`]);
    expect(Object.keys(api).sort()).toEqual(["create", "read"]);
  });
  it("refuses invalid inputs and changed generation without trusting late success", async () => {
    let generation = 0;
    const client = createAPIClient({ fetch: async () => { generation++; return new Response(wire, { headers: { "Content-Type": "application/json" } }); } });
    const api = createAuditExportsAPI(client, () => ({ ...boundary(), generation }));
    const signal = new AbortController().signal;
    await expect(api.create("short", signal)).rejects.toThrow();
    await expect(api.read("foreign", undefined, signal)).rejects.toThrow();
    await expect(api.read(page.export.id, "x".repeat(1025), signal)).rejects.toThrow();
    await expect(api.read(page.export.id, undefined, signal)).rejects.toMatchObject({ name: "AbortError" });
  });
  it("rejects requested-id or organization mismatch and corruption", async () => {
    for (const mutate of [(v: typeof page) => { v.export.id = v.export.audit_correlation_id; }, (v: typeof page) => { v.contents.chunk.events[0].metadata["10"] = "TEN"; }]) {
      const changed = JSON.parse(wire); mutate(changed);
      const client = createAPIClient({ fetch: async () => Response.json(changed) });
      await expect(createAuditExportsAPI(client, boundary).read(page.export.id, undefined, new AbortController().signal)).rejects.toThrow();
    }
  });
});

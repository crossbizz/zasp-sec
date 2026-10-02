import { describe, expect, it } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { createSecurityAgentExportAPI } from "./export-api";

const run = "pid_20000002-0000-4000-8000-000000000002";
const step = "pid_20000003-0000-4000-8000-000000000003";
const status = { export_id: "pid_20000001-0000-4000-8000-000000000001", state: "pending", phase: "queued", failure_code: null, created_at: "2026-09-19T00:00:00Z", retrieval_expires_at: "2099-01-01T00:00:00Z", mapping_revision: "security-agent-run-evidence-v1", snapshot_at: null, cleanup_state: "retained", selection: [{ source_kind: "finding", source_id: "pid_20000004-0000-4000-8000-000000000004", source_version: 7, association_digest: `sha256:${"a".repeat(64)}` }], artifact: null };
describe("Security Agent export status", () => {
  it("pins expected scope and stops a revoked production boundary", async () => {
    const expectedScope = `${run}/${step}/${run}`;
    let current = true, calls = 0;
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async request => { calls++; expect(request.headers.get("X-Zasp-Expected-Scope")).toBe(expectedScope); return Response.json(status); } }), expectedScope, () => current);
    await api.status(run, step, new AbortController().signal, () => true);
    current = false;
    await expect(api.status(run, step, new AbortController().signal, () => true)).rejects.toThrow();
    await expect(api.download(run, step, "json", new AbortController().signal, () => true)).rejects.toThrow();
    expect(calls).toBe(1);
  });
  it("reads the exact run and step without losing frozen evidence versions", async () => {
    const seen: string[] = [];
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async request => {
      seen.push(new URL(request.url).pathname);
      return Response.json(status);
    } }));
    expect(await api.status(run, step, new AbortController().signal, () => true)).toEqual(status);
    expect(seen).toEqual([`/api/v1/security-agent-runs/${run}/steps/${step}/export`]);
  });
  it.each([
    { ...status, key: "private" }, { ...status, selection: [] }, { ...status, phase: "terminal" },
    { ...status, selection: [{ ...status.selection[0], source_version: 0 }] },
    { ...status, selection: [status.selection[0], status.selection[0]] },
    { ...status, selection: [{ ...status.selection[0], source_id: "foreign" }] },
    { ...status, artifact: { sha256: "a".repeat(64), size: 1, key: "private" } },
    { ...status, artifact: { sha256: "a".repeat(64), size: 8388609 } },
    { ...status, created_at: "2026-02-30T00:00:00Z" },
  ])("refuses malformed public status %#", async payload => {
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async () => Response.json(payload) }));
    await expect(api.status(run, step, new AbortController().signal, () => true)).rejects.toThrow();
  });
  it("discards a late status after scope changes", async () => {
    let current = true, calls = 0;
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async () => { calls++; current = false; return Response.json(status); } }));
    await expect(api.status(run, step, new AbortController().signal, () => current)).rejects.toThrow();
    expect(calls).toBe(1);
  });
});
function attachmentHeaders(format: "json" | "csv" | "human") {
  return { "Content-Type": format === "json" ? "application/json" : format === "csv" ? "text/csv" : "text/plain", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Disposition": `attachment; filename="agent-export-pid_20000001-0000-4000-8000-000000000001.${format === "human" ? "txt" : format}"` };
}
describe("Security Agent export download authority", () => {
  it.each(["json", "csv", "human"] as const)("returns original %s bytes using a body-only grant", async format => {
    const requests: Request[] = [];
    const api = createSecurityAgentExportAPI(createAPIClient({ getCSRFToken: () => "c".repeat(32), fetch: async request => {
      requests.push(request.clone() as Request);
      if (request.url.endsWith("download-grants")) return new Response(JSON.stringify({ token: "a".repeat(64), format, expires_at: "2099-01-01T00:00:00Z" }), { status: 201, headers: { "Content-Type": "application/json" } });
      return new Response("original stored bytes", { headers: attachmentHeaders(format) });
    } }));
    const blob = await api.download(run, step, format, new AbortController().signal, () => true);
    expect(await blob.text()).toBe("original stored bytes");
    expect(requests.map(r => new URL(r.url).pathname)).toEqual([`/api/v1/security-agent-runs/${run}/steps/${step}/export/download-grants`, `/api/v1/security-agent-runs/${run}/steps/${step}/export/download`]);
    expect(requests.every(r => r.method === "POST" && !r.url.includes("a".repeat(64)) && r.headers.get("X-CSRF-Token") === "c".repeat(32))).toBe(true);
    expect(await requests[0].json()).toEqual({ format });
    expect(await requests[1].json()).toEqual({ format, token: "a".repeat(64) });
  });
  it.each(["before", "grant", "bytes"])("rejects session/scope change at %s", async stage => {
    let current = stage !== "before", calls = 0;
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async () => {
      calls++;
      if (stage === "grant" || calls === 2) current = false;
      return calls === 1 ? new Response(JSON.stringify({ token: "a".repeat(64), format: "json", expires_at: "2099-01-01T00:00:00Z" }), { status: 201, headers: { "Content-Type": "application/json" } }) : new Response("private bytes", { headers: attachmentHeaders("json") });
    } }));
    await expect(api.download(run, step, "json", new AbortController().signal, () => current)).rejects.toThrow();
    expect(calls).toBe(stage === "before" ? 0 : stage === "grant" ? 1 : 2);
  });
  it.each(["expired", "wrong format", "malformed token", "revoked", "empty", "oversize", "filename", "media", "cache", "nosniff"])("refuses %s without returning artifact bytes", async mode => {
    let calls = 0;
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async () => {
      calls++;
      if (calls === 1) return new Response(JSON.stringify({ token: mode === "malformed token" ? "bad" : "a".repeat(64), format: mode === "wrong format" ? "csv" : "json", expires_at: mode === "expired" ? "2020-01-01T00:00:00Z" : "2099-01-01T00:00:00Z" }), { status: 201, headers: { "Content-Type": "application/json" } });
      if (mode === "revoked") return new Response(JSON.stringify({ code: "authorization_rejected", message: "Access denied", retryable: false, correlation_id: run }), { status: 403, headers: { "Content-Type": "application/json" } });
      const headers = attachmentHeaders("json");
      if (mode === "filename") headers["Content-Disposition"] = 'attachment; filename="../../private.json"';
      if (mode === "media") headers["Content-Type"] = "text/html";
      if (mode === "cache") headers["Cache-Control"] = "public";
      if (mode === "nosniff") headers["X-Content-Type-Options"] = "";
      return new Response(mode === "empty" ? "" : mode === "oversize" ? "x".repeat(4 * 1024 * 1024 + 1) : "stored bytes", { headers });
    } }));
    await expect(api.download(run, step, "json", new AbortController().signal, () => true)).rejects.toThrow();
    expect(calls).toBe(["expired", "wrong format", "malformed token"].includes(mode) ? 1 : 2);
  });
});

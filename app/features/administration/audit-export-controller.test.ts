import { readFileSync } from "node:fs";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuditExportController, type AuditExportAuthority } from "./audit-export-controller";
import type { AuditExport, AuditExportRead } from "../../../apps/web/api/generated";
import type { AuditExportsAPI } from "../../../apps/web/api/audit-exports";
import { APIProductError } from "../../../apps/web/api/client";
const read: AuditExportRead = JSON.parse(readFileSync("apps/web/api/testdata/audit-export-read.json", "utf8"));
const authority: AuditExportAuthority = { principalID: read.export.audit_correlation_id, organizationID: read.export.organization_id, workspaceID: read.export.workspace_id, environmentID: read.export.environment_id, generation: 1, fresh: true, permitted: true };
const queued: AuditExport = { id: read.export.id, organization_id: authority.organizationID, workspace_id: authority.workspaceID, environment_id: authority.environmentID, created_at: read.export.created_at, audit_correlation_id: authority.principalID, status: "queued", event_count: null };
const options = (api: AuditExportsAPI) => ({ api, authority, storage: sessionStorage, retrySession: async () => {} });
beforeEach(() => sessionStorage.clear());
afterEach(() => vi.useRealTimers());
it("retains the exact lost-POST key through reconstruction and never duplicates an active create", async () => {
  const keys: string[] = []; let release!: () => void;
  const api: AuditExportsAPI = { create: async key => { keys.push(key); await new Promise<void>(r => { release = r; }); throw new Error("response lost"); }, read: async () => read };
  const c = new AuditExportController(options(api));
  const pending = c.create(); await Promise.resolve(); void c.create(); await Promise.resolve();
  expect(keys).toHaveLength(1); release(); await pending;
  expect(c.snapshot().phase).toBe("ambiguous"); await c.dispose();
  const resumed = new AuditExportController(options({ ...api, create: async key => { keys.push(key); return queued; } }));
  await resumed.create(); expect(keys).toHaveLength(2); expect(keys[1]).toBe(keys[0]);
  expect(resumed.snapshot().descriptor?.id).toBe(queued.id); await resumed.dispose();
});
it.each(["queued", "processing", "ready", "failed"] as const)("handles a 201 %s without treating readiness as saved", async status => {
  const descriptor: AuditExport = status === "ready" ? read.export : status === "failed" ? { ...queued, status, failure_code: "capacity_exceeded" } : { ...queued, status };
  const c = new AuditExportController(options({ create: async () => descriptor, read: async () => read }));
  await c.create(); expect(c.snapshot().phase).toBe(status); expect(c.snapshot().phase).not.toBe("saved"); await c.dispose();
});
it("pauses polling by two foreground minutes, with one pending GET at a time", async () => {
  vi.useFakeTimers(); let reads = 0;
  const c = new AuditExportController(options({ create: async () => queued, read: async () => { reads++; return { export: queued, contents: null }; } }));
  await c.create(); await vi.advanceTimersByTimeAsync(121000);
  expect(c.snapshot().phase).toBe("paused"); const count = reads; expect(count).toBeGreaterThan(1); expect(count).toBeLessThan(20);
  await vi.advanceTimersByTimeAsync(600000); expect(reads).toBe(count); await c.dispose();
});
it.each([false, true])("joins old physical operations before a real queued successor (disposed=%s)", async disposeSuccessor => {
  let release!: () => void; let signal!: AbortSignal; const keys: string[] = [];
  const api: AuditExportsAPI = { create: async (key, s) => { keys.push(key); if (keys.length === 1) { signal = s; await new Promise<void>(r => { release = r; }); } return queued; }, read: async () => read };
  const old = new AuditExportController(options(api)); const creating = old.create(); await Promise.resolve();
  const disposed = old.dispose(); const next = new AuditExportController(options(api)); const successor = next.create();
  const disposedNext = disposeSuccessor ? next.dispose() : Promise.resolve();
  try {
    await Promise.resolve(); expect(signal.aborted).toBe(true); expect(keys).toHaveLength(1);
    release(); await creating; await disposed; await successor; await disposedNext;
    expect(keys).toHaveLength(disposeSuccessor ? 1 : 2);
    if (!disposeSuccessor) { expect(keys[1]).toBe(keys[0]); expect(next.snapshot().descriptor?.id).toBe(queued.id); }
    else expect(next.snapshot().descriptor).toBeNull();
    expect(old.snapshot().descriptor).toBeNull();
  } finally { release(); await creating; await disposed; await successor; await disposedNext; await next.dispose(); }
});
it.each([false, true])("rechecks freshness after acquiring the create lane without changing the pending key (newJob=%s)", async newJob => {
  let release!: () => void; const keys: string[] = [];
  const api: AuditExportsAPI = { create: async key => { keys.push(key); if (keys.length === 1) await new Promise<void>(r => { release = r; }); return queued; }, read: async () => read };
  const old = new AuditExportController(options(api)); const creating = old.create(); await Promise.resolve();
  const stored = sessionStorage.getItem(sessionStorage.key(0)!);
  const disposed = old.dispose(); const next = new AuditExportController(options(api)); const successor = next.create(newJob);
  next.setFresh(false);
  try {
    await Promise.resolve(); expect(keys).toHaveLength(1);
    release(); await creating; await disposed; await successor;
    expect(keys).toHaveLength(1);
    expect(sessionStorage.getItem(sessionStorage.key(0)!)).toBe(stored);
    expect(next.snapshot().resume?.key).toBe(keys[0]);
    expect(next.snapshot().descriptor).toBeNull();
    next.setFresh(true); await next.create();
    expect(keys).toEqual([keys[0], keys[0]]); expect(next.snapshot().descriptor?.id).toBe(queued.id);
  } finally { release(); await creating; await disposed; await successor; await next.dispose(); }
});
it("generic forbidden reboots session but never calls that stale authentication itself", async () => {
  let bootstraps = 0;
  const c = new AuditExportController({ ...options({ create: async () => { throw new APIProductError(403, { code: "forbidden", message: "forbidden", retryable: false, correlation_id: authority.principalID }); }, read: async () => read }), retrySession: async () => { bootstraps++; } });
  await c.create(); expect(bootstraps).toBe(1); expect(c.snapshot().phase).toBe("ambiguous"); expect(c.snapshot().message).not.toMatch(/fresh authentication required/i); await c.dispose();
});
it("does not add GETs while a poll response is unresolved, and joins Stop", async () => {
  vi.useFakeTimers(); let calls = 0; let release!: () => void;
  const c = new AuditExportController(options({ create: async () => queued, read: async () => { calls++; await new Promise<void>(r => { release = r; }); return { export: queued, contents: null }; } }));
  await c.create(); await vi.advanceTimersByTimeAsync(2000); await vi.advanceTimersByTimeAsync(300000); expect(calls).toBe(1);
  let stopped = false; const pending = c.stop().then(() => { stopped = true; }); await Promise.resolve(); expect(stopped).toBe(false);
  release(); await pending; expect(c.snapshot().phase).toBe("incomplete"); await vi.advanceTimersByTimeAsync(300000); expect(calls).toBe(1); await c.dispose();
});
it.each([401, 404, 503])("handles %s without losing a known job or exposing foreign existence", async status => {
  const c = new AuditExportController(options({ create: async () => readyDescriptor(), read: async () => { throw new APIProductError(status, { code: "request_failed", message: "private provider details", retryable: status === 503, correlation_id: authority.principalID }); } }));
  await c.create(); await c.check(); expect(c.snapshot().resume?.exportID).toBe(read.export.id);
  expect(c.snapshot().message).not.toContain("private provider details");
  if (status === 401) expect(c.snapshot().descriptor).toBeNull();
  if (status === 404) expect(c.snapshot().message).toContain("not available to this session");
  await c.dispose();
});
function readyDescriptor() { return read.export; }
it("never replays another principal and blocks creation without current permission or freshness", async () => {
  let calls = 0; const api = { create: async () => { calls++; return queued; }, read: async () => read };
  const first = new AuditExportController(options(api)); await first.create(); await first.dispose();
  for (const changed of [{ principalID: "pid_10000009-0000-4000-8000-000000000009" }, { permitted: false }, { fresh: false }]) {
    const c = new AuditExportController({ ...options(api), authority: { ...authority, ...changed } });
    if ("principalID" in changed) expect(c.snapshot().resume).toBeNull(); else { await c.create(); expect(calls).toBe(1); }
    await c.dispose();
  }
});

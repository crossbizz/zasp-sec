import { readFileSync } from "node:fs";
import { webcrypto } from "node:crypto";
import { StrictMode } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AuditExportPanel, AuditExportSaveNotice } from "./AuditExportPanel";
import type { ExportDirectory } from "./audit-export-save";
import { createAuditExportsAPI } from "../../../apps/web/api/audit-exports";
import { createAPIClient } from "../../../apps/web/api/client";
import type { AuditExport } from "../../../apps/web/api/generated";
const ready: AuditExport = JSON.parse(readFileSync("apps/web/api/testdata/audit-export-read.json", "utf8")).export;
const authority = { principalID: ready.audit_correlation_id, organizationID: ready.organization_id, workspaceID: ready.workspace_id, environmentID: ready.environment_id, generation: 1, fresh: true, permitted: true };
const queued: AuditExport = { id: ready.id, organization_id: ready.organization_id, workspace_id: ready.workspace_id, environment_id: ready.environment_id, created_at: ready.created_at, audit_correlation_id: ready.audit_correlation_id, status: "queued", event_count: null };
const base = { authority, retrySession: async () => {}, reauthenticate: () => {} };
beforeEach(() => sessionStorage.clear());
afterEach(() => vi.unstubAllGlobals());
it("keeps the export action usable after React's effect cleanup and setup replay", async () => {
  render(<StrictMode><AuditExportPanel {...base} api={{ create: async () => queued, read: async () => { throw new Error("unused"); } }} /></StrictMode>);
  await userEvent.click(screen.getByRole("button", { name: "Create export" }));
  expect(await screen.findByText(/Queued/)).toBeVisible();
});
it("uses the accepted generated adapter for exact organization POST despite list-independent rendering", async () => {
  const requests: Request[] = [];
  const client = createAPIClient({ fetch: async request => { requests.push(request); return new Response(JSON.stringify(queued), { status: 201, headers: { "Content-Type": "application/json" } }); } });
  const controller = new AbortController();
  const api = createAuditExportsAPI(client, () => ({ generation: 1, scope: `${authority.organizationID}/${authority.workspaceID}/${authority.environmentID}`, csrf: "c".repeat(32), signal: controller.signal }));
  const view = render(<AuditExportPanel {...base} api={api} />);
  await userEvent.click(screen.getByRole("button", { name: "Create export" }));
  expect(await screen.findByText(/Queued/)).toBeVisible(); expect(requests).toHaveLength(1);
  expect(await requests[0].json()).toEqual({}); expect(new URL(requests[0].url).pathname).toBe("/api/v1/audit-exports");
  expect(requests[0].headers.get("Idempotency-Key")).toMatch(/^audit_export_/);
  expect(requests[0].headers.get("X-CSRF-Token")).toBe("c".repeat(32));
  expect(requests[0].headers.get("X-Zasp-Expected-Scope")).toBe(`${authority.organizationID}/${authority.workspaceID}/${authority.environmentID}`); view.unmount();
});
it("requires reauthentication for POST but lets an authorized ready export be checked without freshness", async () => {
  let reauthenticated = false;
  const view = render(<AuditExportPanel {...base} api={{ create: async () => ready, read: async () => { throw new Error("unused"); } }} />);
  await userEvent.click(screen.getByRole("button", { name: "Create export" })); await screen.findByText(/Captured/); view.unmount();
  render(<AuditExportPanel {...base} authority={{ ...authority, fresh: false }} reauthenticate={() => { reauthenticated = true; }} api={{ create: async () => ready, read: async () => { throw new Error("unused"); } }} />);
  await userEvent.click(screen.getByRole("button", { name: "Reauthenticate" })); expect(reauthenticated).toBe(true);
  expect(screen.getByRole("button", { name: "Check status" })).toBeEnabled();
});
it("shows supported-save limits and keeps failed jobs explicit with their correlation ID", async () => {
  const view = render(<AuditExportPanel {...base} api={{ create: async () => ready, read: async () => { throw new Error("unused"); } }} />);
  await userEvent.click(screen.getByRole("button", { name: "Create export" }));
  expect(await screen.findByRole("button", { name: "Save complete export" })).toBeDisabled();
  expect(screen.getByText(/secure browser with directory access/)).toBeVisible(); view.unmount(); sessionStorage.clear();
  render(<AuditExportPanel {...base} api={{ create: async () => ({ ...queued, status: "failed", failure_code: "invalid_source" }), read: async () => { throw new Error("unused"); } }} />);
  await userEvent.click(screen.getByRole("button", { name: "Create export" }));
  expect(await screen.findByText(/source records could not be verified/i)).toBeVisible(); expect(screen.getByText(new RegExp(ready.audit_correlation_id))).toBeVisible();
});
it("clears a previous principal's descriptor and aborts a pending read on identity change", async () => {
  let resolve!: (value: never) => void; let signal!: AbortSignal;
  const api = { create: async () => ready, read: async (_id: string, _cursor: string | undefined, s: AbortSignal) => { signal = s; return new Promise<never>(r => { resolve = r; }); } };
  const view = render(<AuditExportPanel {...base} api={api} />);
  await userEvent.click(screen.getByRole("button", { name: "Create export" })); await screen.findByText(/Captured/);
  await userEvent.click(screen.getByRole("button", { name: "Check status" })); await waitFor(() => expect(signal).toBeDefined());
  view.rerender(<AuditExportPanel {...base} authority={{ ...authority, principalID: "pid_10000009-0000-4000-8000-000000000009" }} api={api} />);
  expect(signal.aborted).toBe(true); expect(screen.queryByText(/Captured/)).not.toBeInTheDocument();
  await act(async () => resolve(undefined as never));
});
it("invokes the directory picker in the save click and preserves actual final-close success after unmount", async () => {
  vi.stubGlobal("crypto", webcrypto); vi.stubGlobal("isSecureContext", true);
  let release!: () => void; let finalizing!: () => void;
  const atClose = new Promise<void>(resolve => { finalizing = resolve; });
  const held = new Promise<void>(resolve => { release = resolve; });
  let releaseChunk!: () => void; let chunkStarted!: () => void; let readSignal!: AbortSignal;
  const chunkHeld = new Promise<void>(resolve => { releaseChunk = resolve; });
  const atChunk = new Promise<void>(resolve => { chunkStarted = resolve; });
  const files = new Map<string, Uint8Array>(); const existing = new Set<string>(); let picks = 0;
  const directory: ExportDirectory = {
    async getDirectoryHandle(_name: string, options?: { create?: boolean }): Promise<ExportDirectory> { if (!options?.create) throw new DOMException("missing", "NotFoundError"); return directory; },
    async *keys() { yield* existing; },
    async getFileHandle(name: string, options?: { create?: boolean }) {
      if (!options?.create) throw new DOMException("missing", "NotFoundError"); existing.add(name);
      return { async createWritable() { let bytes!: Uint8Array; return {
        async write(value: Uint8Array) { bytes = value; },
        async close() { if (name === "manifest.json") { finalizing(); await held; } else { chunkStarted(); await chunkHeld; } files.set(name, bytes); },
        async abort() {},
      }; } };
    },
  };
  vi.stubGlobal("showDirectoryPicker", () => { picks++; return Promise.resolve(directory); });
  const api = { create: async () => ready, read: async (_id: string, _cursor: string | undefined, signal: AbortSignal) => { readSignal = signal; return JSON.parse(readFileSync("apps/web/api/testdata/audit-export-read.json", "utf8")); } };
  const view = render(<AuditExportPanel {...base} api={api} />);
  await userEvent.click(screen.getByRole("button", { name: "Create export" }));
  await userEvent.click(screen.getByRole("button", { name: "Save complete export" }));
  await act(async () => atChunk);
  view.rerender(<AuditExportPanel {...base} authority={{ ...authority, fresh: false }} api={api} />);
  const abortedOnFreshnessExpiry = readSignal.aborted;
  await act(async () => releaseChunk());
  expect(abortedOnFreshnessExpiry).toBe(false);
  await act(async () => atClose); expect(picks).toBe(1); expect(files.has("manifest.json")).toBe(false);
  view.unmount(); render(<AuditExportSaveNotice />);
  await act(async () => release());
  expect(await screen.findByText(/All chunks and the final manifest closed successfully/)).toBeVisible(); expect(files.has("manifest.json")).toBe(true);
  expect(screen.queryByText(new RegExp(ready.id))).not.toBeInTheDocument();
});

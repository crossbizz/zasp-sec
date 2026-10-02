import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAPIClient } from "../../../apps/web/api/client";
import { createSecurityAgentExportAPI } from "./export-api";
import { ExportPanel } from "./ExportPanel";
const runID = "pid_20000002-0000-4000-8000-000000000002", stepID = "pid_20000003-0000-4000-8000-000000000003";
const pending = { export_id: "pid_20000001-0000-4000-8000-000000000001", state: "pending", phase: "queued", failure_code: null, created_at: "2026-09-19T00:00:00Z", retrieval_expires_at: "2099-01-01T00:00:00Z", mapping_revision: "security-agent-run-evidence-v1", snapshot_at: null, cleanup_state: "retained", selection: [{ source_kind: "finding", source_id: "pid_20000004-0000-4000-8000-000000000004", source_version: 7, association_digest: `sha256:${"a".repeat(64)}` }], artifact: null };
afterEach(() => vi.restoreAllMocks());
describe("Agent export panel", () => {
  it.each(["grant", "bytes"] as const)("discards late %s after the panel is replaced or its authority changes", async phase => {
    for (const boundary of ["unmount", "run", "disabled", "scope"] as const) {
      let currentScope = true;
      let resolveResponse!: (value: Response) => void;
      const delayed = new Promise<Response>(resolve => { resolveResponse = resolve; });
      let delayedSignal: AbortSignal | undefined;
      let downloadRequests = 0;
      const objectURL = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:stale-export");
      const save = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => undefined);
      const otherRun = "pid_20000009-0000-4000-8000-000000000009";
      const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async request => {
        if (request.url.includes(otherRun)) return Response.json(pending);
        if (request.url.endsWith("download-grants")) {
          if (phase === "grant") { delayedSignal = request.signal; return delayed; }
          return Response.json({ token: "a".repeat(64), format: "json", expires_at: "2099-01-01T00:00:00Z" }, { status: 201 });
        }
        if (request.url.endsWith("/download")) { downloadRequests++; delayedSignal = request.signal; return delayed; }
        return Response.json({ ...pending, state: "completed", phase: "terminal" });
      } }), undefined, () => currentScope);
      // Observe completion without replacing the real adapter or response decoder.
      const originalDownload = api.download;
      let completion: Promise<Blob> | undefined;
      api.download = (...args) => { completion = originalDownload(...args); return completion; };
      const panel = render(<ExportPanel api={api} runID={runID} stepID={stepID} />);
      await userEvent.click(await screen.findByRole("button", { name: "Download JSON" }));
      await waitFor(() => expect(delayedSignal).toBeDefined());
      if (boundary === "unmount") panel.unmount();
      else if (boundary === "run") panel.rerender(<ExportPanel api={api} runID={otherRun} stepID={stepID} />);
      else if (boundary === "disabled") panel.rerender(<ExportPanel api={api} runID={runID} stepID={stepID} disabled />);
      else currentScope = false;
      if (boundary !== "scope") expect(delayedSignal!.aborted).toBe(true);
      await act(async () => {
        resolveResponse(phase === "grant"
          ? Response.json({ token: "a".repeat(64), format: "json", expires_at: "2099-01-01T00:00:00Z" }, { status: 201 })
          : new Response("original bytes", { headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Disposition": `attachment; filename="agent-export-${pending.export_id}.json"` } }));
        await expect(completion).rejects.toBeDefined();
      });
      expect(objectURL).not.toHaveBeenCalled();
      expect(save).not.toHaveBeenCalled();
      expect(downloadRequests).toBe(phase === "grant" ? 0 : 1);
      expect(screen.queryByRole("button", { name: "Download JSON" })).not.toBeInTheDocument();
      if (boundary === "run") expect(await screen.findByText("Export queued")).toBeInTheDocument();
      panel.unmount();
      vi.restoreAllMocks();
    }
  });
  it("shows frozen selection and pending state without download controls", async () => {
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async () => Response.json(pending) }));
    render(<ExportPanel api={api} runID={runID} stepID={stepID} />);
    expect(await screen.findByText("Export queued")).toBeInTheDocument();
    expect(screen.getByText(/finding.*version 7/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Download JSON" })).not.toBeInTheDocument();
  });
  it.each(["expired", "failed"])("does not offer downloads for %s exports", async mode => {
    const value = { ...pending, state: mode === "failed" ? "failed" : "completed", phase: "terminal", failure_code: mode === "failed" ? "export_cancelled" : null, retrieval_expires_at: mode === "expired" ? "2020-01-01T00:00:00Z" : pending.retrieval_expires_at };
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async () => Response.json(value) }));
    render(<ExportPanel api={api} runID={runID} stepID={stepID} />);
    expect(await screen.findByText(mode === "expired" ? "Export expired" : "Export failed: export_cancelled")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Download JSON" })).not.toBeInTheDocument();
  });
  it("hands verified bytes to the browser without claiming a saved file", async () => {
    let saved = "";
    vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:controlled");
    vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => undefined);
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function(this: HTMLAnchorElement) { saved = this.download; });
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async request => {
      if (request.url.endsWith("download-grants")) return Response.json({ token: "a".repeat(64), format: "json", expires_at: "2099-01-01T00:00:00Z" }, { status: 201 });
      if (request.url.endsWith("/download")) return new Response("original bytes", { headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Content-Disposition": `attachment; filename="agent-export-${pending.export_id}.json"` } });
      return Response.json({ ...pending, state: "completed", phase: "terminal", artifact: { sha256: "a".repeat(64), size: 14 } });
    } }));
    render(<ExportPanel api={api} runID={runID} stepID={stepID} />);
    await userEvent.click(await screen.findByRole("button", { name: "Download JSON" }));
    expect(await screen.findByText("Download handed to your browser. Check its downloads for the saved file.")).toBeInTheDocument();
    expect(saved).toBe(`agent-export-${pending.export_id}.json`);
  });
  it("clears completed status when refresh loses permission", async () => {
    let reads = 0;
    const api = createSecurityAgentExportAPI(createAPIClient({ fetch: async () => ++reads === 1 ? Response.json({ ...pending, state: "completed", phase: "terminal" }) : Response.json({ code: "authorization_rejected", message: "Denied", correlation_id: runID, retryable: false }, { status: 403 }) }));
    render(<ExportPanel api={api} runID={runID} stepID={stepID} />);
    await screen.findByRole("button", { name: "Download JSON" });
    await userEvent.click(screen.getByRole("button", { name: "Refresh export status" }));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Download JSON" })).not.toBeInTheDocument());
    expect(screen.getByRole("alert")).toHaveTextContent("Access denied");
  });
});

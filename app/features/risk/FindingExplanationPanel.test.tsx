import { useEffect, type ReactNode } from "react";
import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { FindingExplanationPanel } from "./FindingExplanationPanel";
import type { FindingExplanationAPI, FindingExplanationIntent, FindingExplanationResponse } from "./finding-explanation-api";

const findingID = "pid_20000001-0000-4000-8000-000000000001";
function result(intent: FindingExplanationIntent, state: FindingExplanationResponse["state"] = "complete", text?: string): FindingExplanationResponse {
  return { request_id: "pid_20000001-0000-4000-8000-000000000002", state, result_retained: false, source: { finding_id: intent.finding_id, finding_version: intent.finding_version }, sent_fields: ["rule", "severity", "evidence_count"], ...(text ? { explanation: text } : {}) };
}
function Scope({ scope, children }: { scope: string; children: ReactNode }) {
  const { setQueryScope, clearQueryCache } = useAPI();
  useEffect(() => setQueryScope(scope), [scope, setQueryScope]);
  return <>{children}<button onClick={clearQueryCache}>Invalidate session generation</button></>;
}
function fixture(api: FindingExplanationAPI, scope = "tenant-a", id = findingID, version = '"7"') {
  return <APIProvider><Scope scope={scope}><FindingExplanationPanel findingID={id} version={version} api={api} /><button>Canonical finding action</button></Scope></APIProvider>;
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }

describe("optional finding explanation", () => {
  it("requires an explicit action, renders transient plain text and keeps the finding actions usable", async () => {
    const text = '<a href="https://foreign.invalid">untrusted suggestion</a>';
    const createAIExplanation = vi.fn(async (intent: FindingExplanationIntent) => result(intent, "complete", text));
    const local = vi.spyOn(Storage.prototype, "setItem");
    render(fixture({ createAIExplanation }));
    const generate = await screen.findByRole("button", { name: "Generate explanation" });
    expect(createAIExplanation).not.toHaveBeenCalled(); expect(screen.getByText(/Only rule, severity and evidence count/)).toBeVisible();
    expect(screen.getByRole("link", { name: "Review current evidence" })).toHaveAttribute("href", `#finding-evidence-${findingID}`);
    await userEvent.click(generate); expect(await screen.findByText(text)).toBeVisible();
    expect(screen.queryByRole("link", { name: "untrusted suggestion" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Canonical finding action" })).toBeEnabled();
    expect(local).not.toHaveBeenCalled(); local.mockRestore();
    const first = createAIExplanation.mock.calls[0][0]; expect(Object.keys(first).sort()).toEqual(["finding_id", "finding_version", "idempotency_key"]);
    await userEvent.click(screen.getByRole("button", { name: "Generate another explanation" }));
    await waitFor(() => expect(createAIExplanation).toHaveBeenCalledTimes(2));
    expect(createAIExplanation.mock.calls[1][0].idempotency_key).not.toBe(first.idempotency_key);
  });
  it("does not turn a double click into a new paid generation when the first result returns immediately", async () => {
    const api = { createAIExplanation: vi.fn(async (intent: FindingExplanationIntent) => result(intent, "complete", "Immediate result")) };
    render(fixture(api)); await userEvent.dblClick(await screen.findByRole("button", { name: "Generate explanation" }));
    expect(await screen.findByText("Immediate result")).toBeVisible(); expect(api.createAIExplanation).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Generate another explanation" }));
    await waitFor(() => expect(api.createAIExplanation).toHaveBeenCalledTimes(2));
  });
  it("retains the same intent for pending, unknown and ambiguous transport outcomes without automatic resend", async () => {
    let calls = 0;
    const createAIExplanation = vi.fn(async (intent: FindingExplanationIntent) => {
      calls++; if (calls === 1) return result(intent, "reserved"); if (calls === 2) return result(intent, "unknown"); if (calls === 3) throw Error("private provider token"); return result(intent);
    });
    render(fixture({ createAIExplanation })); await userEvent.click(await screen.findByRole("button", { name: "Generate explanation" }));
    expect(await screen.findByText(/Explanation request pending/)).toBeVisible(); expect(createAIExplanation).toHaveBeenCalledTimes(1);
    await userEvent.click(screen.getByRole("button", { name: "Check existing request" })); expect(await screen.findByText(/provider outcome is unknown/)).toBeVisible();
    await userEvent.click(screen.getByRole("button", { name: "Check existing request" })); expect(await screen.findByRole("alert")).not.toHaveTextContent("private provider token");
    expect(screen.queryByRole("button", { name: "Generate another explanation" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Check existing request" })); expect(await screen.findByText(/was not retained and cannot be replayed/)).toBeVisible();
    const keys = createAIExplanation.mock.calls.map(([intent]) => intent.idempotency_key); expect(new Set(keys).size).toBe(1);
  });
  it.each(["scope", "finding", "version", "generation", "unmount"] as const)("aborts and clears a pending request on %s change and ignores its late response", async change => {
    const pending = deferred<FindingExplanationResponse>(); let intent!: FindingExplanationIntent, signal!: AbortSignal;
    const api = { createAIExplanation: vi.fn((next: FindingExplanationIntent, abort: AbortSignal) => { intent = next; signal = abort; return pending.promise; }) };
    const view = render(fixture(api)); await userEvent.click(await screen.findByRole("button", { name: "Generate explanation" }));
    expect(screen.getByRole("button", { name: "Check existing request" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Canonical finding action" })).toBeEnabled();
    if (change === "unmount") view.unmount();
    else if (change === "generation") await userEvent.click(screen.getByRole("button", { name: "Invalidate session generation" }));
    else view.rerender(fixture(api, change === "scope" ? "tenant-b" : "tenant-a", change === "finding" ? "pid_20000001-0000-4000-8000-000000000099" : findingID, change === "version" ? '"8"' : '"7"'));
    expect(signal.aborted).toBe(true);
    await act(async () => { pending.resolve(result(intent, "complete", "OLD PRIVATE OUTPUT")); await pending.promise; });
    expect(screen.queryByText("OLD PRIVATE OUTPUT")).not.toBeInTheDocument(); expect(api.createAIExplanation).toHaveBeenCalledTimes(1);
  });
  it("clears existing output on version changes, refuses invalid versions and rejects source-mismatched responses", async () => {
    const api = { createAIExplanation: vi.fn(async (intent: FindingExplanationIntent) => result(intent, "complete", "Temporary guidance")) };
    const view = render(fixture(api)); await userEvent.click(await screen.findByRole("button", { name: "Generate explanation" })); expect(await screen.findByText("Temporary guidance")).toBeVisible();
    view.rerender(fixture(api, "tenant-a", findingID, 'W/"7"')); expect(screen.queryByText("Temporary guidance")).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: "Generate explanation" })).not.toBeInTheDocument();
    view.rerender(fixture({ createAIExplanation: async intent => ({ ...result(intent, "complete", "FOREIGN OUTPUT"), source: { finding_id: findingID, finding_version: 99 } }) }));
    await userEvent.click(await screen.findByRole("button", { name: "Generate explanation" })); expect(await screen.findByRole("alert")).toHaveTextContent("Explanation unavailable"); expect(screen.queryByText("FOREIGN OUTPUT")).not.toBeInTheDocument();
  });
});

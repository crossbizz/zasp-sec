import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { APIProductError, APITransportError } from "../../../apps/web/api/client";
import type { SingleTestRecoveryView } from "../../../apps/web/api/single-test-recovery";
import { useRetainedWorkflowMutation } from "../workflows/useRetainedWorkflowMutation";
import type { RecoveryIntent } from "./recovery-intent";
import { SingleTestRecovery, type SingleTestRecoveryAPI } from "./SingleTestRecovery";

const runID = "pid_78000003-0000-4000-8000-000000000003";
const initial: SingleTestRecoveryView = { run_id: runID, parent_version: 7, status: "not_requested", reason: "not_requested",
  request_identity: { definition_version: 3, input_digest: "a".repeat(64) }, command: null, accepted_at: null, completion: null };
function Harness({ api, version = 7, canManage = true }: { api: SingleTestRecoveryAPI; version?: number; canManage?: boolean }) {
  const mutation = useRetainedWorkflowMutation<RecoveryIntent>(`recovery:${runID}`, canManage);
  return <SingleTestRecovery api={api} runID={runID} version={version} canManage={canManage} blocked={mutation.isUnresolved} mutation={mutation} onSettled={async () => {}} />;
}
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }

describe("connected cleanup recovery", () => {
  it.each([403, 409])("requires a new authority read after definitive POST %s", async status => {
    const fresh = deferred<SingleTestRecoveryView>(); let reads = 0;
    const api: SingleTestRecoveryAPI = {
      get: async () => ++reads === 1 ? initial : fresh.promise,
      request: async () => { throw new APIProductError(status, { code: status === 403 ? "permission_denied" : "conflict", message: "rejected", correlation_id: runID, retryable: false }); },
    };
    render(<Harness api={api} />);
    await userEvent.click(await screen.findByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: "Request cleanup recovery" }));
    await waitFor(() => expect(reads).toBe(2));
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry retained cleanup request" })).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Loading");
    await act(async () => fresh.resolve(initial));
    expect(await screen.findByRole("checkbox")).not.toBeChecked();
    expect(screen.getByRole("button", { name: "Request cleanup recovery" })).toBeDisabled();
  });

  it("discards an old API response after scope transport changes", async () => {
    const old = deferred<SingleTestRecoveryView>(); const next = deferred<SingleTestRecoveryView>();
    let oldSignal: AbortSignal | undefined;
    const request: SingleTestRecoveryAPI["request"] = async () => { throw new Error("unexpected mutation"); };
    const oldAPI: SingleTestRecoveryAPI = { get: async (_id, signal) => { oldSignal = signal; return old.promise; }, request };
    const nextAPI: SingleTestRecoveryAPI = { get: async () => next.promise, request };
    const view = render(<Harness api={oldAPI} />);
    view.rerender(<Harness api={nextAPI} />);
    expect(oldSignal?.aborted).toBe(true);
    await act(async () => old.resolve(initial));
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Loading");
    await act(async () => next.resolve(initial));
    expect(await screen.findByRole("checkbox")).toBeInTheDocument();
  });

  it("replays the frozen request after parent version advancement and prevents replay after permission loss", async () => {
    let current = initial;
    const sent: Array<{ intent: RecoveryIntent; key: string }> = [];
    const api: SingleTestRecoveryAPI = { get: async () => current, request: async (intent, attempt) => {
      sent.push({ intent, key: attempt.idempotencyKey }); throw new APITransportError("timeout", "lost response");
    } };
    const view = render(<Harness api={api} />);
    await userEvent.click(await screen.findByRole("checkbox"));
    await userEvent.click(screen.getByRole("button", { name: "Request cleanup recovery" }));
    await screen.findByRole("button", { name: "Retry retained cleanup request" });
    current = { ...initial, parent_version: 8 };
    view.rerender(<Harness api={api} version={8} />);
    await userEvent.click(await screen.findByRole("button", { name: "Retry retained cleanup request" }));
    await waitFor(() => expect(sent).toHaveLength(2));
    expect(sent[1]).toEqual(sent[0]);
    expect(sent[1].intent.version).toBe(7);
    expect(sent[1].intent.body).toEqual({ definition_version: 3, input_digest: "a".repeat(64), diagnostic: "history_unavailable", stop_original: true });
    expect(sent[0].key).toMatch(/^wf_/);
    view.rerender(<Harness api={api} version={8} canManage={false} />);
    expect(screen.queryByRole("button", { name: "Retry retained cleanup request" })).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(/outcome is unknown/i);
    expect(sent).toHaveLength(2);
  });

  it("hides previous evidence while a new parent version is loading", async () => {
    const next = deferred<SingleTestRecoveryView>(); let calls = 0;
    const api: SingleTestRecoveryAPI = { get: async () => ++calls === 1 ? initial : next.promise,
      request: async () => { throw new Error("unexpected mutation"); } };
    const view = render(<Harness api={api} />);
    await screen.findByRole("checkbox");
    view.rerender(<Harness api={api} version={8} />);
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
    await act(async () => next.resolve(initial));
    expect(screen.getByRole("status")).toHaveTextContent("Refresh");
    expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  });
});

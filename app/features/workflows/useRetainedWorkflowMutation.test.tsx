import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { APITransportError } from "../../../apps/web/api/client";
import type { WorkflowMutationReceipt } from "../../../apps/web/api/generated";
import type { WorkflowRecoveryAPI } from "./api";
import { WorkflowMutationProvider, useRetainedWorkflowMutation } from "./useRetainedWorkflowMutation";

type Intent = { name: string };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((next, fail) => { resolve = next; reject = fail; });
  return { promise, resolve, reject };
}

function Probe({ operation, name, send }: { operation: string; name: string; send: (intent: Intent) => Promise<string> }) {
  const mutation = useRetainedWorkflowMutation<Intent>(operation);
  return <section aria-label={name}>
    <output>{`${mutation.isUnresolved ? "unresolved" : "settled"}:${mutation.canRetry ? "retry" : "locked"}`}</output>
    <button disabled={mutation.isUnresolved} onClick={() => void mutation.execute({ name }, send).catch(() => undefined)}>Start {name}</button>
    {mutation.canRetry && <button onClick={() => void mutation.retry().catch(() => undefined)}>Retry {name}</button>}
  </section>;
}

describe("observable scope-owned workflow mutation registry", () => {
  it("notifies every mounted consumer for in-flight, ambiguous, retried, and cleared transitions", async () => {
    const user = userEvent.setup();
    const request = deferred<string>();
    const send = vi.fn(() => request.promise);
    render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a">
      <Probe operation="policies" name="policy" send={send} />
      <Probe operation="integrations" name="integration" send={async () => "competing"} />
    </WorkflowMutationProvider>);

    await user.click(screen.getByRole("button", { name: "Start policy" }));
    expect(screen.getByRole("region", { name: "policy" })).toHaveTextContent("unresolved:locked");
    expect(screen.getByRole("region", { name: "integration" })).toHaveTextContent("unresolved:locked");
    expect(screen.getByRole("button", { name: "Start integration" })).toBeDisabled();

    await act(async () => request.reject(new APITransportError("timeout", "committed response lost")));
    expect(screen.getByRole("region", { name: "policy" })).toHaveTextContent("unresolved:retry");
    expect(screen.getByRole("region", { name: "integration" })).toHaveTextContent("unresolved:locked");

    send.mockResolvedValueOnce("recovered");
    await user.click(screen.getByRole("button", { name: "Retry policy" }));
    expect(screen.getByRole("region", { name: "policy" })).toHaveTextContent("settled:locked");
    expect(screen.getByRole("region", { name: "integration" })).toHaveTextContent("settled:locked");
  });

  it("keeps an in-flight operation locked across an owner unmount and transitions its remount when it settles", async () => {
    const user = userEvent.setup();
    const request = deferred<string>();
    function Surface() {
      const [mounted, setMounted] = useState(true);
      return <><button onClick={() => setMounted((value) => !value)}>Toggle owner</button>{mounted && <Probe operation="security-agent:create" name="agent" send={() => request.promise} />}</>;
    }
    render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><Surface /></WorkflowMutationProvider>);
    await user.click(screen.getByRole("button", { name: "Start agent" }));
    await user.click(screen.getByRole("button", { name: "Toggle owner" }));
    await user.click(screen.getByRole("button", { name: "Toggle owner" }));
    expect(screen.getByRole("region", { name: "agent" })).toHaveTextContent("unresolved:locked");
    await act(async () => request.reject(new APITransportError("timeout", "lost")));
    expect(screen.getByRole("region", { name: "agent" })).toHaveTextContent("unresolved:retry");
  });

  it("isolates A, B, and A again while retaining A's exact unresolved state", async () => {
    const user = userEvent.setup();
    const request = deferred<string>();
    const view = render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><Probe operation="policies" name="policy" send={() => request.promise} /></WorkflowMutationProvider>);
    await user.click(screen.getByRole("button", { name: "Start policy" }));
    view.rerender(<WorkflowMutationProvider scopeKey="organization/workspace-b/environment-b"><Probe operation="policies" name="policy" send={async () => "B"} /></WorkflowMutationProvider>);
    expect(screen.getByRole("region", { name: "policy" })).toHaveTextContent("settled:locked");
    await act(async () => request.reject(new APITransportError("timeout", "lost in A")));
    expect(screen.getByRole("region", { name: "policy" })).toHaveTextContent("settled:locked");
    view.rerender(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><Probe operation="policies" name="policy" send={async () => "A retry"} /></WorkflowMutationProvider>);
    expect(screen.getByRole("region", { name: "policy" })).toHaveTextContent("unresolved:retry");
  });

  it("installs a beforeunload warning only while the active scope is unresolved", async () => {
    const user = userEvent.setup();
    const request = deferred<string>();
    render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><Probe operation="policies" name="policy" send={() => request.promise} /></WorkflowMutationProvider>);
    const before = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(before);
    expect(before.defaultPrevented).toBe(false);
    await user.click(screen.getByRole("button", { name: "Start policy" }));
    const during = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(during);
    expect(during.defaultPrevented).toBe(true);
    await act(async () => request.resolve("done"));
    const after = new Event("beforeunload", { cancelable: true });
    window.dispatchEvent(after);
    expect(after.defaultPrevented).toBe(false);
  });

  it("keeps a server-recovered result globally locked through acknowledgement failure and retry", async () => {
    const user = userEvent.setup();
    const receipt: WorkflowMutationReceipt = {
      id: "pid_11111111-1111-4111-8111-111111111111",
      operation: "createSecurityAgent",
      idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
      intent: { kind: "create" },
      result: { id: "pid_22222222-2222-4222-8222-222222222222" },
      resource_kind: "security_agent",
      resource_id: "pid_22222222-2222-4222-8222-222222222222",
      resource_version: 1,
      audit_id: "pid_33333333-3333-4333-8333-333333333333",
      correlation_id: "pid_44444444-4444-4444-8444-444444444444",
      created_at: "2026-08-18T12:00:00Z",
      expires_at: "2026-08-25T12:00:00Z",
    };
    const nextReceipt: WorkflowMutationReceipt = {
      ...receipt,
      id: "pid_55555555-5555-4555-8555-555555555555",
      operation: "createIntegration",
      resource_kind: "integration",
      resource_id: "pid_66666666-6666-4666-8666-666666666666",
    };
    const acknowledgeReceipt = vi.fn()
      .mockRejectedValueOnce(new APITransportError("timeout", "Acknowledgement response was lost"))
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined);
    const listReceipts = vi.fn()
      .mockResolvedValueOnce([receipt])
      .mockResolvedValueOnce([nextReceipt])
      .mockResolvedValueOnce([]);
    const recovery: WorkflowRecoveryAPI = { listReceipts, acknowledgeReceipt };
    render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a" recovery={recovery}>
      <Probe operation="security-agent:create" name="agent" send={async () => "new agent"} />
    </WorkflowMutationProvider>);

    expect(await screen.findByRole("heading", { name: "Recover committed operations" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Start agent" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Acknowledgement response was lost");
    expect(screen.getByRole("button", { name: "Start agent" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    expect(await screen.findByText(new RegExp(nextReceipt.resource_id))).toBeVisible();
    expect(screen.getByRole("button", { name: "Start agent" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Recover committed operations" })).not.toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Start agent" })).toBeEnabled();
    expect(listReceipts).toHaveBeenCalledTimes(3);
  });
});

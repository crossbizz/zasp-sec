import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { APIProductError, APITransportError } from "../../../apps/web/api/client";
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

function Probe({ operation, name, send }: { operation: string; name: string; send: (intent: Intent) => Promise<unknown> }) {
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
    const receipt = receiptFixture("pid_11111111-1111-4111-8111-111111111111");
    const nextReceipt: WorkflowMutationReceipt = {
      ...receipt,
      id: "pid_55555555-5555-4555-8555-555555555555",
      resource_id: "policy-later-second",
      intent: { body: { ...receipt.result, id: "policy-later-second", name: "Second policy" }, expected_version: 0, resource_id: "" },
      result: { ...receipt.result, id: "policy-later-second", name: "Second policy" },
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

  it("re-lists the captured scope after automatic acknowledgement and renders a later committed receipt", async () => {
    const user = userEvent.setup();
    const ownID = "pid_77777777-7777-4777-8777-777777777777";
    const laterReceipt = receiptFixture("pid_88888888-8888-4888-8888-888888888888");
    const listReceipts = vi.fn().mockResolvedValueOnce([]).mockResolvedValueOnce([laterReceipt]);
    const acknowledgeReceipt = vi.fn().mockResolvedValue(undefined);
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts, acknowledgeReceipt }}>
      <Probe operation="policies" name="policy" send={async () => ({ receiptID: ownID })} />
    </WorkflowMutationProvider>);

    await waitFor(() => expect(listReceipts).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Start policy" }));
    expect(await screen.findByText(new RegExp(laterReceipt.resource_id))).toBeVisible();
    expect(acknowledgeReceipt).toHaveBeenCalledWith(ownID);
    expect(listReceipts).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: "Start policy" })).toBeDisabled();
  });

  it("treats an expired acknowledgement as reconciled only after an empty exact-scope relist", async () => {
    const user = userEvent.setup();
    const ownID = "pid_77777777-7777-4777-8777-777777777777";
    const listReceipts = vi.fn().mockResolvedValueOnce([]).mockResolvedValueOnce([]);
    const acknowledgeReceipt = vi.fn().mockRejectedValue(new APIProductError(404, {
      code: "not_found", message: "Resource not found", retryable: false,
      correlation_id: "pid_99999999-9999-4999-8999-999999999999",
    }));
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts, acknowledgeReceipt }}>
      <Probe operation="policies" name="policy" send={async () => ({ receiptID: ownID })} />
    </WorkflowMutationProvider>);

    await waitFor(() => expect(listReceipts).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Start policy" }));
    await waitFor(() => expect(listReceipts).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("button", { name: "Start policy" })).toBeEnabled();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("unlocks an expired listed receipt only after its not-found acknowledgement relists empty", async () => {
    const user = userEvent.setup();
    const expired = receiptFixture("pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    const listReceipts = vi.fn().mockResolvedValueOnce([expired]).mockResolvedValueOnce([]);
    const acknowledgeReceipt = vi.fn().mockRejectedValue(new APIProductError(404, {
      code: "not_found", message: "Resource not found", retryable: false,
      correlation_id: "pid_99999999-9999-4999-8999-999999999999",
    }));
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts, acknowledgeReceipt }}>
      <Probe operation="policies" name="policy" send={async () => "unused"} />
    </WorkflowMutationProvider>);

    await screen.findByRole("heading", { name: "Recover committed operations" });
    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Recover committed operations" })).not.toBeInTheDocument());
    expect(listReceipts).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("button", { name: "Start policy" })).toBeEnabled();
  });

  it("renders allowlisted frozen intent and committed result details without configuration values or raw JSON", async () => {
    const integration = {
      id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "generic-webhook", name: "Webhook",
      configuration: { destination_url: "https://secret.invalid", signing_secret_reference: "secret_ref_1234" },
      status: "configured", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z",
    };
    const receipt = {
      ...receiptFixture("pid_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), operation: "createIntegration",
      intent: { body: { connector_key: integration.connector_key, name: integration.name, configuration: integration.configuration }, expected_version: 0, resource_id: "" },
      result: integration, resource_kind: "integration", resource_id: integration.id,
    } as WorkflowMutationReceipt;
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts: async () => [receipt], acknowledgeReceipt: vi.fn() }}>
      <Probe operation="integrations" name="integration" send={async () => "unused"} />
    </WorkflowMutationProvider>);

    await screen.findByRole("heading", { name: "Frozen request" });
    expect(screen.getByRole("heading", { name: "Committed result" })).toBeVisible();
    expect(screen.getAllByText("destination_url, signing_secret_reference")).toHaveLength(2);
    expect(screen.queryByText("https://secret.invalid")).not.toBeInTheDocument();
    expect(screen.queryByText("secret_ref_1234")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Mutation recovery" })).not.toHaveTextContent(/[{}\"]/);
  });

  it("keeps a forced A to B scope drift locked while captured-scope acknowledgement and relist finish", async () => {
    const user = userEvent.setup();
    const acknowledgement = deferred<void>();
    const scopeBList = deferred<readonly WorkflowMutationReceipt[]>();
    const listA = vi.fn().mockResolvedValueOnce([]).mockResolvedValueOnce([]);
    const recoveryA: WorkflowRecoveryAPI = { listReceipts: listA, acknowledgeReceipt: vi.fn(() => acknowledgement.promise) };
    const recoveryB: WorkflowRecoveryAPI = { listReceipts: vi.fn(() => scopeBList.promise), acknowledgeReceipt: vi.fn() };
    const view = render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={recoveryA}>
      <Probe operation="policies" name="policy" send={async () => ({ receiptID: "pid_77777777-7777-4777-8777-777777777777" })} />
    </WorkflowMutationProvider>);
    await waitFor(() => expect(listA).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Start policy" }));
    await waitFor(() => expect(recoveryA.acknowledgeReceipt).toHaveBeenCalledTimes(1));

    view.rerender(<WorkflowMutationProvider scopeKey="principal/organization/workspace-b/environment-b" recovery={recoveryB}>
      <Probe operation="policies" name="policy" send={async () => "scope B mutation"} />
    </WorkflowMutationProvider>);
    expect(screen.getByRole("button", { name: "Start policy" })).toBeDisabled();
    await act(async () => acknowledgement.resolve());
    await waitFor(() => expect(listA).toHaveBeenCalledTimes(2));
    expect(screen.getByRole("button", { name: "Start policy" })).toBeDisabled();
    await act(async () => scopeBList.resolve([]));
  });
});

function receiptFixture(id: string): WorkflowMutationReceipt {
  const policy = { id: "policy-later", name: "Later policy", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "write" }], action: "monitor", rollout: "draft", failure_mode: "open" } as const;
  return {
    id,
    operation: "createPolicy",
    idempotency_key: "wf_11111111-1111-4111-8111-111111111111",
    intent: { body: policy, expected_version: 0, resource_id: "" },
    result: policy,
    resource_kind: "policy",
    resource_id: "policy-later",
    resource_version: 1,
    audit_id: "pid_33333333-3333-4333-8333-333333333333",
    correlation_id: "pid_44444444-4444-4444-8444-444444444444",
    created_at: "2026-08-18T12:00:00Z",
    expires_at: "2026-08-25T12:00:00Z",
  };
}

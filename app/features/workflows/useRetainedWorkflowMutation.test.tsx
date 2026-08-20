import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";

import { APIProductError, APITransportError } from "../../../apps/web/api/client";
import type { Integration, WorkflowMutationReceipt } from "../../../apps/web/api/generated";
import { IntegrationRevocationPending, type WorkflowReceipt, type WorkflowRecoveryAPI } from "./api";
import { WorkflowMutationProvider, useRetainedWorkflowMutation } from "./useRetainedWorkflowMutation";

type Intent = { name: string };
const authoritativeRefetch = async () => undefined;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: unknown) => void;
  const promise = new Promise<T>((next, fail) => { resolve = next; reject = fail; });
  return { promise, resolve, reject };
}

function Probe({ operation, name, send, enabled = true, exposeRetry = false }: { operation: string; name: string; send: (intent: Intent) => Promise<unknown>; enabled?: boolean; exposeRetry?: boolean }) {
  const mutation = useRetainedWorkflowMutation<Intent>(operation, enabled);
  return <section aria-label={name}>
    <output>{`${mutation.isUnresolved ? "unresolved" : "settled"}:${mutation.canRetry ? "retry" : "locked"}`}</output>
    <button disabled={mutation.isUnresolved} onClick={() => void mutation.execute({ name }, send).catch(() => undefined)}>Start {name}</button>
    {mutation.canRetry && <button onClick={() => void mutation.retry().catch(() => undefined)}>Retry {name}</button>}
    {exposeRetry && <button onClick={() => void mutation.retry().catch(() => undefined)}>Force retry {name}</button>}
  </section>;
}

describe("observable scope-owned workflow mutation registry", () => {
	it("transport-blocks a known pending retry until its scope-owned deadline survives owner remount", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(new Date("2026-08-19T00:00:00Z"));
		const receipt: WorkflowReceipt<Integration> = {
			value: { id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "github", name: "GitHub", configuration: { authorization_mode: "github_app" }, status: "revoking", created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z" },
			version: '"2"', auditID: "pid_30000001-0000-4000-8000-000000000001", receiptID: "pid_30000002-0000-4000-8000-000000000002",
		};
		const send = vi.fn()
			.mockRejectedValueOnce(new IntegrationRevocationPending(receipt, 2))
			.mockResolvedValueOnce("deleted");
		const surface = (mounted: boolean) => <WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a">{mounted ? <Probe operation="integrations" name="integration" send={send} exposeRetry /> : <p>Other route</p>}</WorkflowMutationProvider>;
		const view = render(surface(true));

		await act(async () => { screen.getByRole("button", { name: "Start integration" }).click(); });
		expect(send).toHaveBeenCalledTimes(1);
		view.rerender(surface(false));
		view.rerender(surface(true));
		await act(async () => { screen.getByRole("button", { name: "Force retry integration" }).click(); });
		expect(send).toHaveBeenCalledTimes(1);
		await act(async () => { await vi.advanceTimersByTimeAsync(1_999); screen.getByRole("button", { name: "Force retry integration" }).click(); });
		expect(send).toHaveBeenCalledTimes(1);
		await act(async () => { await vi.advanceTimersByTimeAsync(1); screen.getByRole("button", { name: "Force retry integration" }).click(); });
		expect(send).toHaveBeenCalledTimes(2);
		vi.useRealTimers();
	});

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
	const nextReceipt = {
      ...receipt,
      id: "pid_55555555-5555-4555-8555-555555555555",
      resource_id: "policy-later-second",
      intent: { body: { ...receipt.result, id: "policy-later-second", name: "Second policy" }, expected_version: 0, resource_id: "" },
      result: { ...receipt.result, id: "policy-later-second", name: "Second policy" },
	} as WorkflowMutationReceipt;
    const acknowledgeReceipt = vi.fn()
      .mockRejectedValueOnce(new APITransportError("timeout", "Acknowledgement response was lost"))
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined);
    const listReceipts = vi.fn()
      .mockResolvedValueOnce([receipt])
      .mockResolvedValueOnce([nextReceipt])
      .mockResolvedValueOnce([]);
    const recovery: WorkflowRecoveryAPI = { listReceipts, acknowledgeReceipt };
    render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a" recovery={recovery} reconcileReceipt={authoritativeRefetch}>
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

  it("refetches the authoritative resource before ACK and preserves the receipt across refetch failure and scope changes", async () => {
    const user = userEvent.setup();
    const receipt = receiptFixture("pid_11111111-1111-4111-8111-111111111111");
    const refetch = deferred<void>();
    const reconcileReceipt = vi.fn(() => refetch.promise);
    const acknowledgeReceipt = vi.fn().mockResolvedValue(undefined);
    const listA = vi.fn().mockResolvedValueOnce([receipt]).mockResolvedValueOnce([receipt]).mockResolvedValueOnce([]);
    const listB = vi.fn().mockResolvedValue([]);
    const recoveryA: WorkflowRecoveryAPI = { listReceipts: listA, acknowledgeReceipt };
    const recoveryB: WorkflowRecoveryAPI = { listReceipts: listB, acknowledgeReceipt: vi.fn() };
    const view = render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={recoveryA} reconcileReceipt={reconcileReceipt}>
      <Probe operation="policies" name="policy" send={async () => "unused"} />
    </WorkflowMutationProvider>);

    await screen.findByRole("heading", { name: "Recover committed operations" });
    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    expect(reconcileReceipt).toHaveBeenCalledWith(receipt, expect.any(AbortSignal));
    expect(acknowledgeReceipt).not.toHaveBeenCalled();

    view.rerender(<WorkflowMutationProvider scopeKey="principal/organization/workspace-b/environment-b" recovery={recoveryB} reconcileReceipt={async () => undefined}>
      <Probe operation="policies" name="policy" send={async () => "scope B"} />
    </WorkflowMutationProvider>);
    await act(async () => refetch.reject(new APITransportError("timeout", "Authoritative resource refetch failed")));
    expect(acknowledgeReceipt).not.toHaveBeenCalled();

    view.rerender(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={recoveryA} reconcileReceipt={async () => undefined}>
      <Probe operation="policies" name="policy" send={async () => "scope A"} />
    </WorkflowMutationProvider>);
    expect(await screen.findByRole("alert")).toHaveTextContent("Authoritative resource refetch failed");
    expect(screen.getByRole("heading", { name: "Recover committed operations" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    await waitFor(() => expect(acknowledgeReceipt).toHaveBeenCalledWith(receipt.id));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Recover committed operations" })).not.toBeInTheDocument());
    expect(reconcileReceipt.mock.invocationCallOrder[0]).toBeLessThan(acknowledgeReceipt.mock.invocationCallOrder[0]);
  });

  it("keeps a reloaded revoking integration receipt locked until terminal reconciliation", async () => {
    const user = userEvent.setup();
    const integration = {
      id: "pid_20000001-0000-4000-8000-000000000001", connector_key: "github", name: "GitHub",
      configuration: { authorization_mode: "github_app" }, status: "revoking",
      created_at: "2026-08-19T00:00:00Z", updated_at: "2026-08-19T00:01:00Z",
    };
    const receipt = {
      ...receiptFixture("pid_11111111-1111-4111-8111-111111111111"),
      operation: "deleteIntegration", resource_kind: "integration", resource_id: integration.id, resource_version: 2,
      intent: { body: {}, expected_version: 1, resource_id: integration.id }, result: integration,
    } as WorkflowMutationReceipt;
    const listReceipts = vi.fn().mockResolvedValueOnce([receipt]).mockResolvedValueOnce([]);
    const acknowledgeReceipt = vi.fn().mockResolvedValue(undefined);
    const reconcileReceipt = vi.fn()
      .mockRejectedValueOnce(new APITransportError("invalid_response", "Authoritative integration is still revoking"))
      .mockResolvedValueOnce(undefined);

    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts, acknowledgeReceipt }} reconcileReceipt={reconcileReceipt}>
      <Probe operation="integrations" name="integration" send={async () => "unused"} />
    </WorkflowMutationProvider>);

    await screen.findByRole("heading", { name: "Recover committed operations" });
    expect(screen.getByText("revoking")).toBeVisible();
    expect(screen.getByRole("button", { name: "Start integration" })).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Authoritative integration is still revoking");
    expect(acknowledgeReceipt).not.toHaveBeenCalled();
    expect(screen.queryByText(/Integration deleted/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Acknowledge recovered result" }));
    await waitFor(() => expect(screen.queryByRole("heading", { name: "Recover committed operations" })).not.toBeInTheDocument());
    expect(acknowledgeReceipt).toHaveBeenCalledWith(receipt.id);
    expect(screen.getByRole("button", { name: "Start integration" })).toBeEnabled();
  });

  it("retains an ambiguous attempt but blocks retry transport after current authorization is lost", async () => {
    const user = userEvent.setup();
    const send = vi.fn().mockRejectedValueOnce(new APITransportError("timeout", "response lost")).mockResolvedValueOnce("must not send");
    const view = render(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a">
      <Probe operation="finding:update" name="finding" send={send} exposeRetry />
    </WorkflowMutationProvider>);
    await user.click(screen.getByRole("button", { name: "Start finding" }));
    await waitFor(() => expect(screen.getByRole("region", { name: "finding" })).toHaveTextContent("unresolved:retry"));

    view.rerender(<WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a">
      <Probe operation="finding:update" name="finding" send={send} enabled={false} exposeRetry />
    </WorkflowMutationProvider>);
    expect(screen.getByRole("region", { name: "finding" })).toHaveTextContent("unresolved:locked");
    expect(screen.queryByRole("button", { name: "Retry finding" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Force retry finding" }));
    expect(send).toHaveBeenCalledTimes(1);
  });

  it("re-lists the captured scope after automatic acknowledgement and renders a later committed receipt", async () => {
    const user = userEvent.setup();
    const ownID = "pid_77777777-7777-4777-8777-777777777777";
    const ownReceipt = receiptFixture(ownID);
    const laterReceipt = receiptFixture("pid_88888888-8888-4888-8888-888888888888");
    const listReceipts = vi.fn().mockResolvedValueOnce([]).mockResolvedValueOnce([ownReceipt, laterReceipt]).mockResolvedValueOnce([laterReceipt]);
    const acknowledgeReceipt = vi.fn().mockResolvedValue(undefined);
    const reconcileReceipt = vi.fn(authoritativeRefetch);
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts, acknowledgeReceipt }} reconcileReceipt={reconcileReceipt}>
      <Probe operation="policies" name="policy" send={async () => ({ receiptID: ownID })} />
    </WorkflowMutationProvider>);

    await waitFor(() => expect(listReceipts).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Start policy" }));
    expect(await screen.findByText(new RegExp(laterReceipt.resource_id))).toBeVisible();
    expect(reconcileReceipt).toHaveBeenCalledWith(ownReceipt, expect.any(AbortSignal));
    expect(acknowledgeReceipt).toHaveBeenCalledWith(ownID);
    expect(reconcileReceipt.mock.invocationCallOrder[0]).toBeLessThan(acknowledgeReceipt.mock.invocationCallOrder[0]);
    expect(listReceipts).toHaveBeenCalledTimes(3);
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
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts, acknowledgeReceipt }} reconcileReceipt={authoritativeRefetch}>
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
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts, acknowledgeReceipt }} reconcileReceipt={authoritativeRefetch}>
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
    render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={{ listReceipts: async () => [receipt], acknowledgeReceipt: vi.fn() }} reconcileReceipt={authoritativeRefetch}>
      <Probe operation="integrations" name="integration" send={async () => "unused"} />
    </WorkflowMutationProvider>);

    await screen.findByRole("heading", { name: "Frozen request" });
    expect(screen.getByRole("heading", { name: "Committed result" })).toBeVisible();
    expect(screen.getAllByText("destination_url, signing_secret_reference")).toHaveLength(2);
    expect(screen.queryByText("https://secret.invalid")).not.toBeInTheDocument();
    expect(screen.queryByText("secret_ref_1234")).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Mutation recovery" })).not.toHaveTextContent(/[{}"]/);
  });

  it("keeps a forced A to B scope drift locked while captured-scope acknowledgement and relist finish", async () => {
    const user = userEvent.setup();
    const acknowledgement = deferred<void>();
    const scopeBList = deferred<readonly WorkflowMutationReceipt[]>();
    const ownReceipt = receiptFixture("pid_77777777-7777-4777-8777-777777777777");
    const listA = vi.fn().mockResolvedValueOnce([]).mockResolvedValueOnce([ownReceipt]).mockResolvedValueOnce([]);
    const recoveryA: WorkflowRecoveryAPI = { listReceipts: listA, acknowledgeReceipt: vi.fn(() => acknowledgement.promise) };
    const recoveryB: WorkflowRecoveryAPI = { listReceipts: vi.fn(() => scopeBList.promise), acknowledgeReceipt: vi.fn() };
    const view = render(<WorkflowMutationProvider scopeKey="principal/organization/workspace-a/environment-a" recovery={recoveryA} reconcileReceipt={authoritativeRefetch}>
      <Probe operation="policies" name="policy" send={async () => ({ receiptID: "pid_77777777-7777-4777-8777-777777777777" })} />
    </WorkflowMutationProvider>);
    await waitFor(() => expect(listA).toHaveBeenCalledTimes(1));
    await user.click(screen.getByRole("button", { name: "Start policy" }));
    await waitFor(() => expect(recoveryA.acknowledgeReceipt).toHaveBeenCalledTimes(1));

    view.rerender(<WorkflowMutationProvider scopeKey="principal/organization/workspace-b/environment-b" recovery={recoveryB} reconcileReceipt={authoritativeRefetch}>
      <Probe operation="policies" name="policy" send={async () => "scope B mutation"} />
    </WorkflowMutationProvider>);
    expect(screen.getByRole("button", { name: "Start policy" })).toBeDisabled();
    await act(async () => acknowledgement.resolve());
    await waitFor(() => expect(listA).toHaveBeenCalledTimes(3));
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

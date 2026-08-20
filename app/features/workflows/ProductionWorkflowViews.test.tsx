import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { SessionProvider } from "../../auth/SessionProvider";
import { ProductionIntegrationsView } from "./ProductionWorkflowViews";
import { WorkflowMutationProvider } from "./useRetainedWorkflowMutation";

const integration: Integration = {
  id: "pid_20000001-0000-4000-8000-000000000001",
  connector_key: "github",
  name: "GitHub",
  configuration: { authorization_mode: "github_app" },
  status: "active",
  created_at: "2026-08-19T00:00:00Z",
  updated_at: "2026-08-19T00:01:00Z",
};
const revoking: Integration = { ...integration, status: "revoking", updated_at: "2026-08-19T00:02:00Z" };
const awsPending: Integration = {
	...integration,
	connector_key: "aws",
	name: "AWS",
	configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" },
	status: "pending_authorization",
};
const awsActive: Integration = { ...awsPending, status: "active", updated_at: "2026-08-19T00:02:00Z" };
const receiptHeaders = {
  ETag: '"2"',
  "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
  "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
};

describe("production integration deletion", () => {
	it("fails closed when reference authorization has no session authority", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn();
		render(<APIProvider client={{ GET, POST } as unknown as APIClient}><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite /></WorkflowMutationProvider></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeDisabled();
		expect(screen.getByRole("alert")).toHaveTextContent("Fresh authentication is required to authorize this reference.");
		expect(screen.queryByRole("button", { name: "Reauthenticate" })).not.toBeInTheDocument();
		expect(POST).not.toHaveBeenCalled();
	});

	it("authorizes a supported reference integration and keeps its references redacted", async () => {
		const user = userEvent.setup();
		const authorization = deferred<ReturnType<typeof jsonResult>>();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn(() => authorization.promise);
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		const authorize = screen.getByRole("button", { name: "Authorize AWS reference" });
		await user.click(authorize);
		expect(authorize).toBeDisabled();
		expect(screen.getByRole("dialog", { name: "AWS" })).not.toHaveTextContent("ref:aws/external-id/customer-0001");

		authorization.resolve(jsonResult(awsActive, 200, { ...receiptHeaders, "Cache-Control": "no-store" }));
		expect(await screen.findByRole("status")).toHaveTextContent("Integration authorized. Audit pid_30000001-0000-4000-8000-000000000001");
		expect(screen.getByRole("dialog", { name: "AWS" })).toHaveTextContent("active");
		expect(screen.queryByRole("button", { name: "Authorize AWS reference" })).not.toBeInTheDocument();
		expect(document.body.innerHTML).not.toContain("ref:aws/external-id/customer-0001");
	});

	it("refetches a 409 reference authorization conflict before enabling a new attempt", async () => {
		const user = userEvent.setup();
		let detailCalls = 0;
		const changed = { ...awsPending, name: "AWS current", status: "degraded" as const, updated_at: "2026-08-19T00:03:00Z" };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") {
				detailCalls += 1;
				return detailCalls === 1 ? jsonResult(awsPending, 200, { ETag: '"1"' }) : jsonResult(changed, 200, { ETag: '"2"' });
			}
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn(async () => productErrorResult(409, "conflict", "Resource version changed"));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));

		expect(await screen.findByRole("alert")).toHaveTextContent("Integration changed. Review the current version before authorizing again.");
		expect(screen.getByRole("dialog", { name: "AWS current" })).toHaveTextContent('Version "2"');
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeEnabled();
		expect(POST).toHaveBeenCalledOnce();
		expect(detailCalls).toBe(2);
	});

	it("retains the exact reference authorization attempt across lost responses", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost after commit"))
			.mockRejectedValueOnce(new TypeError("replay response lost"))
			.mockResolvedValueOnce(jsonResult(awsActive, 200, { ...receiptHeaders, "Cache-Control": "no-store" }));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));
		expect(await screen.findByText(/The response was lost\. The exact operation and idempotency key are retained\./)).toBeVisible();
		await user.click(screen.getByRole("button", { name: "Retry retained integration operation" }));
		expect(await screen.findByRole("status")).toHaveTextContent("Integration authorized");
		const calls = POST.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }] >;
		expect(calls).toHaveLength(3);
		expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
		expect(new Set(calls.map(([, options]) => options.params.header["If-Match"]))).toEqual(new Set(['"1"']));
	});

	it("blocks a retained reference authorization retry when fresh authentication expires", async () => {
		const user = userEvent.setup();
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost after commit"))
			.mockRejectedValueOnce(new TypeError("replay response lost"));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient, new Date(Date.now() + 500).toISOString());

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));
		expect(await screen.findByText(/The response was lost\. The exact operation and idempotency key are retained\./)).toBeVisible();
		await act(async () => { await new Promise((resolve) => setTimeout(resolve, 510)); });

		expect(screen.getByRole("button", { name: "Retry retained integration operation" })).toBeDisabled();
		expect(screen.getByText("Fresh authentication is required to retry this reference authorization.")).toBeVisible();
		expect(screen.getByRole("button", { name: "Reauthenticate" })).toBeEnabled();
		fireEvent.click(screen.getByRole("button", { name: "Retry retained integration operation" }));
		expect(POST).toHaveBeenCalledTimes(2);
	});

	it("keeps a retained reference authorization locked through 409 refetch failures", async () => {
		const user = userEvent.setup();
		let listCalls = 0;
		let detailCalls = 0;
		const changed = { ...awsPending, name: "AWS current", status: "degraded" as const, updated_at: "2026-08-19T00:03:00Z" };
		const foreign = { ...changed, id: "pid_20000001-0000-4000-8000-000000000099" };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") {
				listCalls += 1;
				return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			}
			if (path === "/api/v1/integrations/{id}") {
				detailCalls += 1;
				if (detailCalls === 1) return jsonResult(awsPending, 200, { ETag: '"1"' });
				if (detailCalls === 2) throw new TypeError("authoritative refetch failed");
				if (detailCalls === 3) return jsonResult(foreign, 200, { ETag: '"2"' });
				return jsonResult(changed, 200, { ETag: '"2"' });
			}
			throw new Error(`unexpected GET ${path}`);
		});
		const POST = vi.fn()
			.mockRejectedValueOnce(new TypeError("response lost after commit"))
			.mockRejectedValueOnce(new TypeError("replay response lost"))
			.mockResolvedValueOnce(productErrorResult(409, "conflict", "Resource version changed"));
		renderFreshIntegrations({ GET, POST } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		const listCallsBeforeConflictReconciliation = listCalls;
		await user.click(screen.getByRole("button", { name: "Authorize AWS reference" }));
		await user.click(await screen.findByRole("button", { name: "Retry retained integration operation" }));

		expect(await screen.findByRole("button", { name: "Retry authoritative integration refetch" })).toBeEnabled();
		expect(screen.getByRole("alert")).toHaveTextContent("The current integration could not be confirmed. Retry the authoritative refetch.");
		for (const close of screen.getAllByRole("button", { name: "Close" })) expect(close).toBeDisabled();
		await user.click(screen.getByRole("button", { name: "Retry authoritative integration refetch" }));
		expect(screen.getByRole("button", { name: "Retry authoritative integration refetch" })).toBeEnabled();
		for (const close of screen.getAllByRole("button", { name: "Close" })) expect(close).toBeDisabled();
		await user.click(screen.getByRole("button", { name: "Retry authoritative integration refetch" }));

		expect(await screen.findByRole("alert")).toHaveTextContent("Integration changed. Review the current version before authorizing again.");
		expect(screen.getByRole("dialog", { name: "AWS current" })).toHaveTextContent('Version "2"');
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeEnabled();
		await waitFor(() => expect(listCalls).toBe(listCallsBeforeConflictReconciliation + 1));
		expect(detailCalls).toBe(4);
		expect(POST).toHaveBeenCalledTimes(3);
		const calls = POST.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }] >;
		expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
		expect(new Set(calls.map(([, options]) => options.params.header["If-Match"]))).toEqual(new Set(['"1"']));
	});

	it("requires fresh authentication before offering a reference authorization mutation", async () => {
		const user = userEvent.setup();
		const bootstrap = {
			principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "org-production", member_reference: "member-production", role: "admin", active: true },
			organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
			permissions: ["view", "manage_workflows"], capabilities: ["integrations.read", "integrations.write"], csrf_token: "csrf_12345678901234567890123456789012",
			fresh_auth_expires_at: "2026-08-18T00:00:00Z", correlation_id: "pid_10000005-0000-4000-8000-000000000005",
		};
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/session/bootstrap") return jsonResult(bootstrap);
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [awsPending], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(awsPending, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		render(<APIProvider client={{ GET } as unknown as APIClient}><SessionProvider><ProductionIntegrationsView canWrite /></SessionProvider></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		expect(screen.getByRole("button", { name: "Authorize AWS reference" })).toBeDisabled();
		expect(screen.getByRole("alert")).toHaveTextContent("Fresh authentication is required to authorize this reference.");
		expect(screen.getByRole("button", { name: "Reauthenticate" })).toBeEnabled();
	});

	it("offers the same capability-gated reference authorization for Kubernetes", async () => {
		const user = userEvent.setup();
		const kubernetes: Integration = { ...awsPending, connector_key: "kubernetes", name: "Kubernetes", configuration: { connection_reference: "ref:kubernetes/connection/customer-0001" } };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [kubernetes], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(kubernetes, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		renderFreshIntegrations({ GET } as unknown as APIClient);

		await user.click(await screen.findByRole("button", { name: "Open Kubernetes" }));
		expect(screen.getByRole("button", { name: "Authorize Kubernetes reference" })).toBeEnabled();
		expect(screen.getByLabelText("connection reference")).toHaveValue("Configured reference");
		expect(document.body.innerHTML).not.toContain("ref:kubernetes/connection/customer-0001");
	});

  it("keeps revocation pending with the exact DELETE until terminal 204", async () => {
    const user = userEvent.setup();
    let listCalls = 0;
    const GET = vi.fn(async (path: string) => {
      if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
      if (path === "/api/v1/integrations") {
        listCalls += 1;
        return jsonResult({ items: [integration], page_info: { next_cursor: null, has_more: false } });
      }
      if (path === "/api/v1/integrations/{id}") return jsonResult(integration, 200, { ETag: '"1"' });
      throw new Error(`unexpected GET ${path}`);
    });
    const DELETE = vi.fn()
      .mockResolvedValueOnce(jsonResult(revoking, 202, { ...receiptHeaders, "Retry-After": "2" }))
      .mockResolvedValueOnce({ response: new Response(null, { status: 204, headers: receiptHeaders }) });
    const client = { GET, DELETE } as unknown as APIClient;

    const surface = (canWrite: boolean, route: "integrations" | "other" = "integrations") => <APIProvider client={client}><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a">{route === "integrations" ? <ProductionIntegrationsView canWrite={canWrite} /> : <p>Other route</p>}</WorkflowMutationProvider></APIProvider>;
    const view = render(surface(true));
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
		expect(screen.queryByRole("button", { name: /Authorize .* reference/ })).not.toBeInTheDocument();
    vi.useFakeTimers();
    await act(async () => {
      fireEvent.click(screen.getByRole("button", { name: "Delete integration" }));
      await Promise.resolve();
    });

    expect(screen.getByRole("status")).toHaveTextContent("Provider revocation is pending");
    const dialog = screen.getByRole("dialog", { name: "GitHub" });
    expect(dialog).toHaveTextContent("revoking");
    for (const button of within(dialog).getAllByRole("button", { name: "Close" })) expect(button).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Delete integration" })).toBeDisabled();
    expect(screen.queryByText(/Integration deleted/)).not.toBeInTheDocument();
    expect(listCalls).toBe(1);

    view.rerender(surface(true, "other"));
    expect(screen.getByText("Other route")).toBeVisible();
    expect(DELETE).toHaveBeenCalledTimes(1);
    view.rerender(surface(false));
    expect(screen.getByRole("status")).toHaveTextContent("Provider revocation is pending");
    expect(screen.queryByText(/The response was lost/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry pending integration deletion" })).not.toBeInTheDocument();
    view.rerender(surface(true));
    const retry = screen.getByRole("button", { name: "Retry pending integration deletion" });
    expect(retry).toBeDisabled();
    fireEvent.click(retry);
    expect(DELETE).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1_999); });
    expect(retry).toBeDisabled();
    expect(DELETE).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(retry).toBeEnabled();
    await act(async () => { fireEvent.click(retry); });
    vi.useRealTimers();
    expect(await screen.findByRole("status")).toHaveTextContent("Integration deleted. Audit pid_30000001-0000-4000-8000-000000000001");
    expect(screen.queryByRole("dialog", { name: "GitHub" })).not.toBeInTheDocument();
    await waitFor(() => expect(listCalls).toBe(3));
    const calls = DELETE.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }]>;
    expect(calls).toHaveLength(2);
    expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
    expect(calls.map(([, options]) => options.params.header["If-Match"])).toEqual(['"1"', '"1"']);
  });

  it("enables an already-due retained revocation when the effect observes an elapsed deadline", async () => {
    const now = vi.spyOn(Date, "now").mockImplementation(() => {
      const stack = new Error().stack ?? "";
      return stack.includes("ProductionWorkflowViews.tsx") && stack.includes("commitHookEffectListMount") ? 4_000 : 1_000;
    });
    const GET = vi.fn(async (path: string) => {
      if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
      if (path === "/api/v1/integrations") return jsonResult({ items: [integration], page_info: { next_cursor: null, has_more: false } });
      if (path === "/api/v1/integrations/{id}") return jsonResult(integration, 200, { ETag: '"1"' });
      throw new Error(`unexpected GET ${path}`);
    });
    const DELETE = vi.fn(async () => jsonResult(revoking, 202, { ...receiptHeaders, "Retry-After": "2" }));
    try {
      render(<APIProvider client={{ GET, DELETE } as unknown as APIClient}><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite /></WorkflowMutationProvider></APIProvider>);
      fireEvent.click(await screen.findByRole("button", { name: "Open GitHub" }));
      fireEvent.click(await screen.findByRole("button", { name: "Delete integration" }));
      const retry = await screen.findByRole("button", { name: "Retry pending integration deletion" });
      await waitFor(() => expect(retry).toBeEnabled());
    } finally {
      now.mockRestore();
    }
  });

	it("formats opaque configuration references without rendering their values", async () => {
		const user = userEvent.setup();
		const aws: Integration = { ...integration, connector_key: "aws", name: "AWS", configuration: { role_arn: "arn:aws:iam::123456789012:role/zasp-discovery", external_id_reference: "ref:aws/external-id/customer-0001", region: "us-east-1" } };
		const GET = vi.fn(async (path: string) => {
			if (path === "/api/v1/integration-catalog") return jsonResult({ items: [] });
			if (path === "/api/v1/integrations") return jsonResult({ items: [aws], page_info: { next_cursor: null, has_more: false } });
			if (path === "/api/v1/integrations/{id}") return jsonResult(aws, 200, { ETag: '"1"' });
			throw new Error(`unexpected GET ${path}`);
		});
		render(<APIProvider client={{ GET } as unknown as APIClient}><ProductionIntegrationsView canWrite={false} /></APIProvider>);

		await user.click(await screen.findByRole("button", { name: "Open AWS" }));
		const reference = screen.getByLabelText("external id reference");
		expect(reference).toHaveValue("Configured reference");
		expect(reference).toBeDisabled();
		expect(document.body.innerHTML).not.toContain("ref:aws/external-id/customer-0001");
		expect(screen.queryByRole("button", { name: "Authorize AWS reference" })).not.toBeInTheDocument();
	});
});

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return {
    data,
    response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }),
  };
}

function productErrorResult(status: number, code: string, message: string) {
	const error = { code, message, correlation_id: "pid_90000001-0000-4000-8000-000000000001", retryable: false };
	return { error, response: new Response(JSON.stringify(error), { status, headers: { "Content-Type": "application/json" } }) };
}

function renderFreshIntegrations(client: APIClient, expiresAt = new Date(Date.now() + 60_000).toISOString()) {
	const GET = client.GET.bind(client);
	const sessionClient = {
		...client,
		GET: (path: Parameters<APIClient["GET"]>[0], options?: unknown) => path === "/api/v1/session/bootstrap"
			? Promise.resolve(jsonResult(sessionBootstrap(expiresAt)))
			: GET(path as never, options as never),
	} as APIClient;
	return render(<APIProvider client={sessionClient}><SessionProvider><WorkflowMutationProvider scopeKey="organization/workspace-a/environment-a"><ProductionIntegrationsView canWrite /></WorkflowMutationProvider></SessionProvider></APIProvider>);
}

function sessionBootstrap(freshAuthExpiresAt: string) {
	return {
		principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "org-production", member_reference: "member-production", role: "admin", active: true },
		organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003",
		permissions: ["view", "manage_workflows"], capabilities: ["integrations.read", "integrations.write"], csrf_token: "csrf_12345678901234567890123456789012",
		fresh_auth_expires_at: freshAuthExpiresAt, correlation_id: "pid_10000005-0000-4000-8000-000000000005",
	};
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (error: unknown) => void;
	const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
	return { promise, resolve, reject };
}

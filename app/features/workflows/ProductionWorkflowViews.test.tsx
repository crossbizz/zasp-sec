import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
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
const receiptHeaders = {
  ETag: '"2"',
  "X-Audit-ID": "pid_30000001-0000-4000-8000-000000000001",
  "X-Mutation-Receipt-ID": "pid_30000002-0000-4000-8000-000000000002",
};

describe("production integration deletion", () => {
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
	});
});

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return {
    data,
    response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }),
  };
}

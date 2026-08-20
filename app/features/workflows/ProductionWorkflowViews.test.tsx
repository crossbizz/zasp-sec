import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import type { Integration } from "../../../apps/web/api/generated";
import { APIProvider } from "../../api/APIProvider";
import { ProductionIntegrationsView } from "./ProductionWorkflowViews";

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
      .mockResolvedValueOnce(jsonResult(revoking, 202, { ...receiptHeaders, "Retry-After": "1" }))
      .mockResolvedValueOnce({ response: new Response(null, { status: 204, headers: receiptHeaders }) });
    const client = { GET, DELETE } as unknown as APIClient;

    const surface = (canWrite: boolean) => <APIProvider client={client}><ProductionIntegrationsView canWrite={canWrite} /></APIProvider>;
    const view = render(surface(true));
    await user.click(await screen.findByRole("button", { name: "Open GitHub" }));
    await user.click(await screen.findByRole("button", { name: "Delete integration" }));

    expect(await screen.findByRole("status")).toHaveTextContent("Provider revocation is pending");
    const dialog = screen.getByRole("dialog", { name: "GitHub" });
    expect(dialog).toHaveTextContent("revoking");
    for (const button of within(dialog).getAllByRole("button", { name: "Close" })) expect(button).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(within(dialog).getByRole("button", { name: "Delete integration" })).toBeDisabled();
    expect(screen.queryByText(/Integration deleted/)).not.toBeInTheDocument();
    expect(listCalls).toBe(1);

    view.rerender(surface(false));
    expect(screen.getByRole("status")).toHaveTextContent("Provider revocation is pending");
    expect(screen.queryByRole("button", { name: "Retry pending integration deletion" })).not.toBeInTheDocument();
    view.rerender(surface(true));
    await user.click(screen.getByRole("button", { name: "Retry pending integration deletion" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Integration deleted. Audit pid_30000001-0000-4000-8000-000000000001");
    expect(screen.queryByRole("dialog", { name: "GitHub" })).not.toBeInTheDocument();
    await waitFor(() => expect(listCalls).toBe(2));
    const calls = DELETE.mock.calls as unknown as Array<[string, { params: { header: Record<string, string> } }]>;
    expect(calls).toHaveLength(2);
    expect(new Set(calls.map(([, options]) => options.params.header["Idempotency-Key"])).size).toBe(1);
    expect(calls.map(([, options]) => options.params.header["If-Match"])).toEqual(['"1"', '"1"']);
  });
});

function jsonResult(data: unknown, status = 200, headers: Record<string, string> = {}) {
  return {
    data,
    response: new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json", ...headers } }),
  };
}

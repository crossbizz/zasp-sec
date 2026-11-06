import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { APIProductError, createAPIClient } from "../../../apps/web/api/client";
import { describe, expect, it } from "vitest";
import { AdminOperationsView, type AdminOperationsAPI } from "./AdminOperationsView";

const productID = "pid_10000001-0000-4000-8000-000000000001";
function api(overrides: Partial<AdminOperationsAPI> = {}): AdminOperationsAPI { return {
  getHealth: async () => ({ status: { security_plane_healthy: false, optional_degraded: false, fresh_at: "2026-08-19T00:00:00Z" }, components: [{ id: "postgresql", required: true, state: "healthy", fresh_at: "2026-08-19T00:00:00Z" }, { id: "identity-provider", required: true, state: "unavailable", fresh_at: "2026-08-19T00:00:00Z" }], version: "1.0.0" }),
  getExternalFlows: async () => [{ id: "identity-provider", required: true, categories: ["identity_metadata"], enabled: true, health: "degraded" }],
  ...overrides,
}; }

describe("production administration state", () => {
  it("exposes organization export independently of a failed browse request when installed and authorized", async () => {
    const exports = { api: { create: async () => { throw new Error("unused"); }, read: async () => { throw new Error("unused"); } }, authority: { principalID: productID, organizationID: productID, workspaceID: productID, environmentID: productID, generation: 1, permitted: true, fresh: true }, retrySession: async () => {}, reauthenticate: () => {} };
    render(<AdminOperationsView surface="audit" auditAPI={{ page: async () => { throw new Error("browse unavailable"); } }} {...{ auditExport: exports }} />);
    expect(screen.getByRole("button", { name: "Create export" })).toBeEnabled();
    expect(screen.getByText(/unaffected by visible list filters/)).toBeVisible();
  });
  it("loads only the current audit page and sends applied exact filters on Next", async () => {
    const requests: URL[] = [];
    const client = createAPIClient({ fetch: async (request) => {
      const url = new URL(request.url); requests.push(url);
      return new Response(JSON.stringify({ items: [{ id: productID, workspace_id: productID, environment_id: productID, actor_id: productID, action: "identity_provider.createSSOConnection", target_id: productID, outcome: "succeeded", metadata: {}, occurred_at: "2026-08-19T00:00:00Z" }], page_info: { has_more: true, next_cursor: `cursor-${requests.length}` } }), { headers: { "Content-Type": "application/json" } });
    } });
    render(<AdminOperationsView surface="audit" client={client} />);
    expect(await screen.findByText("identity_provider.createSSOConnection")).toBeVisible();
    expect(requests).toHaveLength(1);
    await userEvent.type(screen.getByLabelText("Action (exact)"), "identity_provider.createSSOConnection");
    await userEvent.click(screen.getByRole("button", { name: "Apply filters" }));
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[1].searchParams.get("action")).toBe("identity_provider.createSSOConnection");
    expect(requests[1].searchParams.has("cursor")).toBe(false);
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(requests).toHaveLength(3));
    expect(requests[2].searchParams.get("cursor")).toBe("cursor-2");
    expect(requests[2].searchParams.get("action")).toBe("identity_provider.createSSOConnection");
  });
  it("renders only real probed components", async () => { render(<AdminOperationsView surface="health" api={api()} />); expect(await screen.findByText("Security plane degraded")).toBeVisible(); expect(screen.getByText("postgresql")).toBeVisible(); expect(screen.getByText("identity-provider")).toBeVisible(); expect(screen.queryByText(/remote telemetry/i)).not.toBeInTheDocument(); });
  it("derives external flow inventory from the registered adapter", async () => { render(<AdminOperationsView surface="external" api={api()} />); expect(await screen.findByText("identity-provider")).toBeVisible(); expect(screen.queryByText(/product analytics/i)).not.toBeInTheDocument(); });
  it("keeps durable audit readable and export disabled without claiming an installation state", async () => { render(<AdminOperationsView surface="audit" auditAPI={{ page: async () => ({ items: [{ id: productID, workspace_id: productID, environment_id: productID, actor_id: productID, action: "member.role.update", target_id: productID, outcome: "succeeded", metadata: {}, occurred_at: "2026-08-19T00:00:00Z" }], page_info: { has_more: false, next_cursor: null } }) }} />); expect(await screen.findByText("member.role.update")).toBeVisible(); expect(screen.getByText("Audit exports unavailable")).toBeVisible(); expect(screen.getByText("Export is unavailable for this session or installation.")).toBeVisible(); expect(screen.queryByText(/no export mutation is mounted/i)).not.toBeInTheDocument(); expect(screen.queryByRole("button", { name: /export/i })).not.toBeInTheDocument(); });
});

const flowBoundary = { identityKey: "principal/tenant-a/scope/1", permitted: true, fresh: true, isCurrent: () => true };
const serverFlows = [
  { id: "stytch", required: true, categories: ["identity_metadata"], enabled: true, health: "healthy" },
  { id: "neon", required: true, categories: ["security_metadata"], enabled: true, health: "healthy" },
  { id: "openrouter", name: "OpenRouter", required: false, categories: ["redacted_summary"], enabled: true, available: true, version: 4, health: "healthy" },
  { id: "posthog", required: false, categories: ["product_usage"], enabled: false, available: false, version: 1, health: "disabled" },
] as const;

it("disables an optional destination through real scoped PATCH and reloads authoritative server state", async () => {
  const requests: Request[] = []; let enabled = true, version = 4;
  const client = createAPIClient({ getCSRFToken: () => "owned-csrf", fetch: async request => {
    requests.push(request);
    if (request.method === "PATCH") { const body = await request.clone().json() as { enabled: boolean; flow_id: string; idempotency_key: string }; enabled = body.enabled; version++; return new Response(JSON.stringify({ flow_id: body.flow_id, enabled, version, idempotency_key: body.idempotency_key }), { headers: { "Content-Type": "application/json" } }); }
    return new Response(JSON.stringify({ items: serverFlows.map(flow => flow.id === "openrouter" ? { ...flow, enabled, version, health: enabled ? "healthy" : "disabled" } : flow) }), { headers: { "Content-Type": "application/json" } });
  } });
  render(<AdminOperationsView surface="external" client={client} externalBoundary={flowBoundary} />);
  await userEvent.dblClick(await screen.findByRole("button", { name: "Disable OpenRouter" }));
  expect(await screen.findByRole("button", { name: "Enable OpenRouter" })).toBeEnabled();
  expect(requests.map(request => request.method)).toEqual(["GET", "PATCH", "GET"]);
  const body = await requests[1].json() as { idempotency_key: string }; expect(body).toEqual({ flow_id: "openrouter", enabled: false, expected_version: 4, idempotency_key: expect.any(String) }); expect(requests[1].headers.get("Idempotency-Key")).toBe(body.idempotency_key);
  expect(screen.queryByRole("button", { name: /(?:Enable|Disable) (?:stytch|neon)/i })).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Enable posthog" })).toBeDisabled();
  await userEvent.click(screen.getByRole("button", { name: "Reload external data flows" }));
  await waitFor(() => expect(requests).toHaveLength(4)); expect(screen.getByRole("button", { name: "Enable OpenRouter" })).toBeEnabled();
});

it("retains the same intent after an ambiguous outcome and offers only an explicit same-key retry", async () => {
  const attempts: unknown[] = []; let applied = false;
  const operations = api({ getExternalFlows: async () => serverFlows.map(flow => flow.id === "openrouter" && applied ? { ...flow, enabled: false, version: 5, available: false, health: "disabled" as const } : flow), updateExternalFlow: async intent => { attempts.push(intent); if (!applied) { applied = true; throw Error("private token"); } return { flow_id: intent.flow_id, enabled: intent.enabled, version: intent.expected_version + 1, idempotency_key: intent.idempotency_key }; } });
  render(<AdminOperationsView surface="external" api={operations} externalBoundary={flowBoundary} />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable OpenRouter" }));
  expect(await screen.findByRole("alert")).not.toHaveTextContent("private token");
  expect(screen.queryByRole("button", { name: "Enable OpenRouter" })).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Reload external data flows" }));
  await waitFor(() => expect(screen.getByRole("button", { name: "Retry change for OpenRouter" })).toBeEnabled());
  await userEvent.click(screen.getByRole("button", { name: "Retry change for OpenRouter" }));
  await waitFor(() => expect(attempts).toHaveLength(2)); expect(attempts[1]).toEqual(attempts[0]);
});

it("keeps legacy and unauthorized catalogs read-only but permits safe disable after adapter availability expires", async () => {
  const operations = api({ getExternalFlows: async () => [{ ...serverFlows[2], available: false }, { ...serverFlows[3], version: undefined }], updateExternalFlow: async intent => ({ flow_id: intent.flow_id, enabled: intent.enabled, version: intent.expected_version + 1, idempotency_key: intent.idempotency_key }) });
  const view = render(<AdminOperationsView surface="external" api={operations} externalBoundary={{ ...flowBoundary, permitted: false }} />);
  expect(await screen.findByRole("button", { name: "Disable OpenRouter" })).toBeDisabled();
  view.rerender(<AdminOperationsView surface="external" api={operations} externalBoundary={flowBoundary} />);
  expect(await screen.findByRole("button", { name: "Disable OpenRouter" })).toBeEnabled();
  expect(screen.getByRole("button", { name: "Enable posthog" })).toBeDisabled();
});


it("aborts an unresolved change on scope or permission loss and ignores its late receipt", async () => {
  let resolve!: (value: { flow_id: "openrouter"; enabled: boolean; version: number; idempotency_key: string }) => void;
  const pending = new Promise<{ flow_id: "openrouter"; enabled: boolean; version: number; idempotency_key: string }>(r => { resolve = r; });
  let signal!: AbortSignal, key = "", reads = 0;
  const operations = api({ getExternalFlows: async () => { reads++; return serverFlows; }, updateExternalFlow: async (intent, currentSignal) => { signal = currentSignal; key = intent.idempotency_key; return pending; } });
  const view = render(<AdminOperationsView surface="external" api={operations} externalBoundary={flowBoundary} />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable OpenRouter" }));
  view.rerender(<AdminOperationsView surface="external" api={operations} externalBoundary={{ ...flowBoundary, identityKey: "principal/tenant-b/scope/2", permitted: false }} />);
  expect(signal.aborted).toBe(true); await screen.findByRole("button", { name: "Disable OpenRouter" });
  await act(async () => { resolve({ flow_id: "openrouter", enabled: false, version: 5, idempotency_key: key }); await pending; });
  expect(reads).toBe(2); expect(screen.queryByText("Change recorded. Current server policy reloaded.")).not.toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Disable OpenRouter" })).toBeDisabled();
});


it("recovers a confirmed mutation with GET only when catalog reload fails", async () => {
  let reads = 0, writes = 0;
  const operations = api({ getExternalFlows: async () => { reads++; if (reads === 2) throw Error("read failed"); return serverFlows.map(flow => flow.id === "openrouter" && writes ? { ...flow, enabled: false, version: 5, health: "disabled" as const } : flow); }, updateExternalFlow: async intent => { writes++; return { flow_id: intent.flow_id, enabled: intent.enabled, version: intent.expected_version + 1, idempotency_key: intent.idempotency_key }; } });
  render(<AdminOperationsView surface="external" api={operations} externalBoundary={flowBoundary} />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable OpenRouter" }));
  await userEvent.click(await screen.findByRole("button", { name: "Reload policy status for OpenRouter" }));
  expect(await screen.findByRole("button", { name: "Enable OpenRouter" })).toBeEnabled(); expect(writes).toBe(1); expect(reads).toBe(3);
});

it("reloads a definitively rejected CAS before an explicit new intent", async () => {
  let reads = 0; const intents: { idempotency_key: string; expected_version: number }[] = [];
  const operations = api({ getExternalFlows: async () => { reads++; return serverFlows.map(flow => flow.id === "openrouter" ? { ...flow, version: reads === 1 ? 4 : 5 } : flow); }, updateExternalFlow: async intent => {
    intents.push(intent); if (intents.length === 1) throw new APIProductError(409, { code: "operation_conflict", message: "Operation conflicted", correlation_id: productID, retryable: false });
    return { flow_id: intent.flow_id, enabled: intent.enabled, version: intent.expected_version + 1, idempotency_key: intent.idempotency_key };
  } });
  render(<AdminOperationsView surface="external" api={operations} externalBoundary={flowBoundary} />);
  await userEvent.click(await screen.findByRole("button", { name: "Disable OpenRouter" }));
  await userEvent.click(await screen.findByRole("button", { name: "Reload before a new change for OpenRouter" }));
  expect(intents).toHaveLength(1);
  await userEvent.click(await screen.findByRole("button", { name: "Disable OpenRouter" }));
  await waitFor(() => expect(intents).toHaveLength(2)); expect(intents[1].expected_version).toBe(5); expect(intents[1].idempotency_key).not.toBe(intents[0].idempotency_key);
});

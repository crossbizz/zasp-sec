import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { createAPIClient } from "../../../apps/web/api/client";
import { APIProvider, useAPI } from "../../api/APIProvider";
import { SessionProvider } from "../../auth/SessionProvider";
import { APIAccessView, type APIAccessAPI } from "./APIAccessView";

const activeWorkspaceID = "pid_10000002-0000-4000-8000-000000000002";
const activeEnvironmentID = "pid_10000003-0000-4000-8000-000000000003";

function SessionExpiryControl() {
  const { client } = useAPI();
  return <button onClick={() => void client.GET("/api/v1/home/summary")}>Expire session in test</button>;
}

function renderAuthenticated(api: APIAccessAPI, freshAuthExpiresAt = new Date(Date.now() + 60_000).toISOString(), includeSessionExpiryControl = false) {
  const fetch = async (request: Request) => {
      const path = new URL(request.url).pathname;
      if (path === "/api/v1/home/summary") return new Response(JSON.stringify({ code: "authentication_required", message: "Authentication required", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: false }), { status: 401, headers: { "Content-Type": "application/json" } });
      if (path !== "/api/v1/session/bootstrap") throw new Error(`unexpected request ${path}`);
      return new Response(JSON.stringify({
        principal: { id: "pid_10000004-0000-4000-8000-000000000004", organization_id: "pid_10000001-0000-4000-8000-000000000001", organization_reference: "organization-test", member_reference: "member-test", role: "security_admin", active: true },
        organization_id: "pid_10000001-0000-4000-8000-000000000001",
        workspace_id: activeWorkspaceID,
        environment_id: activeEnvironmentID,
        permissions: ["view"],
        capabilities: ["api-access.manage"],
        csrf_token: "cccccccccccccccccccccccccccccccc",
        fresh_auth_expires_at: freshAuthExpiresAt,
        correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
      }), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  const client = createAPIClient({
    fetch,
    generateCorrelationID: () => "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
  });
  if (includeSessionExpiryControl) {
    vi.stubGlobal("fetch", fetch);
    return render(<APIProvider><SessionProvider><APIAccessView api={api} /><SessionExpiryControl /></SessionProvider></APIProvider>);
  }
  return render(<APIProvider client={client}><SessionProvider><APIAccessView api={api} />{includeSessionExpiryControl && <SessionExpiryControl />}</SessionProvider></APIProvider>);
}

function fixtureAPI(overrides: Partial<APIAccessAPI> = {}): APIAccessAPI {
  const token = { id: "pid_token", name: "CI scanner", workspaceId: "pid_workspace", environmentId: "pid_environment", permissions: ["view"], expiresAt: "2026-08-19T00:00:00.000Z", revokedAt: null, version: 1 };
  const created = { ...token, id: "pid_created", name: "Automation" };
  const createdGrant = { grantId: "pid_grant", tokenId: created.id, operation: "createAPIToken" as const, expiresAt: "2026-08-19T00:05:00.000Z" };
  return {
    listTokens: async () => [token],
    listPendingGrants: async () => [],
    createToken: async () => ({ token: created, grant: createdGrant }),
    rotateToken: async (id, version) => {
      const replacement = { ...token, id: `${id}_replacement`, version: version + 1 };
      return { token: replacement, grant: { ...createdGrant, tokenId: replacement.id, operation: "rotateAPIToken" } };
    },
    revealGrant: async (id) => ({ grantId: id, tokenId: created.id, rawToken: `zasp_pat_${"A".repeat(43)}`, expiresAt: createdGrant.expiresAt }),
    acknowledgeGrant: async () => undefined,
    revokeToken: async (id, version) => ({ id, name: "CI scanner", workspaceId: "pid_workspace", environmentId: "pid_environment", permissions: ["view"], expiresAt: "2026-08-19T00:00:00.000Z", revokedAt: "2026-08-18T01:00:00.000Z", version: version + 1 }),
    ...overrides,
  };
}

describe("API Access product surface", () => {
  afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });

  it("lists, creates, reveals, acknowledges, and revokes API tokens", async () => {
    const user = userEvent.setup();
    const revokeToken = vi.fn(fixtureAPI().revokeToken);
    const acknowledgeGrant = vi.fn(fixtureAPI().acknowledgeGrant);
    const createToken = vi.fn(fixtureAPI().createToken);
    renderAuthenticated(fixtureAPI({ createToken, revokeToken, acknowledgeGrant }));

    expect(await screen.findByText("CI scanner")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Token name"), "Automation");
    expect(screen.queryByLabelText("Workspace ID")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Environment ID")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create API token" }));
    await waitFor(() => expect(createToken).toHaveBeenCalledWith(expect.objectContaining({ workspaceId: activeWorkspaceID, environmentId: activeEnvironmentID }), expect.stringMatching(/^admin_/)));
    expect(await screen.findByLabelText("API token credential")).toHaveTextContent(/^zasp_pat_A{43}$/);
    expect(screen.getByRole("dialog", { name: "Save API token" })).toContainElement(document.activeElement as HTMLElement);
    await user.click(screen.getByRole("button", { name: "I saved it — destroy recovery copy" }));
    await waitFor(() => expect(acknowledgeGrant).toHaveBeenCalledWith("pid_grant"));
    expect(screen.queryByRole("dialog", { name: "Save API token" })).not.toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("button", { name: "Create API token" })).toHaveFocus());

    vi.spyOn(window, "confirm").mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Revoke CI scanner" }));
    await waitFor(() => expect(revokeToken).toHaveBeenCalledWith("pid_token", 1));
  });

  it("recovers a pending reveal grant after reload and reports copy failure without exposing the secret elsewhere", async () => {
    const user = userEvent.setup();
    const grant = { grantId: "pid_grant", tokenId: "pid_token", operation: "createAPIToken" as const, expiresAt: "2026-08-19T00:05:00.000Z" };
    const acknowledgeGrant = vi.fn(fixtureAPI().acknowledgeGrant);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    renderAuthenticated(fixtureAPI({ listPendingGrants: async () => [grant], acknowledgeGrant }));

    expect(await screen.findByLabelText("Token name")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Create API token" })).toBeDisabled();
    await user.click(await screen.findByRole("button", { name: "Reveal token" }));
    await user.click(screen.getByRole("button", { name: "Copy token" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Copy failed");
    expect(document.body.textContent?.match(/zasp_pat_/g)).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "I saved it — destroy recovery copy" }));
    await waitFor(() => expect(acknowledgeGrant).toHaveBeenCalledWith("pid_grant"));
  });

  it("retains and locks an ambiguous create until the exact idempotent retry reconciles", async () => {
    const user = userEvent.setup();
    const recovered = await fixtureAPI().createToken({ name: "Automation", workspaceId: "pid_workspace", environmentId: "pid_environment", permissions: ["view"], expiresAt: "2026-08-20T00:00:00Z" }, "unused");
    const keys: string[] = [];
    const createToken = vi.fn(async (_input: Parameters<APIAccessAPI["createToken"]>[0], key: string) => {
      keys.push(key);
      if (keys.length === 1) throw new Error("response lost");
      return recovered;
    });
    renderAuthenticated(fixtureAPI({ createToken }));
    await screen.findByText("CI scanner");
    await user.type(screen.getByLabelText("Token name"), "Automation");
    await user.click(screen.getByRole("button", { name: "Create API token" }));

    expect(await screen.findByRole("button", { name: "Retry retained API token create" })).toBeEnabled();
    expect(screen.getByLabelText("Token name")).toBeDisabled();
    await user.click(screen.getByRole("button", { name: "Retry retained API token create" }));
    expect(await screen.findByRole("dialog", { name: "Save API token" })).toBeVisible();
    expect(keys).toHaveLength(2);
    expect(keys[1]).toBe(keys[0]);
  });

  it("keeps the secret dialog open and retries the exact acknowledgement after a lost response", async () => {
    const user = userEvent.setup();
    const acknowledgeGrant = vi.fn()
      .mockRejectedValueOnce(new Error("response lost"))
      .mockResolvedValueOnce(undefined);
    renderAuthenticated(fixtureAPI({ listPendingGrants: async () => [{ grantId: "pid_grant", tokenId: "pid_token", operation: "createAPIToken", expiresAt: "2026-08-19T00:05:00Z" }], acknowledgeGrant }));
    await user.click(await screen.findByRole("button", { name: "Reveal token" }));
    await user.click(screen.getByRole("button", { name: "I saved it — destroy recovery copy" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Acknowledgement failed");
    expect(screen.getByRole("dialog", { name: "Save API token" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "I saved it — destroy recovery copy" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Save API token" })).not.toBeInTheDocument());
    expect(acknowledgeGrant).toHaveBeenCalledTimes(2);
  });

  it("keeps a pending grant and visible retry feedback after a lost reveal response", async () => {
    const user = userEvent.setup();
    const grant = { grantId: "pid_grant", tokenId: "pid_token", operation: "createAPIToken" as const, expiresAt: "2026-08-19T00:05:00Z" };
    const revealGrant = vi.fn()
      .mockRejectedValueOnce(new Error("response lost"))
      .mockResolvedValueOnce({ grantId: grant.grantId, tokenId: grant.tokenId, rawToken: `zasp_pat_${"A".repeat(43)}`, expiresAt: grant.expiresAt });
    renderAuthenticated(fixtureAPI({ listPendingGrants: async () => [grant], revealGrant }));
    await user.click(await screen.findByRole("button", { name: "Reveal token" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("reveal grant is unavailable or expired");
    expect(screen.getByRole("button", { name: "Reveal token" })).toBeEnabled();
    await user.click(screen.getByRole("button", { name: "Reveal token" }));
    expect(await screen.findByRole("dialog", { name: "Save API token" })).toBeVisible();
    expect(revealGrant).toHaveBeenCalledTimes(2);
  });

  it("fails closed with stable loading, empty, validation, and error states", async () => {
    const user = userEvent.setup();
    renderAuthenticated(fixtureAPI({ listTokens: async () => [] }));
    expect(screen.getByText("Loading API access…")).toBeInTheDocument();
    expect(await screen.findByText("No API tokens")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create API token" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter a token name");

    cleanup();
    renderAuthenticated(fixtureAPI({ listTokens: async () => { throw new Error("secret provider detail"); } }));
    expect(await screen.findByRole("alert")).toHaveTextContent("API access could not be loaded");
    expect(screen.queryByText("secret provider detail")).not.toBeInTheDocument();
  });

  it("clears a revealed raw token as soon as the fresh-auth clock expires", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-19T00:00:00.000Z"));
    const grant = { grantId: "pid_grant", tokenId: "pid_token", operation: "createAPIToken" as const, expiresAt: "2026-08-19T00:05:00.000Z" };
    renderAuthenticated(fixtureAPI({ listPendingGrants: async () => [grant] }), "2026-08-19T00:00:01.000Z");
    await act(async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); });
    fireEvent.click(screen.getByRole("button", { name: "Reveal token" }));
    await act(async () => { await Promise.resolve(); await Promise.resolve(); });
    expect(screen.getByLabelText("API token credential")).toHaveTextContent(/^zasp_pat_A{43}$/);
    expect(screen.getByRole("button", { name: "Copy token" })).toBeEnabled();

    act(() => { vi.advanceTimersByTime(1_010); });
    await act(async () => { await Promise.resolve(); });
    expect(screen.queryByText(/^zasp_pat_/)).not.toBeInTheDocument();
    expect(screen.queryByRole("dialog", { name: "Save API token" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy token" })).not.toBeInTheDocument();
    expect(screen.getByText(/revealed token was cleared/)).toBeInTheDocument();
  });

  it("clears a revealed raw token when the product session becomes invalid", async () => {
    const grant = { grantId: "pid_grant", tokenId: "pid_token", operation: "createAPIToken" as const, expiresAt: "2026-08-19T00:05:00.000Z" };
    renderAuthenticated(fixtureAPI({ listPendingGrants: async () => [grant] }), new Date(Date.now() + 60_000).toISOString(), true);
    fireEvent.click(await screen.findByRole("button", { name: "Reveal token" }));
    expect(await screen.findByLabelText("API token credential")).toHaveTextContent(/^zasp_pat_A{43}$/);
    fireEvent.click(screen.getByText("Expire session in test"));
    await waitFor(() => expect(screen.queryByText(/^zasp_pat_/)).not.toBeInTheDocument());
    expect(screen.queryByRole("button", { name: "Copy token" })).not.toBeInTheDocument();
    expect(screen.getByText(/revealed token was cleared/)).toBeInTheDocument();
  });
});

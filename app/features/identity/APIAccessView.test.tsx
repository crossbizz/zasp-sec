import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIAccessView, type APIAccessAPI } from "./APIAccessView";

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
  it("lists, creates, reveals, acknowledges, and revokes API tokens", async () => {
    const user = userEvent.setup();
    const revokeToken = vi.fn(fixtureAPI().revokeToken);
    const acknowledgeGrant = vi.fn(fixtureAPI().acknowledgeGrant);
    render(<APIAccessView api={fixtureAPI({ revokeToken, acknowledgeGrant })} />);

    expect(await screen.findByText("CI scanner")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Token name"), "Automation");
    await user.type(screen.getByLabelText("Workspace ID"), "pid_workspace");
    await user.type(screen.getByLabelText("Environment ID"), "pid_environment");
    await user.click(screen.getByRole("button", { name: "Create API token" }));
    expect(await screen.findByLabelText("API token credential")).toHaveTextContent(/^zasp_pat_A{43}$/);
    expect(screen.getByRole("dialog", { name: "Save API token" })).toContainElement(document.activeElement as HTMLElement);
    await user.click(screen.getByRole("button", { name: "I saved it — destroy recovery copy" }));
    await waitFor(() => expect(acknowledgeGrant).toHaveBeenCalledWith("pid_grant"));
    expect(screen.queryByRole("dialog", { name: "Save API token" })).not.toBeInTheDocument();

    vi.spyOn(window, "confirm").mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Revoke CI scanner" }));
    await waitFor(() => expect(revokeToken).toHaveBeenCalledWith("pid_token", 1));
  });

  it("recovers a pending reveal grant after reload and reports copy failure without exposing the secret elsewhere", async () => {
    const user = userEvent.setup();
    const grant = { grantId: "pid_grant", tokenId: "pid_token", operation: "createAPIToken" as const, expiresAt: "2026-08-19T00:05:00.000Z" };
    const acknowledgeGrant = vi.fn(fixtureAPI().acknowledgeGrant);
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn().mockRejectedValue(new Error("denied")) } });
    render(<APIAccessView api={fixtureAPI({ listPendingGrants: async () => [grant], acknowledgeGrant })} />);

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
    render(<APIAccessView api={fixtureAPI({ createToken })} />);
    await screen.findByText("CI scanner");
    await user.type(screen.getByLabelText("Token name"), "Automation");
    await user.type(screen.getByLabelText("Workspace ID"), "pid_workspace");
    await user.type(screen.getByLabelText("Environment ID"), "pid_environment");
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
    render(<APIAccessView api={fixtureAPI({ listPendingGrants: async () => [{ grantId: "pid_grant", tokenId: "pid_token", operation: "createAPIToken", expiresAt: "2026-08-19T00:05:00Z" }], acknowledgeGrant })} />);
    await user.click(await screen.findByRole("button", { name: "Reveal token" }));
    await user.click(screen.getByRole("button", { name: "I saved it — destroy recovery copy" }));
    expect(await screen.findByRole("status")).toHaveTextContent("Acknowledgement failed");
    expect(screen.getByRole("dialog", { name: "Save API token" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "I saved it — destroy recovery copy" }));
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Save API token" })).not.toBeInTheDocument());
    expect(acknowledgeGrant).toHaveBeenCalledTimes(2);
  });

  it("fails closed with stable loading, empty, validation, and error states", async () => {
    const user = userEvent.setup();
    render(<APIAccessView api={fixtureAPI({ listTokens: async () => [] })} />);
    expect(screen.getByText("Loading API access…")).toBeInTheDocument();
    expect(await screen.findByText("No API tokens")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create API token" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter token name and canonical scope IDs");

    cleanup();
    render(<APIAccessView api={fixtureAPI({ listTokens: async () => { throw new Error("secret provider detail"); } })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("API access could not be loaded");
    expect(screen.queryByText("secret provider detail")).not.toBeInTheDocument();
  });
});

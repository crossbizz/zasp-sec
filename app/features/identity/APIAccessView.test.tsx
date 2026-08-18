import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIAccessView, type APIAccessAPI } from "./APIAccessView";

function fixtureAPI(overrides: Partial<APIAccessAPI> = {}): APIAccessAPI {
  return {
    listTokens: async () => [{ id: "pid_token", name: "CI scanner", workspaceId: "pid_workspace", environmentId: "pid_environment", permissions: ["view"], expiresAt: "2026-08-19T00:00:00.000Z", revokedAt: null }],
    createToken: async (input) => ({ id: "pid_created", ...input, revokedAt: null, rawToken: "zasp_pat_one_time_fixture" }),
    revokeToken: async (id) => ({ id, name: "CI scanner", workspaceId: "pid_workspace", environmentId: "pid_environment", permissions: ["view"], expiresAt: "2026-08-19T00:00:00.000Z", revokedAt: "2026-08-18T01:00:00.000Z" }),
    ...overrides,
  };
}

describe("API Access product surface", () => {
  it("lists, creates, displays once, and revokes API tokens", async () => {
    const user = userEvent.setup();
    const revokeToken = vi.fn(fixtureAPI().revokeToken);
    render(<APIAccessView api={fixtureAPI({ revokeToken })} />);

    expect(await screen.findByText("CI scanner")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Token name"), "Automation");
    await user.type(screen.getByLabelText("Workspace ID"), "pid_workspace");
    await user.type(screen.getByLabelText("Environment ID"), "pid_environment");
    await user.click(screen.getByRole("button", { name: "Create API token" }));
    expect(await screen.findByText(/zasp_pat_one_time_fixture/)).toBeInTheDocument();
    expect(screen.getByText(/shown only once/i)).toBeInTheDocument();

    vi.spyOn(window, "confirm").mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Revoke CI scanner" }));
    await waitFor(() => expect(revokeToken).toHaveBeenCalledWith("pid_token"));
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

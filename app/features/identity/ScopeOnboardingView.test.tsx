import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ScopeOnboardingView, type ScopeAdminAPI } from "./ScopeOnboardingView";

function fixtureAPI(overrides: Partial<ScopeAdminAPI> = {}): ScopeAdminAPI {
  return {
    listWorkspaces: async () => [{ id: "pid_workspace_a", name: "Agent Security" }],
    createWorkspace: async (name) => ({ id: "pid_workspace_b", name }),
    updateWorkspace: async (id, name) => ({ id, name }),
    listEnvironments: async () => [{ id: "pid_environment_a", workspaceId: "pid_workspace_a", name: "Production" }],
    createEnvironment: async (workspaceId, name) => ({ id: "pid_environment_b", workspaceId, name }),
    updateEnvironment: async (id, name) => ({ id, workspaceId: "pid_workspace_a", name }),
    ...overrides,
  };
}

describe("Workspace and Environment onboarding", () => {
  it("creates, updates, and selects only API-authorized scopes", async () => {
    const user = userEvent.setup();
    const onScopeChange = vi.fn();
    const setItem = vi.spyOn(Storage.prototype, "setItem");
    render(<ScopeOnboardingView api={fixtureAPI()} onScopeChange={onScopeChange} />);
    expect(await screen.findByRole("option", { name: "Agent Security" })).toBeInTheDocument();
    expect(screen.queryByText("Inaccessible workspace")).not.toBeInTheDocument();

    await user.type(screen.getByLabelText("New workspace name"), "Research");
    await user.click(screen.getByRole("button", { name: "Create workspace" }));
    expect(await screen.findByRole("option", { name: "Research" })).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Authorized workspace"), "pid_workspace_a");
    await user.selectOptions(await screen.findByLabelText("Authorized environment"), "pid_environment_a");
    await waitFor(() => expect(onScopeChange).toHaveBeenCalledWith({ workspaceId: "pid_workspace_a", environmentId: "pid_environment_a" }));

    await user.clear(screen.getByLabelText("Environment display name"));
    await user.type(screen.getByLabelText("Environment display name"), "Primary production");
    await user.click(screen.getByRole("button", { name: "Update environment" }));
    expect(await screen.findByRole("option", { name: "Primary production" })).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Workspace display name"));
    await user.type(screen.getByLabelText("Workspace display name"), "Agent Platform");
    await user.click(screen.getByRole("button", { name: "Update workspace" }));
    expect(await screen.findByRole("option", { name: "Agent Platform" })).toBeInTheDocument();

    await user.type(screen.getByLabelText("New environment name"), "Staging");
    await user.click(screen.getByRole("button", { name: "Create environment" }));
    expect(await screen.findByRole("option", { name: "Staging" })).toBeInTheDocument();
    expect(setItem).not.toHaveBeenCalledWith("zasp-authorized-scope", expect.anything());
  });

  it("renders stable empty, validation, and provider error states", async () => {
    const user = userEvent.setup();
    render(<ScopeOnboardingView api={fixtureAPI({ listWorkspaces: async () => [] })} />);
    expect(await screen.findByText("No authorized workspaces")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create workspace" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter a workspace name");

    cleanup();
    render(<ScopeOnboardingView api={fixtureAPI({ listWorkspaces: async () => { throw new Error("database detail"); } })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Authorized scopes could not be loaded");
    expect(screen.queryByText("database detail")).not.toBeInTheDocument();
  });
});

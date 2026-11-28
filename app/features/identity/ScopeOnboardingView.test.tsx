import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { APIProductError } from "../../../apps/web/api/client";
import { ScopeOnboardingView, type ScopeAdminAPI } from "./ScopeOnboardingView";

const organization = { id: "pid_10000000-0000-4000-8000-000000000001", name: "Agent Security", domain: "example.test", version: 3 };

function fixtureAPI(overrides: Partial<ScopeAdminAPI> = {}): ScopeAdminAPI {
  return {
    getOrganization: async () => organization,
    updateOrganization: async (name, version) => ({ ...organization, name, version: version + 1 }),
    listWorkspaces: async () => [{ id: "pid_workspace_a", name: "Agent Security" }],
    createWorkspace: async (name) => ({ id: "pid_workspace_b", name, initialEnvironmentId: "pid_environment_b" }),
    updateWorkspace: async (id, name) => ({ id, name }),
    listEnvironments: async (workspaceId) => workspaceId === "pid_workspace_b" ? [{ id: "pid_environment_b", workspaceId, name: "Development" }] : [{ id: "pid_environment_a", workspaceId: "pid_workspace_a", name: "Production" }],
    createEnvironment: async (workspaceId, name) => ({ id: "pid_environment_b", workspaceId, name }),
    updateEnvironment: async (id, name) => ({ id, workspaceId: "pid_workspace_a", name }),
    ...overrides,
  };
}

describe("Workspace and Environment onboarding", () => {
  it("renames the current organization using its loaded version and reloads after a conflicting edit", async () => {
    const user = userEvent.setup();
    const concurrent = { ...organization, name: "New owner", version: 4 };
    const getOrganization = vi.fn().mockResolvedValueOnce(organization).mockResolvedValue(concurrent);
    const updateOrganization = vi.fn()
      .mockRejectedValueOnce(new APIProductError(409, { code: "version_conflict", message: "Resource version conflict", correlation_id: organization.id, retryable: false }))
      .mockResolvedValueOnce({ ...organization, name: "Research", version: 5 });
    render(<ScopeOnboardingView api={fixtureAPI({ getOrganization, updateOrganization })} />);
    const field = await screen.findByRole("textbox", { name: "Organization display name" });
    const save = screen.getByRole("button", { name: "Save organization name" });
    expect(field).toHaveValue(organization.name);
    expect(save).toBeDisabled();
    await user.clear(field);
    await user.type(field, "Research");
    await user.click(save);
    expect(updateOrganization).toHaveBeenCalledWith("Research", 3);
    expect(await screen.findByRole("alert")).toHaveTextContent("Another administrator changed the display name");
    expect(field).toHaveValue("New owner");
    expect(save).toBeDisabled();
    await user.clear(field);
    await user.type(field, "Research");
    await user.click(save);
    expect(updateOrganization).toHaveBeenCalledWith("Research", 4);
    expect(await screen.findByRole("status")).toHaveTextContent("Organization display name updated");
    expect(screen.getByText("example.test")).toBeVisible();
  });

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
    expect(screen.getByRole("combobox", { name: "Authorized workspace" })).toHaveValue("pid_workspace_b");
    await waitFor(() => expect(onScopeChange).toHaveBeenCalledWith({ workspaceId: "pid_workspace_b", environmentId: "pid_environment_b" }));

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

  it("renders only the exact environments returned by the authorized scope boundary", async () => {
    const listEnvironments = vi.fn(async (workspaceId: string) => [
      { id: "pid_environment_a", workspaceId, name: "Production" },
      { id: "pid_environment_b", workspaceId, name: "Authorized development" },
    ]);
    render(<ScopeOnboardingView api={fixtureAPI({ listEnvironments })} />);
    expect(await screen.findByRole("option", { name: "Production" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Authorized development" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Unpermitted environment" })).not.toBeInTheDocument();
    expect(listEnvironments).toHaveBeenCalledWith("pid_workspace_a");
  });
});

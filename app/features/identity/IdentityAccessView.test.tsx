import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { IdentityAccessView, type IdentityAdminAPI } from "./IdentityAccessView";

function fixtureAPI(overrides: Partial<IdentityAdminAPI> = {}): IdentityAdminAPI {
  return {
    listMembers: async () => [{ id: "pid_member", memberReference: "member-live-a", role: "organization_admin", active: true, version: 1 }],
    updateMemberRole: async (id, role, version) => ({ id, memberReference: "member-live-a", role, active: true, version: version + 1 }),
    listRoles: async () => [{ role: "organization_admin", permissions: ["view", "manage_identity"] }],
    listSSOConnections: async () => [{ id: "saml-connection-live-a", status: "active", displayName: "Corporate SAML", protocol: "saml", identityProvider: "okta" }],
    createSSOConnection: async (input) => ({ id: "saml-connection-created", status: "pending", ...input }),
    deleteSSOConnection: async () => undefined,
    testSSOConnection: async () => undefined,
    listSCIMConnections: async () => [{ id: "scim-connection-live-a", status: "active", displayName: "Corporate SCIM", identityProvider: "okta", baseURL: "https://scim.stytch.com/v2/live-a" }],
    createSCIMConnection: async (input) => ({ id: "scim-connection-created", status: "active", ...input, baseURL: "https://scim.stytch.com/v2/created", bearerToken: "scim_bearer_token_recoverable" }),
    deleteSCIMConnection: async () => undefined,
		listGroupMappings: async () => [{ groupReference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", role: "organization_admin", workspaceID: "pid_workspace", environmentID: "pid_environment", version: 1 }],
		updateGroupMapping: async (input) => ({ ...input, version: input.expectedVersion + 1 }),
    ...overrides,
  };
}

describe("Identity & Access product surface", () => {
  it("renders durable identity sections and live provider administration", async () => {
    render(<IdentityAccessView api={fixtureAPI()} />);
    expect(screen.getByText("Loading identity and access…")).toBeInTheDocument();
    for (const label of ["Members", "Built-in roles", "Enterprise identity", "Group mappings"]) {
      expect(await screen.findByRole("heading", { name: label })).toBeInTheDocument();
      expect(screen.getByRole("link", { name: label })).toHaveAttribute("href", expect.stringMatching(/^#identity-/));
    }
		expect(screen.getByRole("button", { name: "Add SSO connection" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add SCIM connection" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Test Corporate SAML" })).toBeInTheDocument();
		expect(screen.getByLabelText("Stytch SCIM group ID")).toBeInTheDocument();
		expect(screen.getByText("scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31")).toBeInTheDocument();
  });

	it("creates a tenant group mapping with fresh authorization inputs", async () => {
		const user = userEvent.setup();
		const updateGroupMapping = vi.fn(fixtureAPI().updateGroupMapping);
		render(<IdentityAccessView api={fixtureAPI({ listGroupMappings: async () => [], updateGroupMapping })} />);
		await user.type(await screen.findByLabelText("Stytch SCIM group ID"), "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c32");
		await user.type(screen.getByLabelText("Workspace ID"), "pid_workspace");
		await user.type(screen.getByLabelText("Environment ID"), "pid_environment");
		await user.click(screen.getByRole("button", { name: "Save group mapping" }));
		expect(updateGroupMapping).toHaveBeenCalledWith({ groupReference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c32", role: "organization_admin", workspaceID: "pid_workspace", environmentID: "pid_environment", expectedVersion: 0 });
		expect(await screen.findByText("Group mapping saved; affected sessions revoked")).toBeInTheDocument();
	});

  it("creates, tests, and deletes provider connections without exposing provider errors", async () => {
    const user = userEvent.setup();
    const createSSOConnection = vi.fn(fixtureAPI().createSSOConnection);
    const testSSOConnection = vi.fn(fixtureAPI().testSSOConnection);
    const deleteSCIMConnection = vi.fn(fixtureAPI().deleteSCIMConnection);
    render(<IdentityAccessView api={fixtureAPI({ createSSOConnection, testSSOConnection, deleteSCIMConnection })} />);
    await user.type(await screen.findByLabelText("SSO display name"), "Launch SSO");
    await user.click(screen.getByRole("button", { name: "Add SSO connection" }));
    expect(await screen.findByText("SSO connection created")).toBeInTheDocument();
    expect(createSSOConnection).toHaveBeenCalledWith({ displayName: "Launch SSO", protocol: "saml", identityProvider: "generic" });
    await user.click(screen.getByRole("button", { name: "Test Corporate SAML" }));
    expect(testSSOConnection).toHaveBeenCalledWith("saml-connection-live-a");
    await user.click(screen.getByRole("button", { name: "Delete Corporate SCIM" }));
    expect(deleteSCIMConnection).toHaveBeenCalledWith("scim-connection-live-a");
  });

  it("renders explicit empty member and role states", async () => {
    render(<IdentityAccessView api={fixtureAPI({ listMembers: async () => [], listRoles: async () => [] })} />);
    expect(await screen.findByText("No members")).toBeInTheDocument();
    expect(screen.getByText("No roles")).toBeInTheDocument();
  });

  it("renders one stable product error and atomically changes a member role", async () => {
    const user = userEvent.setup();
    const updateMemberRole = vi.fn(fixtureAPI().updateMemberRole);
    render(<IdentityAccessView api={fixtureAPI({ updateMemberRole, listRoles: async () => [{ role: "organization_admin", permissions: ["view"] }, { role: "read_only_viewer", permissions: ["view"] }] })} />);
    await user.selectOptions(await screen.findByLabelText("Role for member-live-a"), "read_only_viewer");
    await user.click(screen.getByRole("button", { name: "Update role" }));
    expect(await screen.findByRole("status")).toHaveTextContent("active sessions revoked");
    expect(updateMemberRole).toHaveBeenCalledWith("pid_member", "read_only_viewer", 1);

    render(<IdentityAccessView api={fixtureAPI({ listMembers: async () => { throw new Error("provider detail"); } })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Identity data could not be loaded");
  });
});

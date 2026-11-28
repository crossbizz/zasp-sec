import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { IdentityAccessView, type IdentityAdminAPI } from "./IdentityAccessView";

function fixtureAPI(overrides: Partial<IdentityAdminAPI> = {}): IdentityAdminAPI {
  return {
    listInvitations: async () => [],
    inviteMember: async input => ({ ...input, id: "invitation", status: "pending", workspace_id: "workspace", environment_id: "environment" }),
    updateMemberProfile: async (id, displayName, version) => ({ id, memberReference: "member-live-a", role: "organization_admin", active: true, displayName, version: version + 1 }),
    removeMember: async (id, version) => ({ id, memberReference: "member-live-a", role: "organization_admin", active: false, version: version + 1 }),
    memberAccess: async () => [],
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
  it("focuses a bookmarked section after the authorized identity reads complete", async () => {
    const original = window.location.href;
    try {
      window.history.replaceState({}, "", "/administration/identity-access#identity-provider");
      render(<IdentityAccessView api={fixtureAPI()} />);
      const target = await screen.findByRole("heading", { name: "Enterprise identity" });
      await waitFor(() => expect(target).toHaveFocus());
    } finally {
      window.history.replaceState({}, "", original);
    }
  });

  it("moves keyboard focus into the editor for the selected group", async () => {
    render(<IdentityAccessView api={fixtureAPI()} />);
    const edit = await screen.findByRole("button", { name: /^Edit scim-group-/ });
    await userEvent.click(edit);
    expect(screen.getByLabelText("Stytch SCIM group ID")).toHaveFocus();
    expect(screen.getByLabelText("Stytch SCIM group ID")).toHaveValue("scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31");
  });

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
		fireEvent.change(await screen.findByLabelText("Stytch SCIM group ID"), { target: { value: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c32" } });
		fireEvent.change(screen.getByLabelText("Workspace ID"), { target: { value: "pid_workspace" } });
		fireEvent.change(screen.getByLabelText("Environment ID"), { target: { value: "pid_environment" } });
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
    fireEvent.change(await screen.findByLabelText("SSO display name"), { target: { value: "Launch SSO" } });
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
    await user.click(await screen.findByRole("button", { name: "Manage member-live-a" }));
    await user.selectOptions(screen.getByLabelText("Organization role"), "read_only_viewer");
    await user.click(screen.getByRole("button", { name: "Update role" }));
    expect(await screen.findByRole("status")).toHaveTextContent("active sessions revoked");
    expect(updateMemberRole).toHaveBeenCalledWith("pid_member", "read_only_viewer", 1);

    render(<IdentityAccessView api={fixtureAPI({ listMembers: async () => { throw new Error("provider detail"); } })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Members could not be loaded");
    expect(screen.queryByText("provider detail")).not.toBeInTheDocument();
  });
  it("searches human-readable identities, edits the selected profile, and displays its access", async () => {
    const user = userEvent.setup();
    const api = fixtureAPI();
    const [original] = await api.listMembers();
    const member = { ...original, displayName: "Jordan Fox", email: "jordan@example.test" };
    const updateMemberProfile = vi.fn(async (_id: string, displayName: string, version: number) => ({ ...member, displayName, version: version + 1 }));
    const memberAccess = vi.fn(async () => [{ workspace_id: "ws-1", environment_id: "env-2", workspace_name: "Payments", environment_name: "Staging", role: "security_engineer" as const, permissions: ["view" as const] }]);
    render(<IdentityAccessView api={fixtureAPI({ listMembers: async () => [member, { ...original, id: "legacy", memberReference: "legacy-id" }], updateMemberProfile, memberAccess })} />);
    const search = await screen.findByRole("searchbox", { name: "Search members" });
    fireEvent.change(search, { target: { value: "JORDAN@" } });
    const directory = screen.getByRole("table", { name: "Organization members" });
    expect(within(directory).getByText("Jordan Fox")).toBeVisible();
    expect(within(directory).queryByText("legacy-id")).toBeNull();
    await user.click(within(directory).getByRole("button", { name: "Manage Jordan Fox" }));
    await user.click(screen.getByRole("tab", { name: "Workspace access" }));
    expect(await screen.findByText("Payments / Staging")).toBeVisible();
    expect(memberAccess).toHaveBeenCalledWith(member.id);
    await user.click(screen.getByRole("tab", { name: "Profile and role" }));
    await user.clear(screen.getByLabelText("Display name"));
    fireEvent.change(screen.getByLabelText("Display name"), { target: { value: "Jordan Smith" } });
    await user.click(screen.getByRole("button", { name: "Save name" }));
    expect(updateMemberProfile).toHaveBeenCalledWith(member.id, "Jordan Smith", member.version);
    expect(await screen.findByText("Jordan Smith")).toBeVisible();
  });

  it("sends an invitation with an explicit role and reloads its durable status", async () => {
    const user = userEvent.setup();
    const inviteMember = vi.fn(fixtureAPI().inviteMember);
    const listInvitations = vi.fn(async () => [await inviteMember.mock.results[0].value]);
    render(<IdentityAccessView api={fixtureAPI({ inviteMember, listInvitations })} />);
    await user.click(await screen.findByRole("button", { name: "Invite member" }));
    const dialog = screen.getByRole("dialog", { name: "Invite member" });
    expect(within(dialog).getByRole("button", { name: "Send invitation" })).toBeDisabled();
    fireEvent.change(within(dialog).getByLabelText("Email address"), { target: { value: "jordan@example.test" } });
    fireEvent.change(within(dialog).getByLabelText("Display name"), { target: { value: "Jordan Smith" } });
    await user.selectOptions(within(dialog).getByLabelText("Initial role"), "organization_admin");
    await user.click(within(dialog).getByRole("button", { name: "Send invitation" }));
    expect(inviteMember).toHaveBeenCalledWith({ email: "jordan@example.test", display_name: "Jordan Smith", role: "organization_admin" });
    expect(await screen.findByText("Pending")).toBeVisible();
    expect(listInvitations).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("status")).toHaveTextContent("Invitation pending for jordan@example.test.");
  });

  it("requires confirmation before removing access and keeps a failed removal visible for retry", async () => {
    const user = userEvent.setup();
    const removeMember = vi.fn(fixtureAPI().removeMember).mockRejectedValueOnce(new Error("private provider error"));
    render(<IdentityAccessView api={fixtureAPI({ removeMember })} />);
    await user.click(await screen.findByRole("button", { name: "Manage member-live-a" }));
    await user.click(screen.getByRole("button", { name: "Remove from organization" }));
    expect(removeMember).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(removeMember).not.toHaveBeenCalled();
    await user.click(screen.getByRole("button", { name: "Remove from organization" }));
    await user.click(screen.getByRole("button", { name: "Confirm removal" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("could not be confirmed");
    expect(screen.queryByText("private provider error")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm removal" }));
    expect(removeMember).toHaveBeenCalledWith("pid_member", 1);
    expect(await screen.findByText("Disabled")).toBeVisible();
  });

});

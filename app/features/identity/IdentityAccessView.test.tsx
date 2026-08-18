import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { IdentityAccessView, type IdentityAdminAPI } from "./IdentityAccessView";

function fixtureAPI(overrides: Partial<IdentityAdminAPI> = {}): IdentityAdminAPI {
  return {
    listMembers: async () => [{ id: "pid_member", memberReference: "member-live-a", role: "organization_admin", active: true }],
    listRoles: async () => [{ role: "organization_admin", permissions: ["view", "manage_identity"] }],
    listSSO: async () => [{ id: "saml-connection-live-a", displayName: "Corporate SAML", status: "active", protocol: "saml", identityProvider: "generic" }],
    createSSO: async () => ({ id: "saml-connection-live-created", displayName: "New SSO", status: "pending", protocol: "saml", identityProvider: "generic" }),
    testSSO: async () => undefined,
    deleteSSO: async () => undefined,
    listSCIM: async () => [{ id: "scim-connection-live-a", displayName: "Corporate SCIM", status: "active", identityProvider: "generic", baseUrl: "https://scim.example.invalid/v2" }],
    createSCIM: async () => ({ id: "scim-connection-live-created", displayName: "New SCIM", status: "active", identityProvider: "generic", baseUrl: "https://scim.example.invalid/v2", bearerToken: "scim_bearer_token_once" }),
    deleteSCIM: async () => undefined,
    listGroupMappings: async () => [{ groupReference: "idp-group-engineering", role: "security_engineer", workspaceId: "pid_workspace", environmentId: "pid_environment", version: 1 }],
    updateGroupMapping: async (input) => ({ ...input, version: input.expectedVersion + 1 }),
    ...overrides,
  };
}

describe("Identity & Access product surface", () => {
  it("renders all five API-backed sections with loaded state", async () => {
    render(<IdentityAccessView api={fixtureAPI()} />);
    expect(screen.getByText("Loading identity and access…")).toBeInTheDocument();
    for (const label of ["Members", "Built-in roles", "SSO connections", "SCIM provisioning", "Group mappings"]) {
      expect(await screen.findByRole("heading", { name: label })).toBeInTheDocument();
      expect(screen.getByRole("link", { name: label })).toHaveAttribute("href", expect.stringMatching(/^#identity-/));
    }
    expect(screen.getByText("Corporate SAML")).toBeInTheDocument();
    expect(screen.getByText("Corporate SCIM")).toBeInTheDocument();
    expect(screen.getByText("idp-group-engineering")).toBeInTheDocument();
  });

  it("renders explicit empty member and role states", async () => {
    render(<IdentityAccessView api={fixtureAPI({ listMembers: async () => [], listRoles: async () => [] })} />);
    expect(await screen.findByText("No members")).toBeInTheDocument();
    expect(screen.getByText("No roles")).toBeInTheDocument();
  });

  it("renders one stable product error and supports SSO test success", async () => {
    const user = userEvent.setup();
    const testSSO = vi.fn(async () => undefined);
    render(<IdentityAccessView api={fixtureAPI({ testSSO })} />);
    await user.click(await screen.findByRole("button", { name: "Test Corporate SAML" }));
    expect(await screen.findByRole("status")).toHaveTextContent("SSO connection is healthy");
    expect(testSSO).toHaveBeenCalledWith("saml-connection-live-a");

    render(<IdentityAccessView api={fixtureAPI({ listMembers: async () => { throw new Error("provider detail"); } })} />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Identity data could not be loaded");
  });

  it("creates and confirms SCIM, then validates and saves one group mapping", async () => {
    const user = userEvent.setup();
    const updateGroupMapping = vi.fn(fixtureAPI().updateGroupMapping);
    render(<IdentityAccessView api={fixtureAPI({ updateGroupMapping })} />);
    await screen.findByText("Corporate SCIM");

    await user.clear(screen.getByLabelText("SCIM display name"));
    await user.type(screen.getByLabelText("SCIM display name"), "Engineering SCIM");
    await user.click(screen.getByRole("button", { name: "Create SCIM connection" }));
    expect(await screen.findByText("Save this bearer token now: scim_bearer_token_once")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("IdP group reference"));
    await user.click(screen.getByRole("button", { name: "Save group mapping" }));
    expect(screen.getByText("Enter a valid IdP group reference")).toBeInTheDocument();
    await user.type(screen.getByRole("textbox", { name: /IdP group reference/ }), "idp-group-platform");
    await user.click(screen.getByRole("button", { name: "Save group mapping" }));
    await waitFor(() => expect(updateGroupMapping).toHaveBeenCalledWith(expect.objectContaining({ groupReference: "idp-group-platform" })));
  });
});

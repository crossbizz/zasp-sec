import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { IdentityAccessView, type IdentityAdminAPI } from "./IdentityAccessView";

function fixtureAPI(overrides: Partial<IdentityAdminAPI> = {}): IdentityAdminAPI {
  return {
    listMembers: async () => [{ id: "pid_member", memberReference: "member-live-a", role: "organization_admin", active: true, version: 1 }],
    updateMemberRole: async (id, role, version) => ({ id, memberReference: "member-live-a", role, active: true, version: version + 1 }),
    listRoles: async () => [{ role: "organization_admin", permissions: ["view", "manage_identity"] }],
    ...overrides,
  };
}

describe("Identity & Access product surface", () => {
  it("renders durable identity sections and an honest unavailable provider state", async () => {
    render(<IdentityAccessView api={fixtureAPI()} />);
    expect(screen.getByText("Loading identity and access…")).toBeInTheDocument();
    for (const label of ["Members", "Built-in roles", "Enterprise identity", "Group mappings"]) {
      expect(await screen.findByRole("heading", { name: label })).toBeInTheDocument();
      expect(screen.getByRole("link", { name: label })).toHaveAttribute("href", expect.stringMatching(/^#identity-/));
    }
    expect(screen.getAllByText("Unavailable")).toHaveLength(2);
    expect(screen.queryByRole("button", { name: /SSO|SCIM/ })).not.toBeInTheDocument();
    expect(screen.getByText(/hidden until verified provider group claims/i)).toBeInTheDocument();
    expect(screen.queryByLabelText("IdP group reference")).not.toBeInTheDocument();
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

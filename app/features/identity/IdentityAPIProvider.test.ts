import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import { createIdentityAdminAPI } from "./IdentityAPIProvider";

const ok = (data: unknown, status = 200) => ({ data, response: new Response(JSON.stringify(data), { status }) });
const page = (items: unknown[]) => ({ items, page_info: { next_cursor: null, has_more: false } });

describe("production identity provider administration API", () => {
  it("strictly maps tenant connection pages and sends fresh mutation authority", async () => {
    const GET = vi.fn(async (path: string) => path.includes("group-mappings")
			? ok(page([{ group_reference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", role: "security_engineer", workspace_id: "pid_10000001-0000-4000-8000-000000000001", environment_id: "pid_10000002-0000-4000-8000-000000000002", version: 1 }]))
			: path.includes("sso")
        ? ok(page([{ id: "saml-connection-live-a", status: "active", display_name: "Corporate SAML", protocol: "saml", identity_provider: "okta" }]))
        : ok(page([{ id: "scim-connection-live-a", status: "active", display_name: "Corporate SCIM", identity_provider: "okta", base_url: "https://scim.stytch.com/v2/live-a" }])));
    const POST = vi.fn(async (path: string) => path.includes("scim")
      ? ok({ id: "scim-connection-created", status: "active", display_name: "SCIM", identity_provider: "okta", base_url: "https://scim.stytch.com/v2/created", bearer_token: "scim_bearer_token_live", audit_correlation_id: "pid_10000001-0000-4000-8000-000000000001" }, 201)
      : ok({ id: "saml-connection-created", status: "pending", display_name: "SSO", protocol: "saml", identity_provider: "okta", audit_correlation_id: "pid_10000001-0000-4000-8000-000000000001" }, 201));
    const DELETE = vi.fn(async (_path: string, options: { params: { path: { id: string }; header: Record<string, string> } }) => ok({ id: options.params.path.id, audit_correlation_id: "pid_10000001-0000-4000-8000-000000000001" }));
		const PATCH = vi.fn(async () => ok({ group_reference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", role: "security_engineer", workspace_id: "pid_10000001-0000-4000-8000-000000000001", environment_id: "pid_10000002-0000-4000-8000-000000000002", version: 2, audit_correlation_id: "pid_10000003-0000-4000-8000-000000000003" }));
    const api = createIdentityAdminAPI({ GET, POST, DELETE, PATCH } as unknown as APIClient);

    await expect(api.listSSOConnections()).resolves.toMatchObject([{ displayName: "Corporate SAML", protocol: "saml" }]);
    await expect(api.listSCIMConnections()).resolves.toMatchObject([{ displayName: "Corporate SCIM", baseURL: "https://scim.stytch.com/v2/live-a" }]);
		await expect(api.listGroupMappings()).resolves.toMatchObject([{ groupReference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", role: "security_engineer", version: 1 }]);
		await expect(api.updateGroupMapping({ groupReference: "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c31", role: "security_engineer", workspaceID: "pid_10000001-0000-4000-8000-000000000001", environmentID: "pid_10000002-0000-4000-8000-000000000002", expectedVersion: 1 })).resolves.toMatchObject({ version: 2 });
    await api.createSSOConnection({ displayName: "SSO", protocol: "saml", identityProvider: "okta" });
    await api.createSCIMConnection({ displayName: "SCIM", identityProvider: "okta" });
    await api.deleteSSOConnection("saml-connection-live-a");

    for (const call of [...POST.mock.calls, ...DELETE.mock.calls]) {
      const options = call[1];
      expect(options?.params.header).toMatchObject({ "Idempotency-Key": expect.stringMatching(/^identity_/), "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" });
    }
  });

  it("reuses the exact idempotency key after an interrupted provider response", async () => {
    const keys: string[] = [];
    const POST = vi.fn(async (_path: string, options: { params: { header: { "Idempotency-Key": string } } }) => {
      keys.push(options.params.header["Idempotency-Key"]);
      if (keys.length === 1) throw new Error("lost response");
      return ok({ id: "saml-connection-created", status: "pending", display_name: "SSO", protocol: "saml", identity_provider: "okta", audit_correlation_id: "pid_10000001-0000-4000-8000-000000000001" }, 201);
    });
    const api = createIdentityAdminAPI({ POST } as unknown as APIClient);
    const input = { displayName: "SSO", protocol: "saml" as const, identityProvider: "okta" };
    await expect(api.createSSOConnection(input)).rejects.toThrow("lost response");
    await expect(api.createSSOConnection(input)).resolves.toMatchObject({ id: "saml-connection-created" });
    expect(keys).toHaveLength(2);
    expect(new Set(keys).size).toBe(1);
  });
  it("sends versioned member changes and enforces the member ID on access responses", async () => {
    const id = "pid_10000001-0000-4000-8000-000000000001";
    const otherID = "pid_10000002-0000-4000-8000-000000000002";
    const member = { id, organization_id: otherID, organization_reference: "org", member_reference: "member-1", role: "read_only_viewer", active: true, display_name: "Jordan", email: "jordan@example.test", version: 8 };
    const PATCH = vi.fn().mockResolvedValue(ok(member));
    const DELETE = vi.fn().mockResolvedValue(ok({ ...member, active: false }));
    const GET = vi.fn()
      .mockResolvedValueOnce(ok(page([member])))
      .mockResolvedValueOnce(ok({ member_id: id, items: [] }))
      .mockResolvedValueOnce(ok({ member_id: otherID, items: [] }));
    const api = createIdentityAdminAPI({ GET, DELETE, PATCH } as unknown as APIClient);
    await expect(api.listMembers()).resolves.toMatchObject([{ displayName: "Jordan", email: "jordan@example.test" }]);
    await expect(api.updateMemberProfile(id, "Jordan", 7)).resolves.toMatchObject({ version: 8 });
    const params = { path: { id }, header: { "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed", "If-Match": '"7"' } };
    expect(PATCH).toHaveBeenCalledWith("/api/v1/admin/members/{id}/profile", { params, body: { display_name: "Jordan" } });
    await expect(api.removeMember(id, 7)).resolves.toMatchObject({ active: false });
    expect(DELETE).toHaveBeenCalledWith("/api/v1/admin/members/{id}", { params });
    await expect(api.memberAccess(id)).resolves.toEqual([]);
    await expect(api.memberAccess(id)).rejects.toThrow("does not match");
  });

  it("recovers an interrupted invitation with the same idempotency key and reads all invitation pages", async () => {
    const input = { email: "jordan@example.test", display_name: "Jordan", role: "security_engineer" as const };
    const id = "pid_10000001-0000-4000-8000-000000000001";
    const invitation = { id, ...input, workspace_id: id, environment_id: id, status: "pending" };
    const POST = vi.fn().mockRejectedValueOnce(new Error("lost response")).mockResolvedValueOnce(ok(invitation, 201));
    const GET = vi.fn().mockResolvedValueOnce(ok({ items: [], page_info: { has_more: true, next_cursor: "next" } })).mockResolvedValueOnce(ok(page([invitation])));
    const api = createIdentityAdminAPI({ GET, POST } as unknown as APIClient);
    await expect(api.inviteMember(input)).rejects.toThrow("lost response");
    await expect(api.inviteMember(input)).resolves.toEqual(invitation);
    const headers = POST.mock.calls[0][1].params.header;
    expect(headers).toMatchObject({ "X-Zasp-Fresh-Auth": "confirmed", "X-CSRF-Token": "", "Idempotency-Key": expect.stringMatching(/^identity_/) });
    expect(POST.mock.calls[1]).toEqual(["/api/v1/admin/member-invitations", { params: { header: headers }, body: input }]);
    await expect(api.listInvitations()).resolves.toEqual([invitation]);
    expect(GET.mock.calls[1][1].params.query).toMatchObject({ cursor: "next" });
  });

});

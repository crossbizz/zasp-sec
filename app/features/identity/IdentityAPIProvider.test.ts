import { describe, expect, it, vi } from "vitest";

import type { APIClient } from "../../../apps/web/api/client";
import { createIdentityAdminAPI } from "./IdentityAPIProvider";

const ok = (data: unknown, status = 200) => ({ data, response: new Response(JSON.stringify(data), { status }) });
const page = (items: unknown[]) => ({ items, page_info: { next_cursor: null, has_more: false } });

describe("production identity provider administration API", () => {
  it("strictly maps tenant connection pages and sends fresh mutation authority", async () => {
    const GET = vi.fn(async (path: string) => path.includes("sso")
      ? ok(page([{ id: "saml-connection-live-a", status: "active", display_name: "Corporate SAML", protocol: "saml", identity_provider: "okta" }]))
      : ok(page([{ id: "scim-connection-live-a", status: "active", display_name: "Corporate SCIM", identity_provider: "okta", base_url: "https://scim.stytch.com/v2/live-a" }])));
    const POST = vi.fn(async (path: string) => path.includes("scim")
      ? ok({ id: "scim-connection-created", status: "active", display_name: "SCIM", identity_provider: "okta", base_url: "https://scim.stytch.com/v2/created", bearer_token: "scim_bearer_token_live", audit_correlation_id: "pid_10000001-0000-4000-8000-000000000001" }, 201)
      : ok({ id: "saml-connection-created", status: "pending", display_name: "SSO", protocol: "saml", identity_provider: "okta", audit_correlation_id: "pid_10000001-0000-4000-8000-000000000001" }, 201));
    const DELETE = vi.fn(async (_path: string, options: { params: { path: { id: string }; header: Record<string, string> } }) => ok({ id: options.params.path.id, audit_correlation_id: "pid_10000001-0000-4000-8000-000000000001" }));
    const api = createIdentityAdminAPI({ GET, POST, DELETE } as unknown as APIClient);

    await expect(api.listSSOConnections()).resolves.toMatchObject([{ displayName: "Corporate SAML", protocol: "saml" }]);
    await expect(api.listSCIMConnections()).resolves.toMatchObject([{ displayName: "Corporate SCIM", baseURL: "https://scim.stytch.com/v2/live-a" }]);
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
});

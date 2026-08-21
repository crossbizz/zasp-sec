"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";

import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import type {
  BuiltInRolePage,
  ConnectionDeletion,
  ConnectionTest,
  GroupMapping,
  GroupMappingInput,
  GroupMappingPage,
  Principal,
  PrincipalPage,
  ScimConnectionCredential,
  ScimConnectionInput,
  ScimConnectionPage,
  SsoConnectionInput,
  SsoConnectionMutation,
  SsoConnectionPage,
} from "../../../apps/web/api/generated";
import { decodeBuiltInRolePage, decodeConnectionDeletion, decodeConnectionTest, decodeGroupMapping, decodeGroupMappingPage, decodePrincipal, decodePrincipalPage, decodeSCIMConnectionCredential, decodeSCIMConnectionPage, decodeSSOConnectionMutation, decodeSSOConnectionPage } from "../../../apps/web/api/administration-decoders";
import type { IdentityAdminAPI } from "./IdentityAccessView";

const IdentityAPIContext = createContext<IdentityAdminAPI | null>(null);

export function createIdentityAdminAPI(client: APIClient): IdentityAdminAPI {
  const pendingKeys = new Map<string, string>();
  const mutation = async <T,>(binding: string, call: (key: string) => Promise<T>): Promise<T> => {
    const key = pendingKeys.get(binding) ?? `identity_${globalThis.crypto.randomUUID()}`;
    pendingKeys.set(binding, key);
    const result = await call(key);
    pendingKeys.delete(binding);
    return result;
  };
  return {
    async listMembers() {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<PrincipalPage>(await client.GET("/api/v1/admin/members", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodePrincipalPage), { maximumItems: 2_000, maximumPages: 20 });
      return loaded.items.map((item) => ({ id: item.id, memberReference: item.member_reference, role: item.role, active: item.active, version: item.version ?? 1 }));
    },
    async updateMemberRole(id, role, version) {
      const item = requireAPIData<Principal>(await client.PATCH("/api/v1/admin/members/{id}", { params: { path: { id }, header: { "X-CSRF-Token": "", "If-Match": `"${version}"` } }, body: { role: role as Principal["role"] } }), decodePrincipal);
      return { id: item.id, memberReference: item.member_reference, role: item.role, active: item.active, version: item.version ?? version + 1 };
    },
    async listRoles() {
      const page = requireAPIData<BuiltInRolePage>(await client.GET("/api/v1/admin/roles"), decodeBuiltInRolePage);
      return page.items.map((item) => ({ role: item.role, permissions: [...item.permissions] }));
    },
    async listSSOConnections() {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<SsoConnectionPage>(await client.GET("/api/v1/admin/sso-connections", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeSSOConnectionPage), { maximumItems: 2_000, maximumPages: 20 });
      return loaded.items.map((item) => ({ id: item.id, status: item.status, displayName: item.display_name, protocol: item.protocol, identityProvider: item.identity_provider }));
    },
    async createSSOConnection(input) {
      const body: SsoConnectionInput = { display_name: input.displayName, protocol: input.protocol, identity_provider: input.identityProvider as SsoConnectionInput["identity_provider"] };
      const item = await mutation(`create-sso:${JSON.stringify(body)}`, async (key) => requireAPIData<SsoConnectionMutation>(await client.POST("/api/v1/admin/sso-connections", { params: { header: identityMutationHeaders(key) }, body }), decodeSSOConnectionMutation));
      return { id: item.id, status: item.status, displayName: item.display_name, protocol: item.protocol, identityProvider: item.identity_provider };
    },
    async deleteSSOConnection(id) {
      await mutation(`delete-sso:${id}`, async (key) => requireAPIData<ConnectionDeletion>(await client.DELETE("/api/v1/admin/sso-connections/{id}", { params: { path: { id }, header: identityMutationHeaders(key) } }), decodeConnectionDeletion));
    },
    async testSSOConnection(id) {
      await mutation(`test-sso:${id}`, async (key) => requireAPIData<ConnectionTest>(await client.POST("/api/v1/admin/sso-connections/{id}/test", { params: { path: { id }, header: identityMutationHeaders(key) }, body: {} }), decodeConnectionTest));
    },
    async listSCIMConnections() {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<ScimConnectionPage>(await client.GET("/api/v1/admin/scim-connections", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeSCIMConnectionPage), { maximumItems: 2_000, maximumPages: 20 });
      return loaded.items.map((item) => ({ id: item.id, status: item.status, displayName: item.display_name, identityProvider: item.identity_provider, baseURL: item.base_url }));
    },
    async createSCIMConnection(input) {
      const body: ScimConnectionInput = { display_name: input.displayName, identity_provider: input.identityProvider as ScimConnectionInput["identity_provider"] };
      const item = await mutation(`create-scim:${JSON.stringify(body)}`, async (key) => requireAPIData<ScimConnectionCredential>(await client.POST("/api/v1/admin/scim-connections", { params: { header: identityMutationHeaders(key) }, body }), decodeSCIMConnectionCredential));
      return { id: item.id, status: item.status, displayName: item.display_name, identityProvider: item.identity_provider, baseURL: item.base_url, bearerToken: item.bearer_token };
    },
    async deleteSCIMConnection(id) {
      await mutation(`delete-scim:${id}`, async (key) => requireAPIData<ConnectionDeletion>(await client.DELETE("/api/v1/admin/scim-connections/{id}", { params: { path: { id }, header: identityMutationHeaders(key) } }), decodeConnectionDeletion));
    },
    async listGroupMappings() {
      const loaded = await loadAllCursorPages(async (cursor) => requireAPIData<GroupMappingPage>(await client.GET("/api/v1/admin/group-mappings", { params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } } }), decodeGroupMappingPage), { maximumItems: 2_000, maximumPages: 20 });
      return loaded.items.map(groupMapping);
    },
    async updateGroupMapping(input) {
      const body: GroupMappingInput = { group_reference: input.groupReference, role: input.role as GroupMappingInput["role"], workspace_id: input.workspaceID, environment_id: input.environmentID, expected_version: input.expectedVersion };
      return groupMapping(requireAPIData<GroupMapping>(await client.PATCH("/api/v1/admin/group-mappings", { params: { header: { "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" } }, body }), decodeGroupMapping));
    },
  };
}

function groupMapping(item: GroupMapping) {
  return { groupReference: item.group_reference, role: item.role, workspaceID: item.workspace_id, environmentID: item.environment_id, version: item.version };
}

function identityMutationHeaders(key: string): { "Idempotency-Key": string; "X-CSRF-Token": string; "X-Zasp-Fresh-Auth": "confirmed" } {
  return { "Idempotency-Key": key, "X-CSRF-Token": "", "X-Zasp-Fresh-Auth": "confirmed" };
}

export function IdentityAPIProvider({ children, api, client }: { children: ReactNode; api?: IdentityAdminAPI; client?: APIClient }) {
  const value = useMemo(() => api ?? (client ? createIdentityAdminAPI(client) : null), [api, client]);
  return <IdentityAPIContext.Provider value={value}>{children}</IdentityAPIContext.Provider>;
}

export function useIdentityAdminAPI(): IdentityAdminAPI {
  const value = useContext(IdentityAPIContext);
  if (!value) throw new Error("IdentityAccessView requires IdentityAPIProvider or an explicit API");
  return value;
}

export function useOptionalIdentityAdminAPI(): IdentityAdminAPI | null {
  return useContext(IdentityAPIContext);
}

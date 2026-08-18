"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";

import { createAPIClient, type APIClient } from "../../../apps/web/api/client";
import type {
  BuiltInRolePage,
  GroupMapping,
  GroupMappingPage,
  PrincipalPage,
  ScimConnectionCredential,
  ScimConnectionPage,
  SsoConnectionMutation,
  SsoConnectionPage,
} from "../../../apps/web/api/generated";
import type { IdentityAdminAPI } from "./IdentityAccessView";

const IdentityAPIContext = createContext<IdentityAdminAPI | null>(null);

function requireData<T>(value: { data?: unknown; error?: unknown }): T {
  if (value.error || value.data === undefined) throw new Error("product API rejected");
  return value.data as T;
}

export function createIdentityAdminAPI(client: APIClient): IdentityAdminAPI {
  return {
    async listMembers() {
      const page = requireData<PrincipalPage>(await client.GET("/api/v1/admin/members"));
      return page.items.map((item) => ({ id: item.id, memberReference: item.member_reference, role: item.role, active: item.active }));
    },
    async listRoles() {
      const page = requireData<BuiltInRolePage>(await client.GET("/api/v1/admin/roles"));
      return page.items.map((item) => ({ role: item.role, permissions: [...item.permissions] }));
    },
    async listSSO() {
      const page = requireData<SsoConnectionPage>(await client.GET("/api/v1/admin/sso-connections"));
      return page.items.map((item) => ({ id: item.id, displayName: item.display_name, status: item.status, protocol: item.protocol, identityProvider: item.identity_provider }));
    },
    async createSSO(input) {
      const item = requireData<SsoConnectionMutation>(await client.POST("/api/v1/admin/sso-connections", { body: { display_name: input.displayName, protocol: input.protocol as "saml" | "oidc", identity_provider: input.identityProvider as "generic" } }));
      return { id: item.id, displayName: item.display_name, status: item.status, protocol: item.protocol, identityProvider: item.identity_provider };
    },
    async testSSO(id) { requireData(await client.POST("/api/v1/admin/sso-connections/{id}/test", { params: { path: { id } } })); },
    async deleteSSO(id) { requireData(await client.DELETE("/api/v1/admin/sso-connections/{id}", { params: { path: { id } } })); },
    async listSCIM() {
      const page = requireData<ScimConnectionPage>(await client.GET("/api/v1/admin/scim-connections"));
      return page.items.map((item) => ({ id: item.id, displayName: item.display_name, status: item.status, identityProvider: item.identity_provider, baseUrl: item.base_url }));
    },
    async createSCIM(input) {
      const item = requireData<ScimConnectionCredential>(await client.POST("/api/v1/admin/scim-connections", { body: { display_name: input.displayName, identity_provider: input.identityProvider as "generic" } }));
      return { id: item.id, displayName: item.display_name, status: item.status, identityProvider: item.identity_provider, baseUrl: item.base_url, bearerToken: item.bearer_token };
    },
    async deleteSCIM(id) { requireData(await client.DELETE("/api/v1/admin/scim-connections/{id}", { params: { path: { id } } })); },
    async listGroupMappings() {
      const page = requireData<GroupMappingPage>(await client.GET("/api/v1/admin/group-mappings"));
      return page.items.map((item) => ({ groupReference: item.group_reference, role: item.role, workspaceId: item.workspace_id, environmentId: item.environment_id, version: item.version }));
    },
    async updateGroupMapping(input) {
      const item = requireData<GroupMapping>(await client.PATCH("/api/v1/admin/group-mappings", { body: {
        group_reference: input.groupReference, role: input.role as "read_only_viewer", workspace_id: input.workspaceId,
        environment_id: input.environmentId, expected_version: input.expectedVersion,
      } }));
      return { groupReference: item.group_reference, role: item.role, workspaceId: item.workspace_id, environmentId: item.environment_id, version: item.version };
    },
  };
}

export function IdentityAPIProvider({ children, api }: { children: ReactNode; api?: IdentityAdminAPI }) {
  const value = useMemo(() => api ?? createIdentityAdminAPI(createAPIClient()), [api]);
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

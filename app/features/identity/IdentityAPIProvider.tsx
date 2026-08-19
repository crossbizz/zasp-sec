"use client";

import { createContext, useContext, useMemo, type ReactNode } from "react";

import { requireAPIData, type APIClient } from "../../../apps/web/api/client";
import { loadAllCursorPages } from "../../../apps/web/api/pagination";
import type {
  BuiltInRolePage,
  Principal,
  PrincipalPage,
} from "../../../apps/web/api/generated";
import { decodeBuiltInRolePage, decodePrincipal, decodePrincipalPage } from "../../../apps/web/api/administration-decoders";
import type { IdentityAdminAPI } from "./IdentityAccessView";

const IdentityAPIContext = createContext<IdentityAdminAPI | null>(null);

export function createIdentityAdminAPI(client: APIClient): IdentityAdminAPI {
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
  };
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

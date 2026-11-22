import { frameworkNames, type CatalogFramework, type EditionKey } from "../../apps/web/api/framework-coverage";
import type { ActivityScope } from "./activity-links";

export type CatalogTarget = EditionKey & { upstream_id: string };
type Parsed = { state: "selected"; target: CatalogTarget } | { state: "invalid" | "scope_mismatch" | "none" };

const pid = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const label = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

export function catalogLink(target: CatalogTarget, scope: ActivityScope): string {
  if (!Object.hasOwn(frameworkNames, target.framework) || !label.test(target.edition) || !label.test(target.upstream_id) ||
      ![scope.organizationID, scope.workspaceID, scope.environmentID].every(id => pid.test(id))) throw new Error("Invalid catalog reference");
  const query = new URLSearchParams({
    catalog: target.framework, edition: target.edition, control: target.upstream_id,
    organization_id: scope.organizationID, workspace_id: scope.workspaceID, environment_id: scope.environmentID,
  });
  return "/compliance/evidence?" + query;
}

export function parseCatalogLink(location: string, scope: ActivityScope): Parsed {
  if (!location.startsWith("/compliance/evidence?catalog=")) return { state: "none" };
  const query = new URLSearchParams(location.slice(location.indexOf("?") + 1));
  const framework = query.get("catalog");
  if (!framework || !Object.hasOwn(frameworkNames, framework)) return { state: "invalid" };
  const target: CatalogTarget = { framework: framework as CatalogFramework, edition: query.get("edition") ?? "", upstream_id: query.get("control") ?? "" };
  const linkedScope = { organizationID: query.get("organization_id") ?? "", workspaceID: query.get("workspace_id") ?? "", environmentID: query.get("environment_id") ?? "" };
  try {
    if (catalogLink(target, linkedScope) !== location) return { state: "invalid" };
  } catch { return { state: "invalid" }; }
  if (linkedScope.organizationID !== scope.organizationID || linkedScope.workspaceID !== scope.workspaceID || linkedScope.environmentID !== scope.environmentID) return { state: "scope_mismatch" };
  return { state: "selected", target };
}

import {parseRedTeamStatusLink} from "./red-team-status-link";
import { parseRecoveryLink } from "./recovery-links";
import { parseAuditExportLink } from "../features/administration/audit-export-resume";
import { scopedAddonFromSearch } from "./addon-links";

export const calibrationLocation = "/protect/guardrails?tab=calibration";
export const calibrationExportLocation = `${calibrationLocation}#calibration-exports`;

export type ActivityScope = Readonly<{ organizationID: string; workspaceID: string; environmentID: string }>;
export type ActivityKind = "finding" | "attack_path" | "session" | "audit" | "run" | "test_run" | "attack_lab_run" | "purpose" | "approval" | "policy_draft";
export type ActivityTarget = Readonly<{ kind: ActivityKind; id: string }>;
export type ActivityLinkResult = { state: "none" | "invalid" | "scope_mismatch" } | { state: "selected"; target: ActivityTarget };

const routes: Record<ActivityKind, string> = {
  purpose: "/policies",
  approval: "/protect/approvals",
  policy_draft: "/policies",
  finding: "/violations",
  attack_path: "/exposure/attack-paths",
  session: "/investigate/sessions",
  audit: "/administration/audit-log",
  run: "/protect/security-agents",
  test_run: "/red-team/results",
  attack_lab_run: "/test/attack-lab",
};
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const draftID = /^policy-(?:mcp|studio)-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const keys = ["entity_id", "organization_id", "workspace_id", "environment_id"] as const;
const inventoryRoutes = new Set(["/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes"]);
function validScope(scope: ActivityScope): boolean {
  return [scope.organizationID, scope.workspaceID, scope.environmentID].every(value => productID.test(value));
}

export function activityLink(target: ActivityTarget, scope: ActivityScope): string {
  const path = routes[target.kind];
  if (typeof path !== "string" || !(target.kind === "policy_draft" ? draftID : productID).test(target.id) || !validScope(scope)) throw new TypeError("Invalid scoped activity target");
  return `${path}?${new URLSearchParams({ [target.kind === "policy_draft" ? "draft_id" : "entity_id"]: target.id, organization_id: scope.organizationID, workspace_id: scope.workspaceID, environment_id: scope.environmentID })}`;
}

// Parse only canonical relative locations. URL normalization must not turn
// an external, encoded or ambiguous input into a trusted product destination.
// This validates navigation context, not record existence or authorization.
export function parseActivityLink(location: string, scope: ActivityScope & { principalID?: string }): ActivityLinkResult {
  const invalid: ActivityLinkResult = { state: "invalid" };
  if (!validScope(scope)) return invalid;
  const recordStatus=parseRedTeamStatusLink(location,[scope.principalID,scope.organizationID,scope.workspaceID,scope.environmentID].join("/"));
  if(recordStatus.state==="selected")return {state:"none"};
  if(recordStatus.state==="invalid"||recordStatus.state==="scope_mismatch")return {state:recordStatus.state};
  const recovery = parseRecoveryLink(location, scope);
  if (recovery.state === "selected") return {state: "none"};
  if (recovery.state !== "none") return recovery;
  const auditExport = parseAuditExportLink(location, scope.principalID ? { ...scope, principalID: scope.principalID } : null);
  if (auditExport.state === "selected") return { state: "none" };
  if (auditExport.state !== "none") return auditExport;
  if (location === calibrationLocation || location === calibrationExportLocation) return { state: "none" };
  if (!/^\/(?:[a-z0-9/-]*)(?:\?[^?#]*)?$(?![\s\S])/.test(location) || location.startsWith("//") || location.includes("//")) return invalid;
  const separator = location.indexOf("?");
  if (separator < 0) return { state: "none" };
  const path = location.slice(0, separator);
  const query = location.slice(separator + 1);
  // These product surfaces own their existing inventory selector. Delegate only
  // its exact canonical form; mixed or encoded activity keys must still fail.
  if (inventoryRoutes.has(path) && query.startsWith("inventory=") && productID.test(query.slice("inventory=".length))) return { state: "none" };
  if (path === "/integrations/sensors" && query.startsWith("device=") && productID.test(query.slice("device=".length))) return { state: "none" };
  if (path === "/inventory/tools") {
    if (query.startsWith("addon=") && productID.test(query.slice("addon=".length))) return { state: "none" };
    const addon = scopedAddonFromSearch(query, scope.environmentID);
    if (addon?.state === "foreign") return { state: "scope_mismatch" };
    if (addon?.state === "selected" || addon?.state === "version") return { state: "none" };
  }
  const isDraft = path === "/policies" && query.split("&").some(part => part.startsWith("draft_id="));
  const kind = isDraft ? "policy_draft" : (Object.keys(routes) as ActivityKind[]).find(value => routes[value] === path);
  if (!kind) return invalid;
  const entries = query.split("&").map(part => part.split("="));
  const validEntry = ([key, value, extra]: string[]) => {
    if (extra !== undefined || !value) return false;
    if (isDraft && key === "draft_id") return draftID.test(value);
    return keys.some(allowed => key === allowed) && productID.test(value);
  };
  if (entries.length !== keys.length || !entries.every(validEntry)) return invalid;
  const values = new Map(entries.map(([key, value]) => [key, value]));
  if (values.size !== keys.length || (isDraft && values.has("entity_id"))) return invalid;
  if (values.get("organization_id") !== scope.organizationID || values.get("workspace_id") !== scope.workspaceID || values.get("environment_id") !== scope.environmentID) return { state: "scope_mismatch" };
  return { state: "selected", target: { kind, id: values.get(isDraft ? "draft_id" : "entity_id")! } };
}

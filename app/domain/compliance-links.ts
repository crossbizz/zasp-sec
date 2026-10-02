import type { ComplianceEvidenceTarget } from "../../apps/web/api/generated";
import type { ActivityScope } from "./activity-links";
export type ComplianceLinkResult = { state: "none" | "invalid" | "scope_mismatch" } | { state: "selected"; target: ComplianceEvidenceTarget };
const productID = /^pid_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$(?![\s\S])/;
const keys = ["source_kind", "source_id", "source_version", "organization_id", "workspace_id", "environment_id"];
function validTarget(t: ComplianceEvidenceTarget): boolean {
  if (!Number.isSafeInteger(t.source_version) || t.source_version < 1 || t.source_version > 999999999999999) return false;
  switch (t.source_kind) {
    case "policy": return /^policy-[a-z0-9][a-z0-9-]{0,120}$(?![\s\S])/.test(t.source_id);
    case "administration": case "workflow_policy": case "red_team_mutation": return t.source_version === 1 && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$(?![\s\S])/.test(t.source_id);
    case "red_team_test": case "attack_lab_test": return t.source_version <= 5 && productID.test(t.source_id);
    case "finding": case "configuration": return productID.test(t.source_id);
    default: return false;
  }
}
function validScope(s: ActivityScope) { return [s.organizationID, s.workspaceID, s.environmentID].every(v => productID.test(v)); }
export function complianceLink(target: ComplianceEvidenceTarget, scope: ActivityScope): string {
  if (!validTarget(target) || !validScope(scope)) throw new TypeError("Invalid compliance source");
  return `/compliance/evidence?source_kind=${target.source_kind}&source_id=${target.source_id}&source_version=${target.source_version}&organization_id=${scope.organizationID}&workspace_id=${scope.workspaceID}&environment_id=${scope.environmentID}`;
}
export function parseComplianceLink(location: string, scope: ActivityScope): ComplianceLinkResult {
  if (location === "/compliance/evidence" && validScope(scope)) return { state: "none" };
  const invalid: ComplianceLinkResult = { state: "invalid" };
  if (!validScope(scope) || !location.startsWith("/compliance/evidence?") || /[%+#?\s]/.test(location.slice("/compliance/evidence?".length))) return invalid;
  const parts = location.slice("/compliance/evidence?".length).split("&").map(p => p.split("="));
  if (parts.length !== keys.length || parts.some(([k, v, extra]) => !keys.includes(k) || !v || extra !== undefined)) return invalid;
  const fields = Object.fromEntries(parts);
  if (Object.keys(fields).length !== keys.length || !/^[1-9][0-9]*$/.test(fields.source_version)) return invalid;
  const target = { source_kind: fields.source_kind, source_id: fields.source_id, source_version: Number(fields.source_version) } as ComplianceEvidenceTarget;
  if (!validTarget(target) || ![fields.organization_id, fields.workspace_id, fields.environment_id].every(v => productID.test(v))) return invalid;
  if (fields.organization_id !== scope.organizationID || fields.workspace_id !== scope.workspaceID || fields.environment_id !== scope.environmentID) return { state: "scope_mismatch" };
  return { state: "selected", target };
}

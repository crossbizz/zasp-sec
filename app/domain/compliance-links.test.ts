import { describe, expect, it } from "vitest";
import { complianceLink, parseComplianceLink } from "./compliance-links";
const scope = { organizationID: "pid_10000001-0000-4000-8000-000000000001", workspaceID: "pid_10000002-0000-4000-8000-000000000002", environmentID: "pid_10000003-0000-4000-8000-000000000003" };
const suffix = `organization_id=${scope.organizationID}&workspace_id=${scope.workspaceID}&environment_id=${scope.environmentID}`;
describe("typed compliance selectors", () => {
  it.each(["policy", "administration", "finding", "configuration", "red_team_test", "attack_lab_test", "workflow_policy", "red_team_mutation"] as const)("retains the %s source and historical version", source_kind => {
    const target = { source_kind, source_id: source_kind === "policy" ? "policy-production" : ["administration", "workflow_policy", "red_team_mutation"].includes(source_kind) ? "audit:42" : scope.environmentID, source_version: 1 };
    const link = complianceLink(target, scope);
    expect(link).toBe(`/compliance/evidence?source_kind=${source_kind}&source_id=${target.source_id}&source_version=1&${suffix}`);
    expect(parseComplianceLink(link, scope)).toEqual({ state: "selected", target });
  });
  it.each(["&source_id=policy-other", "&entity_id=x", "&unknown=x", "#fragment", "&token=secret"])("rejects ambiguous selectors %s", extra => {
    expect(parseComplianceLink(`/compliance/evidence?source_kind=policy&source_id=policy-production&source_version=2&${suffix}${extra}`, scope)).toEqual({ state: "invalid" });
  });
  it.each(["0", "01", "1e2", "-1", "9007199254740992", "1%32"])("rejects noncanonical versions %s", version => expect(parseComplianceLink(`/compliance/evidence?source_kind=policy&source_id=policy-production&source_version=${version}&${suffix}`, scope)).toEqual({ state: "invalid" }));
  it("rejects encoded source IDs and foreign scope without changing scope", () => {
    expect(parseComplianceLink(`/compliance/evidence?source_kind=policy&source_id=policy%2dproduction&source_version=2&${suffix}`, scope)).toEqual({ state: "invalid" });
    expect(parseComplianceLink(`/compliance/evidence?source_kind=policy&source_id=policy-production&source_version=2&${suffix}`, { ...scope, workspaceID: scope.environmentID })).toEqual({ state: "scope_mismatch" });
  });
});

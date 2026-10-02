import { describe, expect, it } from "vitest";
import { activityLink, parseActivityLink, type ActivityKind } from "./activity-links";

const scope = {
  organizationID: "pid_10000001-0000-4000-8000-000000000001",
  workspaceID: "pid_10000002-0000-4000-8000-000000000002",
  environmentID: "pid_10000003-0000-4000-8000-000000000003",
};
const id = "pid_10000004-0000-4000-8000-000000000004";
const query = "entity_id=pid_10000004-0000-4000-8000-000000000004&organization_id=pid_10000001-0000-4000-8000-000000000001&workspace_id=pid_10000002-0000-4000-8000-000000000002&environment_id=pid_10000003-0000-4000-8000-000000000003";
const routes: [ActivityKind, string][] = [
  ["finding", "/violations"], ["attack_path", "/exposure/attack-paths"],
  ["session", "/investigate/sessions"], ["audit", "/administration/audit-log"],
  ["run", "/protect/security-agents"],
  ["test_run", "/red-team/results"],
  ["attack_lab_run", "/test/attack-lab"],
];

describe("exact scoped activity links", () => {
  it.each(["/discovery/assets", "/inventory/tools", "/identities", "/inventory/runtimes"])("delegates canonical inventory selection on %s to its product reader", path => {
    expect(parseActivityLink(`${path}?inventory=${id}`, scope)).toEqual({ state: "none" });
  });

  it.each([
    `/discovery/assets?inventory=${id}&${query}`,
    `/inventory/tools?inventory=${id}&entity_id=${id}`,
    `/identities?inventory=${id}&organization_id=${scope.organizationID}`,
    `/inventory/runtimes?inventory=${id}&workspace_id=${scope.workspaceID}`,
    `/discovery/assets?inventory=${id}&environment_id=${scope.environmentID}`,
    `/discovery/assets?inventory=${id}&entity%5fid=${id}`,
    `/discovery/assets?inventory=${id}&inventory=${id}`,
    `/discovery/assets?inventory=${id}&extra=1`,
    `/discovery/assets?%69nventory=${id}`,
    `/discovery/assets?inventory=${id.replace("pid_", "pid%5f")}`,
    `/discovery/assets?inventory=${id}%0A`,
    `/discovery/assets?inventory=${id.toUpperCase()}`,
    "/discovery/assets?inventory=", "/discovery/assets?inventory=invalid",
    `/discovery/assets?inventory=${id}=extra`,
    `/discovery/assets/?inventory=${id}`, `/discovery//assets?inventory=${id}`,
    `/discovery/assets?inventory=${id}#record`,
    `https://example.test/discovery/assets?inventory=${id}`,
    `//example.test/discovery/assets?inventory=${id}`,
    `/discovery/../discovery/assets?inventory=${id}`,
    `/?inventory=${id}`, `/violations?inventory=${id}`, `/unknown?inventory=${id}`,
    `/discovery/assets?${query}`, "/discovery/assets?filter=x",
  ])("refuses ambiguous inventory delegation %s", location => {
    expect(parseActivityLink(location, scope)).toEqual({ state: "invalid" });
  });

  it.each(routes)("preserves the exact %s target and its scope", (kind, path) => {
    expect(activityLink({ kind, id }, scope)).toBe(`${path}?${query}`);
    expect(parseActivityLink(`${path}?${query}`, scope)).toEqual({ state: "selected", target: { kind, id } });
  });

  it.each(["organizationID", "workspaceID", "environmentID"] as const)("refuses a link from another %s without replacing current scope", key => {
    const current = { ...scope, [key]: "pid_20000001-0000-4000-8000-000000000001" };
    expect(parseActivityLink(`/violations?${query}`, current)).toEqual({ state: "scope_mismatch" });
    expect(current[key]).toBe("pid_20000001-0000-4000-8000-000000000001");
  });

  it.each(["/", "/violations", "/protect/security-agents", "/administration/audit-log"])("leaves plain %s navigation unselected", path => {
    expect(parseActivityLink(path, scope)).toEqual({ state: "none" });
  });

  it.each([
    `/violations?${query}&entity_id=${id}`, `/violations?${query}&workspace_id=${scope.workspaceID}`,
    `/violations?${query}&extra=1`, `/violations?${query.replace(/&environment_id=.*/, "")}`,
    "/violations?entity_id=", "/violations?filter=x", `/unknown?${query}`,
    `https://example.test/violations?${query}`, `//example.test/violations?${query}`,
    `/exposure/../violations?${query}`, `/violations/?${query}`, `/violations?${query}#record`,
    `/violations?${query.replace(id, `${id}%0A`)}`, `/violations?${query.replace(id, id.toUpperCase())}`,
    `/violations?${query.replace(id, "pid_10000004-0000-1000-8000-000000000004")}`,
    `/violations?${query.replace(id, "pid_10000004-0000-4000-7000-000000000004")}`,
    `/violations?${query.replace("entity_id=", "entity%5fid=")}`,
  ])("rejects malformed or ambiguous link %s", location => {
    expect(parseActivityLink(location, scope)).toEqual({ state: "invalid" });
  });

  it("accepts reordered canonical parameters, without relying on their order", () => {
    expect(parseActivityLink(`/violations?environment_id=${scope.environmentID}&workspace_id=${scope.workspaceID}&organization_id=${scope.organizationID}&entity_id=${id}`, scope))
      .toEqual({ state: "selected", target: { kind: "finding", id } });
  });

  it.each(["", `${id}\n`, "javascript:alert(1)", id.toUpperCase()])("never emits an unsafe target %s", invalidID => {
    expect(() => activityLink({ kind: "finding", id: invalidID }, scope)).toThrow(TypeError);
  });

  it("rejects invalid scope at both construction and selection boundaries", () => {
    const invalid = { ...scope, workspaceID: "" };
    expect(() => activityLink({ kind: "finding", id }, invalid)).toThrow(TypeError);
    expect(parseActivityLink(`/violations?${query}`, invalid)).toEqual({ state: "invalid" });
  });
});

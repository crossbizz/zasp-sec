import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M8-51e through M8-60b deployment-profile batch", () => {
  it("adds exact SaaS, single-tenant, and lightweight edge values", () => {
    const saas = read("deploy/staging/product/values-saas.yaml");
    const single = read("deploy/staging/product/values-single-tenant.yaml");
    const edge = read("deploy/staging/product/values-customer-edge.yaml");
    expect(saas).toContain("deploymentMode: saas");
    expect(saas).not.toContain("organizationID:");
    expect(single).toContain("deploymentMode: single_tenant");
    expect(single).toContain("organizationID: pid_11111111-1111-4111-8111-111111111111");
    for (const value of ["sensorAgent", "runtimeGateway", "policyCache", "tokenSecretName", "credentialSecretName", "policyKeysSecretName", "controlPlaneURL"]) expect(edge).toContain(value);
    for (const forbidden of ["web:", "agentsecApi:", "neo4j:", "nango:", "neon:", "stytch:"]) expect(edge).not.toContain(forbidden);
  });

  it("ships only the bounded customer-edge gateway and sensor workloads", () => {
    const template = read("deploy/staging/product/templates/edge.yaml");
    expect(template).toContain('{{- if eq .Values.profile "customer_edge" }}');
    expect(template).toContain("kind: Deployment");
    expect(template).toContain("kind: DaemonSet");
    expect(template).toContain("name: runtime-gateway");
    expect(template).toContain("name: sensor-agent");
    expect(template).toContain("runtimeGateway.credentialSecretName is required");
    expect(template).toContain("sensorAgent.tokenSecretName is required");
    for (const forbidden of ["kind: Ingress", "privileged: true", "DATABASE_URL", "ZASP_POSTGRES"]) expect(template).not.toContain(forbidden);
  });

  it("adds usability, partner-value, quota, isolation, and SaaS golden models", () => {
    const source = read("cmd/agentsecctl/profiles.go");
    for (const symbol of ["EvaluateInstallUsability", "EvaluateDesignPartnerValue", "ValidateDeploymentProfile", "RunQuotaFixture", "ValidateIsolationSuite", "RunIsolationSuite", "RunSaaSGoldenFixture"]) expect(source).toContain(`func ${symbol}`);
  });

  it("classifies all 25 profile tasks without claiming live or human SaaS evidence", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const complete = tracker.match(/## Complete[\s\S]*?## Blocked/)?.[0] || "";
    const blocked = tracker.match(/## Blocked[\s\S]*/)?.[0] || "";
    const completed = ["M8-55", "M8-56", "M8-57a", "M8-57b", "M8-57c", "M8-57", "M8-58a", "M8-59a1", "M8-59a2", "M8-59a3", "M8-59a", "M8-60a"];
    const externallyBlocked = ["M8-51e", "M8-51", "M8-52a", "M8-52b", "M8-52c", "M8-52d", "M8-52", "M8-53", "M8-58b", "M8-58", "M8-59b", "M8-59", "M8-60b"];
    for (const id of [...completed, ...externallyBlocked]) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm")) ?? []).toHaveLength(0);
    for (const id of completed) expect(complete.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const id of externallyBlocked) expect(blocked.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 0 |", "| Complete | 667 |", "| Blocked | 61 |", "`0/0/667/61`", "| M8 | 141 | 0 | 0 | 89 | 52 |"]) expect(tracker).toContain(value);
  });
});

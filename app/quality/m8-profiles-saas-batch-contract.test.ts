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
    expect(single).toContain("organizationID: org_customer_required");
    for (const value of ["sensor", "runtimeGateway", "policyCache", "enrollmentSecretRef", "saasAPIEndpoint"]) expect(edge).toContain(value);
    for (const forbidden of ["web:", "agentsecApi:", "neo4j:", "nango:", "neon:", "stytch:"]) expect(edge).not.toContain(forbidden);
  });

  it("adds usability, partner-value, quota, isolation, and SaaS golden models", () => {
    const source = read("cmd/agentsecctl/profiles.go");
    for (const symbol of ["EvaluateInstallUsability", "EvaluateDesignPartnerValue", "ValidateDeploymentProfile", "RunQuotaFixture", "ValidateIsolationSuite", "RunIsolationSuite", "RunSaaSGoldenFixture"]) expect(source).toContain(`func ${symbol}`);
  });

  it("advances exactly 25 tasks without claiming live SaaS completion", () => {
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    const selected = ["M8-51e", "M8-51", "M8-52a", "M8-52b", "M8-52c", "M8-52d", "M8-52", "M8-53", "M8-55", "M8-56", "M8-57a", "M8-57b", "M8-57c", "M8-57", "M8-58a", "M8-58b", "M8-58", "M8-59a1", "M8-59a2", "M8-59a3", "M8-59a", "M8-59b", "M8-59", "M8-60a", "M8-60b"];
    for (const id of selected) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 72 |", "`0/72/636/20`", "| M8 | 141 | 0 | 66 | 58 | 17 |"]) expect(tracker).toContain(value);
  });
});

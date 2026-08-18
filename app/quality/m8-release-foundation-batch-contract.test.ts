import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const read = (path: string) => readFileSync(path, "utf8");

describe("M8-01a through M8-16 release foundation batch", () => {
  it("extends the one Terraform root with private production hardening", () => {
    const main = read("deploy/staging/main.tf");
    const variables = read("deploy/staging/variables.tf");
    const release = read("deploy/staging/release.tfvars");
    for (const value of ["aws_vpc_endpoint", "aws_eks_fargate_profile", "aws_security_group\" \"attack_lab", "aws_s3_bucket_lifecycle_configuration", "maxReceiveCount", "node_to_node_encryption", "AssumeRoleWithWebIdentity"]) expect(main).toContain(value);
    for (const value of ["environment", "node_desired_size", "node_instance_types", "opensearch_instance_type", "attack_lab_namespace"]) expect(variables).toContain(value);
    for (const value of [/environment\s*=\s*"production"/, /endpoint_public_access\s*=\s*false/, /node_desired_size\s*=\s*3/]) expect(release).toMatch(value);
  });

  it("renders one bounded product chart for web, APIs, workers, gateway, and dependencies", () => {
    const chart = read("deploy/staging/product/Chart.yaml");
    const values = read("deploy/staging/product/values.yaml");
    const workloads = read("deploy/staging/product/templates/workloads.yaml");
    const services = read("deploy/staging/product/templates/services.yaml");
    const resilience = read("deploy/staging/product/templates/resilience.yaml");
    expect(chart).toContain("name: zasp-product");
    for (const value of ["web", "agentsec-api", "agentsec-worker", "event-ingest", "runtime-gateway"]) expect(workloads).toContain(`"name" "${value}"`);
    for (const value of ["neo4j", "nango", "otel-collector", "tetragon"]) expect(workloads).toContain(`name: ${value}`);
    for (const value of ["readinessProbe", "livenessProbe", "terminationGracePeriodSeconds", "preStop", "resources:"]) expect(workloads).toContain(value);
    for (const value of ["ClusterIP", "agentsec-api", "runtime-gateway", "neo4j", "nango", "otel-collector"]) expect(services).toContain(value);
    for (const value of ["PodDisruptionBudget", "topologySpreadConstraints", "maxUnavailable", "SecurityGroupPolicy"]) expect(resilience).toContain(value);
    expect(values).toContain("privateEndpointOnly: true");
  });

  it("adds a fail-closed preflight and advances exactly 25 tasks", () => {
    const preflight = read("deploy/staging/preflight.mjs");
    for (const value of ["terraform", "helm", "kubectl", "aws", "production", "privateEndpointOnly"]) expect(preflight).toContain(value);
    const tracker = read("docs/internal/implementation_status_v1.5.md");
    const active = tracker.match(/## In progress[\s\S]*?## Complete/)?.[0] || "";
    for (const id of ["M8-01a", "M8-01b", "M8-01c", "M8-01", "M8-02", "M8-03", "M8-04", "M8-05", "M8-06", "M8-07", "M8-08a", "M8-08b", "M8-08c", "M8-08", "M8-09a", "M8-09b", "M8-09c", "M8-09", "M8-10", "M8-11", "M8-12", "M8-13", "M8-14", "M8-15", "M8-16"]) expect(active.match(new RegExp(`^\\| ${id} \\|`, "gm"))).toHaveLength(1);
    for (const value of ["| Pending | 0 |", "| In progress | 441 |", "`0/441/284/3`", "| M8 | 141 | 0 | 141 | 0 | 0 |"]) expect(tracker).toContain(value);
  });
});

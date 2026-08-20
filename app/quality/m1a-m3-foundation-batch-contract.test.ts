import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const root = resolve(import.meta.dirname, "../..");

describe("M1A and M3 foundation batch", () => {
  it("defines the exact private staging Terraform resources and outputs", async () => {
    const [versions, main, outputs] = await Promise.all([
      readFile(resolve(root, "deploy/staging/versions.tf"), "utf8"),
      readFile(resolve(root, "deploy/staging/main.tf"), "utf8"),
      readFile(resolve(root, "deploy/staging/outputs.tf"), "utf8"),
    ]);
    expect(versions).toContain('required_version = "= 1.15.8"');
    for (const resource of [
      'resource "aws_vpc" "staging"', 'resource "aws_subnet" "private"',
      'resource "aws_eks_cluster" "staging"', 'resource "aws_eks_node_group" "staging"', 'resource "aws_s3_bucket" "evidence"',
      'resource "aws_kms_key" "staging"', 'resource "aws_secretsmanager_secret" "product"',
      'resource "aws_sqs_queue" "work"', 'resource "aws_sqs_queue" "dead_letter"',
      'resource "aws_opensearch_domain" "events"', 'resource "aws_iam_role" "api"',
      'resource "aws_iam_role" "migration"', 'resource "aws_iam_role" "canary_secret_sync"',
      'resource "aws_kms_key" "connector_oauth"', 'resource "aws_secretsmanager_secret" "connector_provider"',
      'resource "aws_iam_role" "api_connectors"',
    ]) expect(main).toContain(resource);
    expect(main).toContain("block_public_acls       = true");
    expect(main).toContain("encrypt_at_rest");
    expect(main).toContain("node_to_node_encryption");
    expect(main).toContain("redrive_policy");
    expect(main).toContain("StringEquals");
    expect(main).not.toMatch(/Action\s*=\s*"\*"/);
    expect(main).not.toMatch(/iam:(?:Create|Delete|Put|Update)|ec2:(?:Create|Delete|Modify)|secretsmanager:PutSecretValue/);
    expect(main).not.toContain('Action    = "es:ESHttp*"');
    expect(main).not.toContain('resource "aws_iam_role" "product"');
    for (const output of ["private_subnet_ids", "cluster_name", "bucket_name", "queue_urls", "opensearch_endpoint", "api_role_arn", "migration_role_arn", "canary_secret_sync_role_arn", "connector_role_arn", "connector_kms_key_arn", "connector_secret_prefix", "connector_runtime_config"]) {
      expect(outputs).toContain(`output "${output}"`);
    }
    expect(outputs).not.toContain('output "product_role_arn"');
  });

  it("publishes mounted integration definitions and only the launch authorization routes", async () => {
    const openapi = await readFile(resolve(root, "openapi/openapi.yaml"), "utf8");
    for (const operation of ["listIntegrationCatalog", "listIntegrations", "createIntegration", "getIntegration", "updateIntegration", "deleteIntegration", "authorizeIntegration", "authorizeIntegrationReference", "completeIntegrationOAuthCallback"]) expect(openapi).toContain(`operationId: ${operation}`);
    for (const operation of ["syncIntegration", "listIntegrationSyncs", "getIntegrationSync"]) expect(openapi).not.toContain(`operationId: ${operation}`);
    const section = openapi.match(/ {2}\/api\/v1\/integration-catalog:[\s\S]*?(?=security:)/)?.[0] ?? "";
    expect(section).not.toMatch(/nango|cartography|prowler|adapter_key/i);
  });

  it("records exactly the 20 completed tasks and preserves the provider gate", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(tracker).toMatch(/^\| Pending \| \d+ \|/m);
    expect(tracker).toMatch(/^\| In progress \| \d+ \|/m);
    expect(tracker).toMatch(/^\| Complete \| \d+ \|/m);
    expect(tracker).toContain("| M1A | 10 | 0 | 0 | 6 | 4 |");
    expect(tracker).toContain("| M3 | 75 | 0 | 0 | 73 | 2 |");
    const tasks = [
      "M1A-01", "M1A-02", "M1A-03", "M1A-04", "M1A-05", "M1A-06",
      "M3-01", "M3-02", "M3-02a", "M3-03", "M3-04", "M3-05", "M3-06",
      "M3-07", "M3-08", "M3-09", "M3-10", "M3-11", "M3-12", "M3-13",
    ];
    for (const task of tasks) {
      expect(tracker.match(new RegExp(`^\\| ${task.replace("-", "\\-")} \\|`, "gm"))).toHaveLength(1);
    }
    for (const task of ["M1A-07", "M1A-08", "M1A-09", "M1A-10"]) expect(tracker.match(new RegExp(`^\\| ${task} \\|`, "gm"))).toHaveLength(1);
    expect(tracker.match(/^\| M3-14 \|/gm)).toHaveLength(1);
    expect(readme).toContain("M1A-07 through M1A-10 are Blocked");
    expect(readme).toContain("M3-15 through M3-36 are Complete");
  });
});

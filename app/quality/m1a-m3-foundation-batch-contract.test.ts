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
      'resource "aws_opensearch_domain" "events"', 'resource "aws_iam_role" "product"',
    ]) expect(main).toContain(resource);
    expect(main).toContain("block_public_acls       = true");
    expect(main).toContain("encrypt_at_rest");
    expect(main).toContain("node_to_node_encryption");
    expect(main).toContain("redrive_policy");
    expect(main).toContain("StringEquals");
    expect(main).not.toMatch(/Action\s*=\s*"\*"/);
    expect(main).not.toMatch(/iam:(?:Create|Delete|Put|Update)|ec2:(?:Create|Delete|Modify)|secretsmanager:PutSecretValue/);
    expect(main).not.toContain('Action    = "es:ESHttp*"');
    for (const output of ["private_subnet_ids", "cluster_name", "bucket_name", "queue_urls", "opensearch_endpoint", "product_role_arn"]) {
      expect(outputs).toContain(`output "${output}"`);
    }
  });

  it("publishes the ten M3 integration operations without provider names", async () => {
    const openapi = await readFile(resolve(root, "openapi/openapi.yaml"), "utf8");
    for (const operation of [
      "listIntegrationCatalog", "listIntegrations", "createIntegration", "getIntegration",
      "updateIntegration", "deleteIntegration", "authorizeIntegration", "syncIntegration",
      "listIntegrationSyncs", "getIntegrationSync",
    ]) expect(openapi).toContain(`operationId: ${operation}`);
    const section = openapi.match(/ {2}\/api\/v1\/integration-catalog:[\s\S]*?(?=security:)/)?.[0] ?? "";
    expect(section).not.toMatch(/nango|cartography|prowler|adapter_key/i);
  });

  it("records exactly the 20 completed tasks and preserves the provider gate", async () => {
    const [tracker, readme] = await Promise.all([
      readFile(resolve(root, "docs/internal/implementation_status_v1.5.md"), "utf8"),
      readFile(resolve(root, "README.md"), "utf8"),
    ]);
    expect(tracker).toContain("| Pending | 495 |");
    expect(tracker).toContain("| In progress | 46 |");
    expect(tracker).toContain("| Complete | 184 |");
    expect(tracker).toContain("| M1A | 10 | 4 | 0 | 6 | 0 |");
    expect(tracker).toContain("| M3 | 75 | 15 | 46 | 14 | 0 |");
    const tasks = [
      "M1A-01", "M1A-02", "M1A-03", "M1A-04", "M1A-05", "M1A-06",
      "M3-01", "M3-02", "M3-02a", "M3-03", "M3-04", "M3-05", "M3-06",
      "M3-07", "M3-08", "M3-09", "M3-10", "M3-11", "M3-12", "M3-13",
    ];
    for (const task of tasks) {
      expect(tracker.match(new RegExp(`^\\| ${task.replace("-", "\\-")} \\|`, "gm"))).toHaveLength(1);
    }
    expect(tracker).not.toMatch(/^\| M1A-07 \|/m);
    expect(tracker.match(/^\| M3-14 \|/gm)).toHaveLength(1);
    expect(readme).toContain("M1A-07 remains Pending; no real cloud resource was created");
    expect(readme).toContain("M3-14 through M3-34 are implementation-ready but remain In progress");
  });
});

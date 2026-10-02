import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, readFile, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { loadAll } from "js-yaml";
import { complianceExportReleaseFixture } from "./compliance-export-release-fixture.mjs";

test("direct Helm rejects malformed compliance authority without the JS normalizer", async t => {
  const directory = await mkdtemp(path.join(tmpdir(), "zasp-compliance-helm-"));
  try {
    await mkdir(path.join(directory, "templates"));
    await writeFile(path.join(directory, "Chart.yaml"), "apiVersion: v2\nname: compliance-owned\nversion: 0.1.0\n");
    for (const file of ["_compliance-exports.tpl", "compliance-exports.yaml", "compliance-export-network.yaml", "compliance-export-operations.yaml"]) await writeFile(path.join(directory, "templates", file), await readFile(new URL(`../staging/product/templates/${file}`, import.meta.url)));
    const fixture = () => ({ profile: "control_plane", schema: { expectedVersion: 56 }, runtime: { sessionSearchPhase: "precision-intake" }, global: { terminationGracePeriodSeconds: 30, productImages: { agentsecWorker: `registry.example/worker@sha256:${"a".repeat(64)}` } }, monitoring: { enabled: true, namespace: "monitoring" }, serviceAccounts: { api: { roleArn: "arn:aws:iam::123456789012:role/api" } }, complianceExports: complianceExportReleaseFixture() });
    const render = async value => {
      await writeFile(path.join(directory, "values.json"), JSON.stringify(value));
      const { stdout } = await promisify(execFile)("helm", ["template", "owned", directory, "-n", "agentsec", "-f", path.join(directory, "values.json")], { timeout: 20000 });
      return loadAll(stdout).filter(Boolean);
    };
    assert.equal((await render(fixture())).filter(r => r.kind === "Deployment").length, 2);
    const disabled = fixture(); disabled.complianceExports = { enabled: false }; assert.equal((await render(disabled)).length, 0);
    const cases = {
      unknown: v => { v.complianceExports.extra = true; },
      "disabled authority": v => { v.complianceExports.enabled = false; },
      "wrong schema": v => { v.schema.expectedVersion = 55; },
      "future schema": v => { v.schema.expectedVersion = 57; },
      "wrong phase": v => { v.runtime.sessionSearchPhase = "query"; },
      "wrong account": v => { v.complianceExports.bucketOwner = "987654321098"; },
      "wrong region": v => { v.complianceExports.awsRegion = "us-east-1"; },
      "role collision": v => { v.complianceExports.cleanupRoleArn = v.complianceExports.writerRoleArn; },
      "prior identity": v => { v.complianceExports.writerRoleArn = v.serviceAccounts.api.roleArn; },
      "prior DSN": v => { v.secrets = { old: v.complianceExports.workerDSNSecretArn }; },
      "prior bucket": v => { v.discovery = { evidenceBucket: v.complianceExports.bucket }; },
      "newline principal": v => { v.complianceExports.workerPrincipal += "\n"; },
      "metadata CIDR": v => { v.complianceExports.databaseCIDRs = ["169.254.0.0/16"]; },
      "overlapping CIDRs": v => { v.complianceExports.stsCIDRs = ["10.0.0.0/24", "10.0.0.0/25"]; },
      "monitor disabled": v => { v.monitoring.enabled = false; },
      "grace too long": v => { v.global.terminationGracePeriodSeconds = 301; },
    };
    for (const [name, mutate] of Object.entries(cases)) await t.test(name, async () => { const value = fixture(); mutate(value); await assert.rejects(render(value), /execution error/); });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

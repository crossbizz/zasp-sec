import assert from "node:assert/strict";
import test from "node:test";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { renderRelease } from "./release-contract.mjs";
import { productionReleaseFixture } from "./release-fixture.mjs";
import { complianceExportReleaseFixture } from "./compliance-export-release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";
import { testReconcilerReleaseFixture } from "./test-reconciler-release-fixture.mjs";
import { goTestRuntime, requireGoTestVersion } from "./go-test-runtime.mjs";

test("real Go loaders consume enabled and disabled rendered compliance environments", async t => {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const launch = goTestRuntime();
  const exec = promisify(execFile);
  const version = await exec(launch.executable, ["env", "GOVERSION"], { env: launch.env, timeout: 10000, maxBuffer: 4096 });
  requireGoTestVersion(version.stdout);
  assert.equal(version.stderr, "");
  const dir = await mkdtemp(path.join(tmpdir(), "zasp-compliance-rendered-"));
  try {
    const enabled = await renderRelease(productionReleaseFixture, { schemaVersion: 56, sessionSearchPhase: "precision-intake", complianceExports: complianceExportReleaseFixture(), auditExports: auditExportReleaseFixture(), testReconciler: testReconcilerReleaseFixture() });
    const disabled = await renderRelease(productionReleaseFixture);
    const complianceOnly = await renderRelease(productionReleaseFixture, { schemaVersion: 56, sessionSearchPhase: "precision-intake", complianceExports: complianceExportReleaseFixture() });
    const workflow = await renderRelease(productionReleaseFixture, { schemaVersion: 58, sessionSearchPhase: "precision-intake", complianceExports: complianceExportReleaseFixture(), evidenceExportWorkflow: true });
    const fixture = path.join(dir, "rendered.json");
    await writeFile(fixture, JSON.stringify({ enabled, disabled, complianceOnly, workflow }), { mode: 0o600 });
    const { stdout, stderr } = await exec(launch.executable, ["test", "-race", "./agentsec-api", "./agentsec-worker", "-run", "^TestComplianceDeploymentRendered", "-count=1", "-v"], { cwd: path.join(root, "services/platform"), timeout: 120000, maxBuffer: 4 * 1024 * 1024, env: { ...launch.env, ZASP_COMPLIANCE_RENDERED_FIXTURE: fixture } });
    assert.doesNotMatch(stdout, /SKIP|FAIL/); assert.equal(stderr, "");
    assert.match(stdout, /TestComplianceDeploymentRenderedAPIConfig/); assert.match(stdout, /TestComplianceDeploymentRenderedWorkerConfig/);
    assert.match(stdout, /TestComplianceDeploymentRenderedAPIConfig\/complianceOnly/);
    assert.match(stdout, /TestComplianceDeploymentRenderedAPIConfig\/workflow/);
    t.diagnostic(stdout);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

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

test("real Go loaders consume enabled and disabled rendered compliance environments", async t => {
  const root = fileURLToPath(new URL("../../", import.meta.url));
  const dir = await mkdtemp(path.join(tmpdir(), "zasp-compliance-rendered-"));
  try {
    const enabled = await renderRelease(productionReleaseFixture, { schemaVersion: 56, sessionSearchPhase: "precision-intake", complianceExports: complianceExportReleaseFixture(), auditExports: auditExportReleaseFixture(), testReconciler: testReconcilerReleaseFixture() });
    const disabled = await renderRelease(productionReleaseFixture);
    const fixture = path.join(dir, "rendered.json");
    await writeFile(fixture, JSON.stringify({ enabled, disabled }), { mode: 0o600 });
    const { stdout, stderr } = await promisify(execFile)("/opt/homebrew/bin/go", ["test", "-race", "./agentsec-api", "./agentsec-worker", "-run", "^TestComplianceDeploymentRendered", "-count=1", "-v"], { cwd: path.join(root, "services/platform"), timeout: 120000, maxBuffer: 4 * 1024 * 1024, env: { PATH: "/opt/homebrew/bin:/usr/bin:/bin", HOME: process.env.HOME, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off", GOCACHE: "/private/tmp/zasp-budget-go-cache", ZASP_COMPLIANCE_RENDERED_FIXTURE: fixture } });
    assert.doesNotMatch(stdout, /SKIP|FAIL/); assert.equal(stderr, "");
    assert.match(stdout, /TestComplianceDeploymentRenderedAPIConfig/); assert.match(stdout, /TestComplianceDeploymentRenderedWorkerConfig/);
    t.diagnostic(stdout);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

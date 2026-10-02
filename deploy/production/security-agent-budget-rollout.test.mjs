import assert from "node:assert/strict";
import test from "node:test";
import { renderRelease, validateRenderedRelease } from "./release-contract.mjs";
import { productionReleaseFixture as release } from "./release-fixture.mjs";
import { auditExportReleaseFixture } from "./audit-export-release-fixture.mjs";

const one = (rows, kind, name) => {
  const matches = rows.filter(r => r.kind === kind && r.metadata.name === name);
  assert.equal(matches.length, 1);
  return matches[0];
};
const container = r => r.spec.template.spec.containers[0];
const environment = r => Object.fromEntries(container(r).env.map(e => [e.name, e.value]));

for (const schemaVersion of [53, 54]) {
for (const phase of ["precision-consumers", "precision-intake"]) {
  for (const enabled of [false, true]) {
    test(`security-agent schema${schemaVersion} preserves ${phase}, exports=${enabled}`, async () => {
      const exports = enabled ? auditExportReleaseFixture() : undefined;
      const rows = await renderRelease(release, { schemaVersion, sessionSearchPhase: phase, auditExports: exports });
      const migration = one(rows, "Job", `agentsec-schema-v${schemaVersion}`);
      const command = enabled
        ? `ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)" && export ZASP_POSTGRES_DSN && /app/agentsec-migrate up-to-${schemaVersion} && /app/agentsec-migrate register-audit-export-api && /app/agentsec-migrate register-audit-export-workers && exec /app/agentsec-migrate configure-audit-exports`
        : `export ZASP_POSTGRES_DSN="$(cat /var/run/secrets/zasp-migration/postgres-dsn)"; exec /app/agentsec-migrate up-to-${schemaVersion}`;
      assert.deepEqual(container(migration).args, [command]);
      assert.equal(environment(one(rows, "Deployment", "agentsec-api")).ZASP_EXPECTED_SCHEMA_VERSION, String(schemaVersion));
      assert.equal(environment(one(rows, "Deployment", "agentsec-event-ingest")).ZASP_RUNTIME_INGEST_SCHEMA, phase === "precision-intake" ? "runtime-event-v2" : "runtime-event-v1");
      assert.equal(environment(one(rows, "Deployment", "agentsec-runtime-coordinator")).ZASP_RUNTIME_DELIVERY_SCHEMA, "runtime-event-v2");
      if (enabled) {
        assert.equal(environment(migration).ZASP_AUDIT_EXPORT_POLICY_ID, exports.currentPolicyID);
        for (const name of ["zasp-audit-export-worker", "zasp-audit-export-outbox"]) assert.equal(one(rows, "Deployment", name).spec.template.metadata.annotations["zasp.io/schema-version"], String(schemaVersion));
      } else assert.equal(rows.filter(r => r.metadata.name.startsWith("zasp-audit-export")).length, 0);
      assert.doesNotThrow(() => validateRenderedRelease(rows, "123456789012", schemaVersion, phase, exports));
      const mutations = [
        r => { container(one(r, "Job", `agentsec-schema-v${schemaVersion}`)).args[0] = command.replace(`up-to-${schemaVersion}`, `up-to-${schemaVersion - 1}`); },
        r => { one(r, "Deployment", "agentsec-api").spec.template.metadata.annotations["zasp.io/schema-version"] = String(schemaVersion - 1); },
      ];
      if (enabled) mutations.push(
        r => { container(one(r, "Job", `agentsec-schema-v${schemaVersion}`)).args[0] = command.replace(" && /app/agentsec-migrate register-audit-export-api", ""); },
        r => { container(one(r, "Job", `agentsec-schema-v${schemaVersion}`)).args[0] = command.replace(" && /app/agentsec-migrate register-audit-export-workers", ""); },
        r => { one(r, "Deployment", "zasp-audit-export-worker").spec.template.metadata.annotations["zasp.io/schema-version"] = String(schemaVersion - 1); },
      );
      for (const mutate of mutations) {
        const drift = structuredClone(rows); mutate(drift);
        assert.throws(() => validateRenderedRelease(drift, "123456789012", schemaVersion, phase, exports), /release rejected/);
      }
    });
  }
}
}

test("budget release keeps default49 and rejects implicit or future phases", async () => {
  const rows = await renderRelease(release);
  one(rows, "Job", "agentsec-schema-v49");
  for (const options of [
    { schemaVersion: 53 }, { schemaVersion: 53, sessionSearchPhase: "compatibility" },
    { schemaVersion: 53, sessionSearchPhase: "query" }, { schemaVersion: 53, sessionSearchPhase: "backfill" },
    { schemaVersion: 54 }, { schemaVersion: 54, sessionSearchPhase: "compatibility" },
    { schemaVersion: 54, sessionSearchPhase: "query" }, { schemaVersion: 54, sessionSearchPhase: "backfill" },
    { schemaVersion: 61, sessionSearchPhase: "precision-consumers" }, { schemaVersion: 61, sessionSearchPhase: "precision-intake" },
  ]) await assert.rejects(renderRelease(release, options), /release rejected/);
});

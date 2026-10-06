import assert from "node:assert/strict";
import { complianceRuntimeBindings } from "./compliance-runtime-prerequisites.mjs";

// Requires externally owned live services. Configuration alone is never readiness.
// This changes only the database profile selected before the real API starts.
export async function prepareComplianceCurrentRuntime({ command, migrate, migrationEnvironment, sql, environment, signingKey }) {
  complianceRuntimeBindings(environment);
  assert.equal(typeof command, "function");
  assert.equal(typeof sql, "function");
  assert.ok(typeof migrate === "string" && migrate.length > 0);
  assert.ok(typeof signingKey === "string" && Buffer.byteLength(signingKey) >= 32 && Buffer.byteLength(signingKey) <= 4096, "compliance authorization signing key refused");
  const currentEnvironment = { ...migrationEnvironment, ZASP_WORKFLOW_SIGNING_KEY: signingKey };
  // The fixed runtime installer accepts canonical60/61. It validates all
  // Temporal78 + authorization79/80 identity/audit/worker profile bodies.
  await command(migrate, ["up-to-60"], { env: migrationEnvironment });
  await command(migrate, ["up-authorization-runtime-profile"], { env: migrationEnvironment });
  await command(migrate, ["register-authorization-verifier"], { env: currentEnvironment });
  assert.equal(await sql("SELECT max(version) FROM zasp_schema_versions"), "61", "compliance browser requires the current canonical authorization runtime profile");
}

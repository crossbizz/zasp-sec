import assert from "node:assert/strict";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const repositoryRoot = resolve(import.meta.dirname, "..");
const schemaPath = resolve(repositoryRoot, "openapi/openapi.yaml");
const generatedPath = resolve(repositoryRoot, "apps/web/api/generated.ts");
const cliPath = resolve(repositoryRoot, "node_modules/openapi-typescript/bin/cli.js");
const generationFlags = [
  "--alphabetize",
  "--export-type",
  "--immutable",
  "--root-types",
  "--root-types-no-schema-prefix",
];
const generateScript = [
  "openapi-typescript openapi/openapi.yaml",
  "--output apps/web/api/generated.ts",
  ...generationFlags,
].join(" ");

function runGenerator(outputPath, extraFlags = []) {
  return spawnSync(
    process.execPath,
    [cliPath, schemaPath, "--output", outputPath, ...generationFlags, ...extraFlags],
    {
      cwd: repositoryRoot,
      encoding: "utf8",
      env: {
        HOME: process.env.HOME,
        LANG: "C.UTF-8",
        PATH: process.env.PATH,
      },
      maxBuffer: 64 * 1024,
      timeout: 30_000,
    },
  );
}

test("pins the official generator/runtime and wires exact local-only scripts into verify", async () => {
  const packageJson = JSON.parse(await readFile(resolve(repositoryRoot, "package.json"), "utf8"));
  const packageLock = JSON.parse(await readFile(resolve(repositoryRoot, "package-lock.json"), "utf8"));

  assert.equal(packageJson.dependencies?.["openapi-fetch"], "0.17.0");
  assert.equal(packageJson.devDependencies?.["openapi-typescript"], "7.13.0");
  assert.equal(packageLock.packages?.["node_modules/openapi-fetch"]?.version, "0.17.0");
  assert.equal(packageLock.packages?.["node_modules/openapi-typescript"]?.version, "7.13.0");
  assert.equal(packageJson.scripts?.["openapi:generate"], generateScript);
  assert.equal(packageJson.scripts?.["openapi:check"], `${generateScript} --check`);
  assert.equal(
    packageJson.scripts?.["openapi:test"],
    "node --test openapi/openapi.test.mjs openapi/internal-health.test.mjs openapi/generated-client.test.mjs openapi/identity-admin.test.mjs",
  );
  assert.equal(
    packageJson.scripts?.verify,
    "npm run dependencies:check && npm run health:contract:test && npm run openapi:test && npm run openapi:lint && npm run openapi:check && npm run ui-api:test && npm run ui-api:check && npm run raw-fetch:test && npm run saas:tenancy:test && npm run db:tenant-rls:test && npm test && npm run typecheck && npm run lint && npm run production:imports:test && npm run production:imports:source && npm run production:release:test && npm run build && npm run production:imports:compiled && npm run implementation:status:check",
  );
});

test("reproduces the committed bytes and rejects changed or missing output without rewriting it", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zasp-m1-24-"));
  try {
    const outputPath = join(directory, "generated.ts");
    const missingPath = join(directory, "missing.ts");
    const committed = await readFile(generatedPath);
    const committedMetadata = await lstat(generatedPath);

    assert.equal(committedMetadata.isFile(), true);
    assert.equal(committedMetadata.isSymbolicLink(), false);

    const first = runGenerator(outputPath);
    assert.equal(first.status, 0, `${first.stdout}${first.stderr}`);
    assert.deepEqual(await readFile(outputPath), committed);

    const second = runGenerator(outputPath);
    assert.equal(second.status, 0, `${second.stdout}${second.stderr}`);
    assert.deepEqual(await readFile(outputPath), committed);

    const changed = Buffer.concat([committed, Buffer.from("// drift\n")]);
    await writeFile(outputPath, changed, { mode: 0o600 });
    const drift = runGenerator(outputPath, ["--check"]);
    assert.notEqual(drift.status, 0);
    assert.deepEqual(await readFile(outputPath), changed);

    const missing = runGenerator(missingPath, ["--check"]);
    assert.notEqual(missing.status, 0);
    await assert.rejects(readFile(missingPath));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("exports the Security Agent activation, run, approval, detail, pagination, and cancellation APIs", async () => {
  const generated = await readFile(generatedPath, "utf8");
  for (const operationId of ["updateAgent", "listFindings", "getFinding", "updateFinding", "acceptFindingRisk", "createFindingTicket", "listAttackPaths", "getAttackPath", "getAttackPathBreakOptions", "globalSearch", "authorizeIntegration", "authorizeIntegrationReference", "completeIntegrationOAuthCallback", "syncIntegration", "listIntegrationSyncs", "getIntegrationSync", "getIntegrationSchedule", "putIntegrationSchedule", "deleteIntegrationSchedule", "getIntegrationFreshness", "listSensors", "createSensorEnrollment", "getSensor", "updateSensor", "deleteSensor", "rotateSensorToken", "getSensorCoverage", "activateSecurityAgent", "simulateSecurityAgent", "runSecurityAgent", "listSecurityAgentRuns", "getSecurityAgentRun", "cancelSecurityAgentRun", "listSecurityAgentApprovals", "getSecurityAgentApproval", "decideSecurityAgentApproval"]) {
    assert.match(generated, new RegExp(`\\b${operationId}:`), operationId);
  }
  for (const operationId of [
    "listTests", "createTest", "getTest", "updateTest", "runTest", "listTestRuns", "getTestRun", "cancelTestRun",
    "listAttackLabRuns", "createAttackLabRun", "getAttackLabRun", "cancelAttackLabRun", "rerunAttackLabRun", "simulatePolicy", "listPolicyDecisions",
    "listSecurityActions",
    "createAIExplanation",
  ]) assert.doesNotMatch(generated, new RegExp(`\\b${operationId}:`), operationId);
  for (const operationId of ["updateFinding", "acceptFindingRisk"]) {
    const start = generated.indexOf(`readonly ${operationId}:`);
    const end = generated.indexOf("readonly responses:", start);
    assert.notEqual(start, -1, operationId);
    assert.match(generated.slice(start, end), /readonly "X-CSRF-Token": components\["parameters"\]\["CSRFToken"\]/, `${operationId} browser CSRF`);
  }
  const authorizeStart = generated.indexOf("readonly authorizeIntegration:");
  const authorizeEnd = generated.indexOf("readonly responses:", authorizeStart);
  assert.notEqual(authorizeStart, -1);
  assert.match(generated.slice(authorizeStart, authorizeEnd), /readonly "X-CSRF-Token": components\["parameters"\]\["CSRFToken"\]/);
  assert.match(generated.slice(authorizeStart, authorizeEnd), /readonly "Idempotency-Key": components\["parameters"\]\["IdempotencyKey"\]/);
  assert.match(generated.slice(authorizeStart, authorizeEnd), /readonly "application\/json": components\["schemas"\]\["EmptyInput"\]/);

  const referenceStart = generated.indexOf("readonly authorizeIntegrationReference:");
  const referenceEnd = generated.indexOf("readonly responses:", referenceStart);
  assert.notEqual(referenceStart, -1);
  const reference = generated.slice(referenceStart, referenceEnd);
  assert.match(reference, /readonly "X-CSRF-Token": components\["parameters"\]\["CSRFToken"\]/);
  assert.match(reference, /readonly "X-Zasp-Fresh-Auth": components\["parameters"\]\["FreshAuth"\]/);
  assert.match(reference, /readonly "Idempotency-Key": components\["parameters"\]\["IdempotencyKey"\]/);
  assert.match(reference, /readonly "If-Match": components\["parameters"\]\["ResourceVersion"\]/);
  assert.match(reference, /readonly "application\/json": components\["schemas"\]\["EmptyInput"\]/);

  const callbackStart = generated.indexOf("readonly completeIntegrationOAuthCallback:");
  const callbackEnd = generated.indexOf("readonly responses:", callbackStart);
  assert.notEqual(callbackStart, -1);
  const callback = generated.slice(callbackStart, callbackEnd);
  assert.match(callback, /readonly query: \{[\s\S]*readonly state: components\["schemas"\]\["IntegrationOAuthCallbackValue"\]/);
  assert.match(callback, /readonly code\?: components\["schemas"\]\["IntegrationOAuthCallbackValue"\]/);
  assert.match(callback, /readonly error\?: components\["schemas"\]\["IntegrationOAuthProviderError"\]/);
  assert.doesNotMatch(callback, /X-CSRF-Token|X-Zasp-Expected-Scope|error_description|error_uri/);

  const authorizeOperation = generated.slice(authorizeStart, callbackStart);
  assert.match(authorizeOperation, /readonly "application\/json": components\["schemas"\]\["IntegrationAuthorization"\]/);
  assert.match(authorizeOperation, /readonly "Cache-Control"\?: "no-store"/);
  assert.match(authorizeOperation, /readonly "Referrer-Policy"\?: "no-referrer"/);
  const referenceOperation = generated.slice(referenceStart, generated.indexOf("readonly completeIntegrationOAuthCallback:", referenceStart));
  assert.match(referenceOperation, /readonly "application\/json": components\["schemas"\]\["Integration"\]/);
  assert.match(referenceOperation, /readonly "Cache-Control"\?: "no-store"/);
  assert.match(referenceOperation, /readonly ETag: components\["headers"\]\["WorkflowETag"\]/);
  assert.match(referenceOperation, /readonly "X-Audit-ID": components\["headers"\]\["WorkflowAuditID"\]/);
  assert.match(referenceOperation, /readonly "X-Mutation-Receipt-ID": components\["headers"\]\["WorkflowMutationReceiptID"\]/);
  const syncStart = generated.indexOf("readonly syncIntegration:");
  const syncEnd = generated.indexOf("readonly responses:", syncStart);
  assert.notEqual(syncStart, -1);
  const sync = generated.slice(syncStart, syncEnd);
  assert.match(sync, /readonly "X-CSRF-Token"\?: components\["parameters"\]\["BrowserMutationCSRFToken"\]/);
  assert.match(sync, /readonly Origin\?: components\["parameters"\]\["BrowserMutationOrigin"\]/);
  assert.match(sync, /readonly "Idempotency-Key": components\["parameters"\]\["IdempotencyKey"\]/);
  assert.match(sync, /readonly "If-Match": components\["parameters"\]\["ResourceVersion"\]/);
  assert.match(sync, /readonly "application\/json": components\["schemas"\]\["EmptyInput"\]/);
  assert.match(generated.slice(syncStart, generated.indexOf("readonly listIntegrationSyncs:", syncStart)), /readonly 202: \{[\s\S]*readonly "application\/json": components\["schemas"\]\["IntegrationSync"\]/);

  const putScheduleStart = generated.indexOf("readonly putIntegrationSchedule:");
  const putScheduleEnd = generated.indexOf("readonly responses:", putScheduleStart);
  assert.notEqual(putScheduleStart, -1);
  const putSchedule = generated.slice(putScheduleStart, putScheduleEnd);
  assert.match(putSchedule, /readonly "If-Match": components\["parameters"\]\["ScheduleVersion"\]/);
  assert.match(putSchedule, /readonly "application\/json": components\["schemas"\]\["IntegrationScheduleInput"\]/);

  const activationStart = generated.indexOf("readonly activateSecurityAgent:");
  const activationEnd = generated.indexOf("readonly responses:", activationStart);
  assert.notEqual(activationStart, -1);
  const activation = generated.slice(activationStart, activationEnd);
  assert.match(activation, /readonly "X-CSRF-Token": components\["parameters"\]\["CSRFToken"\]/);
  assert.match(activation, /readonly "X-Zasp-Fresh-Auth": components\["parameters"\]\["FreshAuth"\]/);
  assert.match(activation, /readonly "Idempotency-Key": components\["parameters"\]\["IdempotencyKey"\]/);
  assert.match(activation, /readonly "If-Match": components\["parameters"\]\["ResourceVersion"\]/);
  assert.match(activation, /readonly "application\/json": components\["schemas"\]\["SecurityAgentActivationInput"\]/);
  assert.match(generated.slice(activationStart, generated.indexOf("readonly simulateSecurityAgent:", activationStart)), /readonly 200: \{[\s\S]*readonly "application\/json": components\["schemas"\]\["SecurityAgentActivationResult"\]/);

  const simulationStart = generated.indexOf("readonly simulateSecurityAgent:");
  const simulationEnd = generated.indexOf("readonly responses:", simulationStart);
  assert.notEqual(simulationStart, -1);
  const simulation = generated.slice(simulationStart, simulationEnd);
  assert.match(simulation, /readonly "X-CSRF-Token"\?: components\["parameters"\]\["BrowserMutationCSRFToken"\]/);
  assert.match(simulation, /readonly Origin\?: components\["parameters"\]\["BrowserMutationOrigin"\]/);
  assert.match(simulation, /readonly "Idempotency-Key": components\["parameters"\]\["IdempotencyKey"\]/);
  assert.match(simulation, /readonly "If-Match": components\["parameters"\]\["ResourceVersion"\]/);
  assert.match(simulation, /readonly "application\/json": components\["schemas"\]\["SecurityAgentSimulationInput"\]/);
  assert.match(generated.slice(simulationStart, generated.indexOf("readonly listSecurityAgentTemplates:", simulationStart)), /readonly 200: \{[\s\S]*readonly "application\/json": components\["schemas"\]\["SecurityAgentSimulation"\]/);
  assert.match(generated, /readonly SecurityAgentSimulation: \{[\s\S]*readonly plan_hash: string;[\s\S]*readonly side_effects: 0;[\s\S]*readonly version: 1;/);

  assert.match(generated, /readonly WorkflowMutationReceipt: components\["schemas"\]\["StandardWorkflowMutationReceipt"\] \| components\["schemas"\]\["OAuthCompletionWorkflowMutationReceipt"\] \| components\["schemas"\]\["ReferenceAuthorizationWorkflowMutationReceipt"\] \| components\["schemas"\]\["SyncIntegrationWorkflowMutationReceipt"\] \| components\["schemas"\]\["PutIntegrationScheduleWorkflowMutationReceipt"\] \| components\["schemas"\]\["DeleteIntegrationScheduleWorkflowMutationReceipt"\]/);
  assert.match(generated, /readonly operation: "completeIntegrationOAuth"/);
  assert.match(generated, /readonly operation: "completeIntegrationReferenceAuthorization"/);
  assert.match(generated, /readonly operation: "syncIntegration"/);
  assert.match(generated, /readonly operation: "putIntegrationSchedule"/);
  assert.match(generated, /readonly operation: "deleteIntegrationSchedule"/);
  assert.match(generated, /readonly IntegrationDeletionReceiptResult: \{[\s\S]*readonly id: components\["schemas"\]\["ProductID"\][\s\S]*readonly status: "deleted"/);
  assert.match(generated, /readonly result: components\["schemas"\]\["Policy"\] \| components\["schemas"\]\["Integration"\] \| components\["schemas"\]\["IntegrationDeletionReceiptResult"\] \| components\["schemas"\]\["SecurityAgentDefinition"\] \| components\["schemas"\]\["Finding"\]/);
  assert.match(generated, /readonly resource_kind: "integration_sync"/);
  assert.match(generated, /readonly status: components\["schemas"\]\["IntegrationSyncStatus"\]/);
  assert.match(generated, /readonly projections: components\["schemas"\]\["IntegrationProjectionStatuses"\]/);
  assert.match(generated, /readonly provider: "aws"/);
  assert.match(generated, /readonly provider: "kubernetes"/);
  const callbackOperation = generated.slice(callbackStart, generated.indexOf("readonly createEnvironment:", callbackStart));
  assert.match(callbackOperation, /readonly 303: \{[\s\S]*readonly Location\?: string[\s\S]*content\?: never/);
  assert.match(callbackOperation, /readonly "Cache-Control"\?: "no-store"/);
  assert.match(callbackOperation, /readonly "Referrer-Policy"\?: "no-referrer"/);
});

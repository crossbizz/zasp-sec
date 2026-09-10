import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { readFile, readdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

test("confidence display fixture cannot claim production correlation reachability", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const marker of ["await exerciseRuntimeConfidenceDisplay(browser.cdp, dsn)", "runtime confidence display fixture passed:", "Strong/Probable production correlation NOT RUN", "confidence fixture cleanup changed worker evidence", "data-runtime-confidence", "probable.background, exact.background", "probable.color, exact.color"]) assert.ok(source.includes(marker), marker);
});

test("six-class evidence proof requires schema44 and worker-backed scoped links", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  for (const marker of ["44|production_runtime_session_evidence", "schema 44 production_runtime_session_evidence verified", "runtime six-class evidence links proven:", "Open evidence ", "Canonical evidence metadata", "another scope exposed canonical event evidence", "revoked permission exposed canonical event evidence"]) assert.ok(source.includes(marker), marker);
  for (const marker of ["semantic observation pipeline proven:", '"credential", "use"', '"policy", "block"', 'events[1]["class"], events[1]["action"] = "file", "read"', 'events[2]["class"], events[2]["action"] = "network", "connect"']) assert.ok(worker.includes(marker), marker);
  assert.doesNotMatch(worker, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
});

test("session indexing composition requires schema42 and production checkpoint proof", async()=>{
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  assert.ok(source.includes("42|production_runtime_session_search"));
  assert.ok(source.includes("schema 42 production_runtime_session_search verified"));
  assert.ok(source.includes("production session indexing outbox proven: completion transaction, registered index worker"));
});

test("runtime query composition requires schema43 and real indexed HTTP search", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const marker of ["43|production_runtime_session_query", "schema 43 production_runtime_session_query verified", "startPolicyHistoryServer(policyHistoryPort, runtimeSearchEndpoint)", "worker-indexed runtime search API proven: structured matching, canonical counts, observed-only checkpoints and provider failure"])
    assert.ok(source.includes(marker), marker);
  assert.ok(source.includes('"/zasp-runtime-sessions-v1/_mapping"'));
  assert.ok(source.includes('"/zasp-runtime-sessions-v1/_doc/_zasp_session_schema_v1"'));
  assert.ok(source.includes('"/zasp-runtime-sessions-v1/_search"'));
});

test("runtime timeline proves reverse-ingress canonical order across real UI pages", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRuntimeSessionReads");
  const flow = source.slice(start, source.indexOf("async function exerciseRuntimeConfidenceDisplay", start));
  for (const marker of ['clickBrowserAria(cdp, "Open runtime timeline unattributed")', 'clickBrowserText(cdp, "Next event page")', 'clickBrowserText(cdp, "First event page")', "128 - index", "new Set(timeline.map", "runtime timeline proven: reverse-ingress worker events, canonical 25-plus-1 pagination, source confidence and scope reset"])
    assert.ok(flow.includes(marker), marker);
  assert.doesNotMatch(flow, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
});

test("runtime Sessions UI filters worker-written evidence and resets on scope change", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRuntimeSessionReads");
  const flow = source.slice(start, source.indexOf("async function exerciseRuntimeConfidenceDisplay", start));
  for (const marker of ['fillBrowserLabel(cdp, "Process", "/usr/bin/other")', 'fillBrowserLabel(cdp, "Process", "/usr/bin/agent")', 'clickBrowserText(cdp, "Search sessions")', "runtime Sessions UI proven: structured process filter, canonical confidence, indexing checkpoint and scope reset"])
    assert.ok(flow.includes(marker), marker);
  assert.doesNotMatch(flow, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
});
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";

test("runtime session browser proof reads worker-written evidence without seeding sessions", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRuntimeSessionReads");
  const flow = source.slice(start, source.indexOf("async function exerciseRuntimeConfidenceDisplay", start));
  assert.ok(start > 0);
  for (const text of ["await exerciseRuntimeSessionReads(browser.cdp, dsn)", "runtime session summaries proven: completion-triggered unknown collection, byte-stable replay"]) assert.ok(source.includes(text), text);
  for (const text of ["another scope exposed runtime investigation", "summary.agent_id, null", "summary.principal_id, null", "summary.kind, \"unattributed\"", "revoked investigation permission retained runtime API access", "runtime session fixture permission ownership changed"]) assert.ok(flow.includes(text), text);
  assert.doesNotMatch(flow, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
  assert.doesNotMatch(worker, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
  assert.ok(worker.includes("SQS redelivery changed runtime session summaries"));
  assert.ok(flow.includes("scope = staging"), "positive browser reads must use the worker's actual Staging scope");
});

test("session search proof requires committed evidence and real-engine filter completeness", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const worker = await readFile(new URL("../services/platform/agentsec-worker/runtime_pipeline_combined_e2e_test.go", import.meta.url), "utf8");
  const proof = await readFile(new URL("../services/platform/agentsec-worker/runtime_session_search_combined_e2e_test.go", import.meta.url), "utf8");
  const matrix = await readFile(new URL("../services/platform/agentsec-worker/runtime_session_search_filters_e2e_test.go", import.meta.url), "utf8");
  for (const marker of ["runtime session search index proven:", "real OpenSearch selector matrix passed:"]) assert.ok(source.includes(`assert.match(runtimePipelineResult.stdout, /${marker}`), marker);
  assert.ok(worker.includes("proveRuntimeSessionSearchIndex(t, ctx, admin, scope,"));
  for (const text of ["receipt.receipt_digest=project.result_digest", "complete.state='succeeded'", "receipts.Get(ctx, locator)", "index.Apply(ctx, binding, artifact.Body, archive)", "proveRuntimeStructuredSearchSelectors(t, ctx, index)", "number_of_replicas", "search API remains pending"]) assert.ok(proof.includes(text), text);
  assert.doesNotMatch(proof, /(?:INSERT INTO|UPDATE|DELETE FROM) zasp_runtime_session/);
  for (const text of ["selectors incorrectly joined different events within one session", "composite pagination incomplete", "foreign positive control absent", "when.Add(time.Nanosecond)", "synthetic component fixtures only"]) assert.ok(matrix.includes(text), text);
});

test("Home exposure E2E waits for loaded rows, not the persistent navigation title", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf('await clickBrowserTextContains(cdp, "Critical exposures")');
  const end = source.indexOf('await clickBrowserTextContains(cdp, "Pending approvals")', start);
  const flow = source.slice(start, end);
  assert.match(flow, /await waitForBrowserAction\(cdp,.*Open attack path/);
  assert.ok(flow.indexOf("await waitForBrowserAction") < flow.indexOf("await browserCountAriaPrefix"));
  assert.match(flow, /Home critical exposure route had no authoritative path/);
});

test("webhook browser E2E verifies real persisted outcome across response loss and reload", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const expected of ["integrationWebhookTestRequests", "webhook retry changed its idempotency key", "webhook retry changed its audit record", "webhook failure was not durably retained once", "webhook status reload emitted another delivery", "Signature and acceptance are unconfirmed", "1|failed"]) assert.ok(source.includes(expected));
});

test("Red Team response recovery proves committed authority without duplicate work", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const expected of ["exerciseRedTeamRetainedRun", "response loss was not injected after a real committed run", "reload automatically submitted an unresolved run", "another tenant scope exposed the retained run", "retained replay duplicated durable run authority", "1|queued|0|1|1|1|1", "1|cancelled|0|1|2|2|1", "request.body, redTeamRunRequests[0].body", "request.idempotencyKey, redTeamRunRequests[0].idempotencyKey", "request.expectedScope, expectedScope", "confirmed Red Team operation left a browser checkpoint"]) assert.ok(source.includes(expected), expected);
});

test("recommendation browser proof uses discovered targets without granting execution",async()=>{
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  for(const expected of ["exerciseRedTeamRecommendations", "Support agent", "Automation repository", "Use recommended categories", "recommendation selection created execution authority", "recommendation fixture permission ownership changed", "finally { await setPermission(false)", "Discovered identity or administrative authority warrants authorization-boundary testing"])assert.ok(source.includes(expected),expected);
});

test("Red Team runtime proof preserves real composition and exact evidence claims", async()=>{
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  const worker=await readFile(new URL("../services/platform/agentsec-worker/red_team_runtime_combined_e2e_test.go",import.meta.url),"utf8");
  const start=source.indexOf("async function exerciseRedTeamRuntime");
  const flow=source.slice(start,source.indexOf("async function exerciseRedTeamRetainedRun",start));
  for(const text of ["Save test","Run Runtime pipeline proof","redTeamRuntimeProof.run","--- PASS: TestProductionCombinedE2ERedTeamRuntime","assert.doesNotMatch(result.stdout, /--- SKIP:/)","await reloadBrowser","Verify safely","customer invocation fixture only"])assert.ok(flow.includes(text),text);
  for(const text of ["composeRedTeamWorkerRuntime(","composeRedTeamOutboxWorkerRuntime(","productionRedTeamCommand{}","redteamadapter.NewPostgresResolver(","redteamadapter.NewHandler(","outbox.Ready(ctx)","worker.Ready(ctx)","outbox.Processor.RunOnce(ctx)","worker.Processor.RunOnce(ctx)","p.queue.PublishBatch(ctx, jobs)","attempts != 1","fixture.calls.Load() != 1","!leaseCleared","s3API.GetObject(","!bytes.Equal(checksum, digest[:])","aws.ToString(object.VersionId) != version","object.ServerSideEncryption != s3types.ServerSideEncryptionAwsKms","aws.ToString(object.SSEKMSKeyId) != keyARN","customer invocation fixture only"])assert.ok(worker.includes(text),text);
  assert.equal(worker.match(/p\.queue\.PublishBatch\(ctx, jobs\)/g)?.length,2,"duplicate delivery must be physically published");
  assert.doesNotMatch(worker,/zasp_red_team_(?:finish_run|claim_run|acknowledge_outbox)\s*\(/);
  assert.doesNotMatch(worker,/newRedTeam(?:Processor|OutboxProcessor)\(/);
});

test("Red Team outcome browser proof reaches safety review without granting execution", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const start = source.indexOf("async function exerciseRedTeamRuntime");
  const flow = source.slice(start, source.indexOf("async function exerciseRedTeamRetainedRun", start));
  for (const expected of ["Unsafe behavior observed", "Cancelled", "Verify safely in Attack Lab", "Review safety decision", "Approve exact safety decision", "outcome navigation granted Attack Lab execution", "readAttackLabAuthority", "source_run_id", "Safety approval"]) assert.ok(flow.includes(expected), expected);
});

test("combined production E2E owns every local boundary and fixed assertion", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  const recoveryWorkerSource = await readFile(new URL("../services/platform/agentsec-worker/production_combined_e2e_test.go", import.meta.url), "utf8");
  for (const value of [
    "initdb", "postgres", "agentsec-migrate", "agentsec-api", "vinext", "Google Chrome",
    "/api/v1/session/start", "/auth/callback", "__Host-zasp_session", "Support agent",
    "not_found", "SIGTERM", "pg_ctl", "FIXED_NODE_VERSION", "Roll to monitor",
    "Save Security Agent definition", "configured", "Tenant-scoped response definitions",
    "lostPolicyResponseKeys", "replaceTarget", "Recover committed operations", "Acknowledge recovered result", "full-document receipt recovery", "two lost browser responses changed idempotency key", "1|2|2|1",
    "Input.dispatchKeyEvent", "browserDialogIsolation", "keyboard focus trap and restoration",
    "PAT success, replay, and zero browser receipts", "1|1|0", "workflowPageRequests", "Paged policy 1000", "Paged integration 1001",
    "Second-tab committed policy", "Expiry-race committed policy", "seedExpiringReceipt", "expired receipt left workflow mutations locked",
    "startBrowserTab", "actual two-tab delayed out-of-order ABA stale-scope recovery proven", "X-Zasp-Expected-Scope",
    "delayedFirstTabBootstrap", "secondTabBootstrapWhileFirstDelayed", "firstTabScopeStaleResponses", "X-Zasp-E2E-Tab",
    "ZASP_DEPLOYMENT_MODE", "/administration/identity-access", "member-target-local", "Member role updated; active sessions revoked",
    "ZASP_STYTCH_WEBHOOK_SECRET", "schema 19 identity_administration verified", "schema 20 security_agent_controls verified", "schema 21 security_agent_autonomous_response verified", "schema 24 security_agent_session_isolation verified",
    "production SSO, SCIM, and group-mapping browser workflow proven",
    "signed Stytch webhook replay and tenant deprovision proven",
    "group-derived browser login scope and cross-tenant denial proven",
    "E2E Workspace", "workspace onboarding did not atomically create its first authorized environment and reload boundary", "E2E Development",
    "/administration/api-access", "ZASP_TOKEN_REVEAL_KEY", "lostTokenResponses", "Save API token", "Copy token",
    "Acknowledgement failed", "Rotate E2E API token", "old API token remained valid after rotation", "api_token.reveal.acknowledge", "restartReloadURL",
    "Fresh authentication expired", "Reauthenticate", "configured provider remained falsely healthy", "CDP request timed out", "navigateBrowser", "reloadBrowser", "waitForBrowserScope", "Target.attachToTarget", "Target.closeTarget", "sessionId", "cdp.replaceTarget",
    "session-investigation-e2e", "Shell requested by E2E", "Revoke session session-investigation-e2e",
    "/administration/audit-log", "Audit exports unavailable", "/compliance/evidence", "Evidence exports unavailable",
    "/administration/data-retention", "Data deletion unavailable", "/administration/external-data-flows", "identity-provider",
    "/administration/system-health", "production administration lifecycle and hidden provider/export mutations proven",
    "/violations", "/exposure/attack-paths", "Production credential exposure 0001", "Ranked break option evidence",
    "lostFindingResponseKeys", "Finding status updated through committed-response recovery", "Accepted production exception",
    "PAT risk mutation and zero browser receipts proven", "risk pagination, detail, recovery, acceptance, and persistence proven",
    "Injected authoritative refetch failure", "receipt ACK did not follow authoritative refetch", "findings.write downgrade retained an interactive mutation or retry",
    "Loading path detail", "Loading break options", "Injected break-option failure", "route unmount did not abort both attack-path detail responses",
    "browserStorageHistoryAndCaches", "indexedDB.databases", "assertResponsiveRiskLayout", "Emulation.setDeviceMetricsOverride",
    "browser console and exception stream remained clean", "hidden risk-adjacent routes canonicalized without hidden API calls",
    "/red-team/results", "/test/attack-lab", "/reports", "/guardrails/dashboard", "/prompt-hardening",
    "schema 14 typed_inventory_cutover verified", "schema 15 runtime_data_plane verified", "schema 17 runtime_ingest_reconciliation verified", "schema 18 security_agent_execution verified", "schema 19 identity_administration verified", "schema 20 security_agent_controls verified", "schema 21 security_agent_autonomous_response verified", "ZASP_CONNECTOR_AWS_REGION", "ZASP_CONNECTOR_ROLE_ARN",
    "ZASP_DISCOVERY_PARSER_VERSION", "ZASP_DISCOVERY_TOOL_VERSION",
    "ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE", "ZASP_CONNECTOR_KMS_KEY_ARN", "ZASP_CONNECTOR_SECRET_PREFIX",
    "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS",
		"ZASP_FINDING_TICKET_EGRESS_CIDRS", "/api/v1/findings/{id}/ticket", "findingTicketRequests",
		"finding ticket retained one idempotency key across retry and reload",
    "ZASP_GITHUB_CLIENT_ID", "ZASP_GITHUB_CLIENT_SECRET_REFERENCE", "ZASP_GITHUB_APP_ID", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE",
    "generateHarnessGitHubAppPrivateKey", "github-app-private-key.pem", "ZASP_OKTA_CLIENT_ID", "ZASP_OKTA_CLIENT_SECRET_REFERENCE",
    "/api/v1/integrations/{id}/authorize", "/api/v1/integrations/oauth/callback", "assertRejectedConnectorResponse",
    "unavailable managed OAuth authority remained fail-closed with zero provider calls", "browser launch connector setup catalog proven", "Configure Amazon Web Services", "Configure Kubernetes", "connectorAuthorizationRequests", "browserConnectorForensics", "Page.getNavigationHistory",
    "live AWS/GitHub/Okta connector success remains typed external evidence", "zero provider/AWS calls",
    "integrationDeleteRequests", "malformNextIntegrationDeleteResponse", "completeHarnessConnectorRevocation",
    "external-provider completion simulation", "real DELETE 202 durable revoking receipt",
    "same idempotency key + If-Match", "Retry pending integration deletion", "no premature deleted toast/removal",
    "reload revocation receipt remained locked", "live provider revocation NOT RUN",
		"malformed public 202 response replay", "harness direct-public-API replay",
    "schema 14 typed_inventory_cutover verified", "agentsec-worker",
    "ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL", "ZASP_PROJECTION_RISK_DB_PRINCIPAL",
    "ZASP_PROJECTION_GRAPH_DB_PRINCIPAL", "ZASP_PROJECTION_SEARCH_DB_PRINCIPAL",
    "ZASP_WORKER_MODE", "outbox", "discovery", "scheduler", "projection-risk", "projection-graph", "projection-search",
    "ZASP_DATABASE_AUTHORITY", "zasp_outbox_worker", "zasp_discovery_worker", "zasp_discovery_scheduler",
    "zasp_projection_risk_worker", "zasp_projection_graph_worker", "zasp_projection_search_worker",
    "ZASP_WORKER_ID", "ZASP_POLL_INTERVAL", "ZASP_LEASE_DURATION", "ZASP_BATCH_SIZE", "ZASP_SHUTDOWN_TIMEOUT",
    "/api/v1/integrations/{id}/sync", "/api/v1/integrations/{id}/syncs", "/api/v1/integrations/{id}/syncs/{syncId}",
    "/api/v1/integrations/{id}/schedule", "/api/v1/integrations/{id}/freshness",
    "/api/v1/integrations/${integrationID}/setup-status", "multi-tenant AWS, Kubernetes, GitHub, and Okta setup scope remained exact and credential-redacted",
    "real public manual sync returned 202", "public schedule create/read/delete proven",
    "public sync history/detail/freshness proven", "Task4 reload preserved authoritative discovery state",
    "Task4 discovery forensics found no token, credential reference, artifact key, cursor, or worker identity in persistent browser state",
    "Task4 opaque pagination cursors remained same-origin transport-only data",
    "integration_version,configuration_digest,requested_scopes",
    "202 Retry-After window emitted an early integration DELETE",
    "live AWS/Kubernetes/GitHub/Okta collection and managed SQS/S3/OpenSearch/Neo4j remain NOT RUN",
    "zero fake collection/projection database completion", "cleanup Task4 workers",
    "ZASP_MIGRATION_DB_PRINCIPAL", "ZASP_DISCOVERY_API_DB_PRINCIPAL", "ZASP_DISCOVERY_WORKER_DB_PRINCIPAL",
    "ZASP_RUNTIME_INGEST_DB_PRINCIPAL", "ZASP_RUNTIME_WORKER_DB_PRINCIPAL", "ZASP_OUTBOX_WORKER_DB_PRINCIPAL", "ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL",
    "ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL", "ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL", "ZASP_RUNTIME_INDEX_DB_PRINCIPAL",
    "ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL", "ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL", "ZASP_GATEWAY_CONTROL_DB_PRINCIPAL",
    "ZASP_SECURITY_AGENT_API_DB_PRINCIPAL", "ZASP_SECURITY_AGENT_WORKER_DB_PRINCIPAL", "ZASP_SECURITY_AGENT_POSTGRES_DSN",
    "provisionPostgresPrincipals", "apiDSN", "zasp.production-e2e.test", "zasp.production-e2e.localhost", "--host-resolver-rules", "SIGQUIT",
    "schema 14 typed_inventory_cutover verified", "agentsec-worker-e2e", "runDeterministicLocalDiscovery",
    "deterministic local provider and artifact authority completed public sync", "typed inventory public routes derive only from complete discovery snapshots",
    "typed inventory browser deep-link reload proven", "second-source retention proven", "complete-empty source removal proven",
    "failed and partial discovery retained the last complete inventory", "typed inventory database forensics proved exact current source/snapshot/evidence bindings",
    "/api/v1/tools", "/api/v1/identities", "/api/v1/runtimes", "inventory=pid_",
		"assertTask6SensorBrowserState", "/api/v1/sensors", "/coverage", "/rotate-token", "Runtime sensors", "Enroll sensor",
		"Create enrollment", "Copy this token now", "Save sensor", "Rotate enrollment token", "Delete sensor",
		"Helm deployment boundary", "sensorAgent.enabled=true", "sensorAgent.tokenSecretName=<pre-created-secret-name>",
		"Task6 authenticated heartbeat and healthy sensor coverage proven", "Task6 token rotation and version-pinned sensor update proven",
    "Task6 reload and deletion left no enrollment credential in persistent browser state", "zasp_runtime_sensor_heartbeat",
		"exerciseSecurityAgentAutomaticLifecycle", "production-e2e-security-agent", "multi-tenant supervised approval, autonomous response, exact-session isolation with unrelated allowance and cleanup, signed temporary policy apply/cleanup, and irreversible connector revocation proven", "Verified attack path containment", "verified attack path did not create one exact version-bound supervised plan", "attack-path scheduler duplicated a durable run or receipt", "TestProductionCombinedE2ETemporaryPolicyActionWorker", "Apply temporary containment policy", "Isolate runtime session", "ZASP_COMBINED_E2E_ACTION_SESSION_ID", "ZASP_COMBINED_E2E_ACTION_OTHER_SESSION_ID", "TTL 600s", "zasp_e2e_security_agent_action",
		"exerciseHomeDailyOperations", "Daily ops stale sensor", "Foreign daily ops stale sensor", "dailyOpsSensorToken", "foreignDailyOpsSensorToken", "Home exposed every daily-ops item", "daily-ops sensor disappeared without exact deleted state", "Home daily-ops routing preserved explicit terminal and degraded authority",
		"agentsecctl", "schema 27 production_recovery verified", "schema 28 production_policy_deployment verified", "schema 29 production_home_attention verified", "schema 30 production_approval_notification verified", "schema 31 production_workflow_compatibility verified", "schema 32 production_security_agent_planner verified", "schema 33 production_security_agent_attack_path verified", "schema 34 production_integration_setup verified", "schema 35 production_integration_webhook verified", "ZASP_POLICY_DEPLOYMENT_DB_PRINCIPAL", "ZASP_RECOVERY_WORKER_DB_PRINCIPAL", "ZASP_RECOVERY_OUTBOX_DB_PRINCIPAL",
		"ZASP_COMBINED_E2E_POLICY_DEPLOYMENT_DSN", "central policy deployment signed temporary gateway policy", "central policy deployment signed session isolation gateway policy",
		"runProductionRecoveryLifecycle", "TestProductionCombinedE2ERecoveryWorker", "ZASP_COMBINED_E2E_RECOVERY_PHASE",
		"committed recovery response loss replayed one backup, outbox, audit, and receipt", "signed recovery manifest published last", "cross-tenant recovery read rejected",
		"Recovery rehearsal completed", "Temporary resources deleted", "live Neon/AWS/S3/KMS/Kubernetes recovery remains NOT RUN",
		"exerciseProductionAttackLabLifecycle", "TestProductionCombinedE2EAttackLabWorker", "ZASP_COMBINED_E2E_ATTACK_LAB_CONTROLLER_DSN",
		"Review safety decision", "Approve exact safety decision", "composed Attack Lab outbox and controller completed deterministic isolated sandbox evidence",
  ]) assert.match(source, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  const apiEnvironment = source.slice(source.indexOf("const apiEnvironment = {"), source.indexOf("api = startChild(apiBinary"));
  for (const value of ["HOSTNAME", "ZASP_STYTCH_WEBHOOK_SECRET", "ZASP_SECURITY_AGENT_POSTGRES_DSN", "ZASP_DISCOVERY_PARSER_VERSION", "ZASP_DISCOVERY_TOOL_VERSION", "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS", "ZASP_FINDING_TICKET_EGRESS_CIDRS"]) assert.match(apiEnvironment, new RegExp(value));
  const outboxBoundary = source.slice(source.indexOf("const outbox = startTask4Worker"), source.indexOf("for (const candidate of", source.indexOf("const outbox = startTask4Worker")));
  assert.match(outboxBoundary, /waitForChildExit\(outbox, 10_000\)/);
  assert.match(outboxBoundary, /status: 1, signal: null/);
  assert.doesNotMatch(outboxBoundary, /assertFailClosedTask4Worker/);
  const discoveryBrowserBoundary = source.slice(source.indexOf("async function assertTask4BrowserPublicState"), source.indexOf("async function navigateBrowser", source.indexOf("async function assertTask4BrowserPublicState")));
  assert.equal(discoveryBrowserBoundary.match(/await waitForBrowserText\(cdp, \/Risk projection: pending\/\)/g)?.length, 2);
  assert.equal(discoveryBrowserBoundary.match(/await waitForBrowserText\(cdp, \/No automatic sync schedule\/\)/g)?.length, 2);
  assert.match(discoveryBrowserBoundary, /const \{ resources, \.\.\.persistentForensics \} = forensics/);
  assert.match(discoveryBrowserBoundary, /resources\.every\(\(resource\) => new URL\(resource\)\.origin === publicOrigin\)/);
  assert.doesNotMatch(source, /Shown only once/);
  assert.doesNotMatch(source, /"Page\.(?:navigate|reload)"/);
  assert.doesNotMatch(source, /zasp_execution_(?:finish_job|finish_projection|apply_complete_snapshot)\s*\(/i);
  const seedBoundary = source.slice(source.indexOf("async function seedPostgres"), source.indexOf("async function exercisePublicDiscoveryLifecycle"));
  assert.doesNotMatch(seedBoundary, /INSERT INTO zasp_inventory_/i);
  assert.doesNotMatch(seedBoundary, /'(?:home|agents|tools|identities|runtimes|(?:agent|tool|identity|runtime|asset):pid_[0-9a-f-]{36}|agent_(?:capabilities|relationships|sessions):pid_[0-9a-f-]{36})'/i);
	const securityAgentBoundary = source.slice(source.indexOf("async function exerciseSecurityAgentAutomaticLifecycle"), source.indexOf("async function", source.indexOf("async function exerciseSecurityAgentAutomaticLifecycle") + 15));
	for (const value of ["security-agent", "zasp_security_agent_worker", "30s", "Validate definition", "Enable supervised execution", "Approve", "autonomous", "pid_90000001-0000-4000-8000-000000000001", "Apply temporary containment policy", "Isolate runtime session", "TTL 600s", "create_temporary_policy", "isolate_session", "runTemporaryPolicyActionWorker", "cleanup_pending", "remediated\\|cleaned\\|4\\|3", "contained\\|cleanup_pending\\|1\\|3\\|0", "remediated\\|cleaned\\|2\\|4", "Revoke integration connection", "Identity administrator approval required", "revoke_integration_connection", "runConnectorRevocationProviderWorker", "INSERT INTO zasp_risk_finding_evidence", "remediated\\|verified\\|verified\\|revoked\\|revoked\\|pending\\|pending_authorization"]) assert.match(securityAgentBoundary, new RegExp(value));
	for (const field of ["artifact_reference", "artifact_key", "artifact_version_id", "size_bytes", "tool_version"]) assert.match(securityAgentBoundary, new RegExp(field));
	const connectorWorkerBoundary = source.slice(source.indexOf("async function runConnectorRevocationProviderWorker"), source.indexOf("async function", source.indexOf("async function runConnectorRevocationProviderWorker") + 15));
	for (const value of ["TestProductionCombinedE2EConnectorRevocationWorker", "real connector reconciler revoked exact reference", "ZASP_COMBINED_E2E_CONNECTOR_REFERENCE"]) assert.match(connectorWorkerBoundary, new RegExp(value));
	assert.match(connectorWorkerBoundary, /ZASP_COMBINED_E2E_CONNECTOR_DSN: `postgres:\/\/zasp_e2e_api@/);
	assert.match(source, /ZASP_COMBINED_E2E_GATEWAY_DSN: `postgres:\/\/zasp_e2e_gateway_control@/);
	assert.doesNotMatch(source, /ZASP_COMBINED_E2E_GATEWAY_DSN: `postgres:\/\/zasp_e2e_gateway@/);
	assert.doesNotMatch(securityAgentBoundary, /zasp_security_agent_(?:schedule_triggers|prepare_run|execute_run)(?:_v21)?\s*\(/i);
	assert.match(securityAgentBoundary, /NOT EXISTS\(SELECT 1 FROM zasp_security_agent_runs run WHERE \(run\.organization_id,run\.workspace_id,run\.environment_id,run\.run_id\)=\(effect\.organization_id,effect\.workspace_id,effect\.environment_id,effect\.run_id\)\)/i);
	assert.doesNotMatch(securityAgentBoundary, /JOIN zasp_security_agent_runs run USING\(organization_id,workspace_id,environment_id,run_id\)[\s\S]*effect\.organization_id<>run\.organization_id/i);
	const recoveryBoundary = source.slice(source.indexOf("async function runProductionRecoveryLifecycle"), source.indexOf("async function", source.indexOf("async function runProductionRecoveryLifecycle") + 15));
	for (const value of ["backup", "start", "--credential-file", "--ca-bundle-file", "TestProductionCombinedE2ERecoveryWorker", "ZASP_COMBINED_E2E_RECOVERY_ARTIFACT_FILE", "/administration/recovery", "Start restore rehearsal", "committed recovery response loss replayed one backup, outbox, audit, and receipt", "cross-tenant recovery read rejected", "signed recovery manifest published last", "Temporary resources deleted"]) assert.match(recoveryBoundary, new RegExp(value));
	assert.match(recoveryBoundary, /recoveryOrigin\.origin}\/api\/v1\/recovery\/backups/);
	assert.match(recoveryBoundary, /JSON\.stringify\(\{ backup_id: foreignBackupID, retention_days: 30 \}\)/);
	assert.doesNotMatch(recoveryBoundary, /publicOrigin}\/api\/v1\/recovery\/backups/);
	assert.ok(recoveryBoundary.indexOf('document.readyState !== "loading"') < recoveryBoundary.indexOf("sessionStorage.setItem"), "recovery state was written before the replacement product document loaded");
	assert.match(recoveryBoundary, /recovery session state was not retained in the loaded product document/);
	assert.doesNotMatch(recoveryBoundary, /zasp_recovery_(?:finish_backup|finish_restore|fail_operation|acknowledge_outbox)\s*\(/i);
	const recoveryWorkerBoundary = recoveryWorkerSource.slice(recoveryWorkerSource.indexOf("func TestProductionCombinedE2ERecoveryWorker"), recoveryWorkerSource.indexOf("func combinedE2ERecoveryDatabase"));
	for (const value of ["composeRecoveryOutboxWorkerRuntime", "composeRecoveryWorkerRuntime", ".Ready(ctx)", ".Processor.RunOnce(ctx)", ".Close()"]) assert.match(recoveryWorkerBoundary, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
	assert.doesNotMatch(recoveryWorkerBoundary, /newRecovery(?:Outbox|Backup|Restore)Processor/);
	const attackLabBoundary = recoveryWorkerSource.slice(recoveryWorkerSource.indexOf("func TestProductionCombinedE2EAttackLabWorker"), recoveryWorkerSource.indexOf("func TestProductionCombinedE2ERecoveryWorker"));
	for (const value of ["composeAttackLabOutboxWorkerRuntime", "composeAttackLabWorkerRuntime", ".Ready(ctx)", ".Processor.RunOnce(ctx)", ".Close()", "ZASP_COMBINED_E2E_ATTACK_LAB_EXPECT_CANCELLED", "composed Attack Lab outbox and controller acknowledged cancelled run without sandbox side effects"]) assert.match(attackLabBoundary, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
	assert.doesNotMatch(attackLabBoundary, /newAttackLab(?:Outbox|Processor)/);
  for (const unsafeControl of ["Start bounded run", "waiting_approval", "Simulate policy", "Decision history"]) {
    const escaped = unsafeControl.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    assert.doesNotMatch(source, new RegExp(`(?:clickBrowserText|clickBrowserTextContains|clickBrowserAria)\\([^\\n]*${escaped}`, "i"));
  }
  assert.doesNotMatch(source, /(?:^|[/])\.env(?:$|[/ ])|docker|kubectl|localhost:\d{2,5}/i);
});

test("owned cleanup is idempotent", async () => {
	let calls = 0;
	const controller = installBoundedSignalCleanup(async () => { calls += 1; }, { timeout: 100 });
	try {
		const first = controller.run();
		const second = controller.run();
		assert.equal(first, second);
		await Promise.all([first, second]);
		assert.equal(calls, 1);
	} finally {
		controller.dispose();
	}
});

test("PostgreSQL tool discovery does not depend on a macOS installation path", async () => {
  const source=await readFile(new URL("./production-combined-e2e.mjs",import.meta.url),"utf8");
  assert.ok(/execFileSync\("pg_config", \["--bindir"\]/.test(source));
  assert.ok(/path\.isAbsolute\(postgresBin\)/.test(source));
  assert.ok(!/const postgresBin = "\/opt\/homebrew/.test(source));
});

test("combined production E2E removes owned processes and temp root on SIGTERM", { timeout: 60_000 }, async () => {
  const before = new Set((await readdir(os.tmpdir())).filter((value) => value.startsWith("zasp-production-e2e-")));
  const child = spawn(process.execPath, [fileURLToPath(new URL("./production-combined-e2e.mjs", import.meta.url))], { stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (value) => { output += value; });
  child.stderr.on("data", (value) => { output += value; });
  await waitFor(() => output.includes("combined E2E: disposable PostgreSQL ready"), 20_000, () => output);
  const owned = (await readdir(os.tmpdir())).filter((value) => value.startsWith("zasp-production-e2e-") && !before.has(value));
  assert.equal(owned.length, 1, `owned roots: ${owned.join(", ")}`);
  const ownedRoot = `${os.tmpdir()}/${owned[0]}`;
  child.kill("SIGTERM");
  const [status, signal] = await Promise.race([once(child, "exit"), rejectAfter(45_000, () => `harness did not exit after SIGTERM: ${output}`)]);
  assert.equal(signal, null);
  assert.equal(status, 143);
  assert.equal((await readdir(os.tmpdir())).includes(owned[0]), false, `temporary root survived: ${ownedRoot}`);
  const processes = spawnSync("ps", ["-axo", "command="], { encoding: "utf8" });
  assert.equal(processes.status, 0);
  assert.doesNotMatch(processes.stdout, new RegExp(escapeRegExp(ownedRoot)));
  assert.match(output, /combined E2E: cleanup files/);
});

test("combined runtime proof removes owned containers and processes on real SIGTERM", { timeout: 240_000, skip: process.env.ZASP_RUNTIME_PIPELINE_SIGNAL_TEST !== "true" }, async () => {
  const listContainers = () => {
    const result = spawnSync("docker", ["ps", "--all", "--quiet", "--no-trunc", "--filter", "label=zasp.proof=runtime-pipeline"], { encoding: "utf8", timeout: 5000 });
    assert.equal(result.status, 0);
    return new Set(result.stdout.trim().split("\n").filter(Boolean));
  };
  const beforeContainers = listContainers();
  const beforeRoots = new Set((await readdir(os.tmpdir())).filter((value) => value.startsWith("zasp-production-e2e-")));
  const child = spawn(process.execPath, [fileURLToPath(new URL("./production-combined-e2e.mjs", import.meta.url))], { env: { ...process.env, ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY: "true" }, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (value) => { output += value; });
  child.stderr.on("data", (value) => { output += value; });
  try {
    await waitFor(() => output.includes("combined E2E: owned runtime dependencies ready") || child.exitCode !== null, 180_000, () => output);
    assert.equal(child.exitCode, null, output);
    const ownedContainers = [...listContainers()].filter((id) => !beforeContainers.has(id));
    const ownedRoots = (await readdir(os.tmpdir())).filter((value) => value.startsWith("zasp-production-e2e-") && !beforeRoots.has(value));
    assert.equal(ownedContainers.length, 2);
    assert.equal(ownedRoots.length, 1);
    child.kill("SIGTERM");
    const [status, signal] = await Promise.race([once(child, "exit"), rejectAfter(45_000, () => output)]);
    assert.equal(status, 143, output);
    assert.equal(signal, null);
    for (const id of ownedContainers) assert.equal(listContainers().has(id), false, `owned container survived: ${id}`);
    assert.equal((await readdir(os.tmpdir())).includes(ownedRoots[0]), false);
    const processes = spawnSync("ps", ["-axo", "command="], { encoding: "utf8" });
    assert.equal(processes.status, 0);
    assert.doesNotMatch(processes.stdout, new RegExp(escapeRegExp(`${os.tmpdir()}/${ownedRoots[0]}`)));
    assert.match(output, /combined E2E: cleanup files/);
  } finally {
    if (child.exitCode === null) child.kill("SIGTERM");
  }
});

test("composed Red Team runtime removes its owned container on real SIGTERM", { timeout:420_000, skip:process.env.ZASP_RED_TEAM_RUNTIME_SIGNAL_TEST!=="true" }, async()=>{
  const beforeRoots=new Set((await readdir(os.tmpdir())).filter(value=>value.startsWith("zasp-production-e2e-")));
  const child=spawn(process.execPath,[fileURLToPath(new URL("./production-combined-e2e.mjs",import.meta.url))],{env:{...process.env,ZASP_COMBINED_E2E_RED_TEAM_RUNTIME:"true"},stdio:["ignore","pipe","pipe"]});
  let output="";child.stdout.on("data",value=>{output+=value;});child.stderr.on("data",value=>{output+=value;});
  try{
    await waitFor(()=>output.includes("browser-created Red Team definition and run ready for pinned runtime") || child.exitCode!==null,360_000,()=>output);
    assert.equal(child.exitCode,null,output);
    const roots=(await readdir(os.tmpdir())).filter(value=>value.startsWith("zasp-production-e2e-")&&!beforeRoots.has(value));
    assert.equal(roots.length,1);
    const ownedRoot=path.join(os.tmpdir(),roots[0]);
    let ownedID;
    await waitFor(()=>{
      const result=spawnSync("docker",["ps","--all","--quiet","--no-trunc","--filter","label=zasp.proof=red-team-runtime"],{encoding:"utf8",timeout:3000});
      assert.equal(result.status,0);
      for(const id of result.stdout.trim().split("\n").filter(Boolean)){
        const inspect=spawnSync("docker",["inspect",id],{encoding:"utf8",timeout:3000});
        if(inspect.status!==0)continue;
        const record=JSON.parse(inspect.stdout)[0];
        if(record.Mounts?.some(mount=>mount.Source===path.join(ownedRoot,"red-team-worker.test"))&&record.State?.Running){ownedID=id;return true;}
      }
      return false;
    },15_000,()=>output);
    child.kill("SIGTERM");
    const [status,signal]=await Promise.race([once(child,"exit"),rejectAfter(45_000,()=>output)]);
    assert.equal(status,143,output);assert.equal(signal,null);
    const remaining=spawnSync("docker",["inspect",ownedID],{encoding:"utf8",timeout:3000});
    assert.notEqual(remaining.status,0);assert.match(remaining.stderr,/No such (object|container)/i);
    assert.equal((await readdir(os.tmpdir())).includes(roots[0]),false);
    const processes=spawnSync("ps",["-axo","command="],{encoding:"utf8"});assert.equal(processes.status,0);assert.doesNotMatch(processes.stdout,new RegExp(escapeRegExp(ownedRoot)));
    assert.match(output,/combined E2E: cleanup files/);
  }finally{if(child.exitCode===null&&child.signalCode===null){child.kill("SIGTERM");await Promise.race([once(child,"exit"),rejectAfter(45_000,()=>output)]);}}
});

async function waitFor(predicate, timeout, describe) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail(describe());
}

function rejectAfter(milliseconds, describe) {
	return new Promise((_, reject) => {
		const timer = setTimeout(() => reject(new Error(describe())), milliseconds);
		timer.unref();
	});
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

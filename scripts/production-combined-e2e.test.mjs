import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { once } from "node:events";
import { readFile, readdir } from "node:fs/promises";
import os from "node:os";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";

test("combined production E2E owns every local boundary and fixed assertion", async () => {
  const source = await readFile(new URL("./production-combined-e2e.mjs", import.meta.url), "utf8");
  for (const value of [
    "initdb", "postgres", "agentsec-migrate", "agentsec-api", "vinext", "Google Chrome",
    "/api/v1/session/start", "/auth/callback", "__Host-zasp_session", "Support agent",
    "not_found", "SIGTERM", "pg_ctl", "FIXED_NODE_VERSION", "Roll to monitor",
    "Save Security Agent definition", "configured", "Durable, scoped response definitions",
    "lostPolicyResponseKeys", "replaceTarget", "Recover committed operations", "Acknowledge recovered result", "full-document receipt recovery", "two lost browser responses changed idempotency key", "1|2|2|1",
    "Input.dispatchKeyEvent", "browserDialogIsolation", "keyboard focus trap and restoration",
    "PAT success, replay, and zero browser receipts", "1|1|0", "workflowPageRequests", "Paged policy 1000", "Paged integration 1001",
    "Second-tab committed policy", "Expiry-race committed policy", "seedExpiringReceipt", "expired receipt left workflow mutations locked",
    "startBrowserTab", "actual two-tab delayed out-of-order ABA stale-scope recovery proven", "X-Zasp-Expected-Scope",
    "delayedFirstTabBootstrap", "secondTabBootstrapWhileFirstDelayed", "firstTabScopeStaleResponses", "X-Zasp-E2E-Tab",
    "ZASP_DEPLOYMENT_MODE", "/administration/identity-access", "member-target-local", "Member role updated; active sessions revoked",
    "E2E Workspace", "workspace onboarding did not atomically create its first authorized environment and reload boundary", "E2E Development",
    "/administration/api-access", "ZASP_TOKEN_REVEAL_KEY", "lostTokenResponses", "Save API token", "Copy token",
    "Acknowledgement failed", "Rotate E2E API token", "old API token remained valid after rotation", "api_token.reveal.acknowledge", "restartReloadURL",
    "Fresh authentication expired", "Reauthenticate", "configured provider remained falsely healthy", "CDP request timed out", "navigateBrowser", "reloadBrowser", "Target.attachToTarget", "Target.closeTarget", "sessionId", "cdp.replaceTarget",
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
    "schema 13 production_discovery_execution verified", "ZASP_CONNECTOR_AWS_REGION", "ZASP_CONNECTOR_ROLE_ARN",
    "ZASP_DISCOVERY_PARSER_VERSION", "ZASP_DISCOVERY_TOOL_VERSION",
    "ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE", "ZASP_CONNECTOR_KMS_KEY_ARN", "ZASP_CONNECTOR_SECRET_PREFIX",
    "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS",
    "ZASP_GITHUB_CLIENT_ID", "ZASP_GITHUB_CLIENT_SECRET_REFERENCE", "ZASP_GITHUB_APP_ID", "ZASP_GITHUB_PRIVATE_KEY_REFERENCE",
    "generateHarnessGitHubAppPrivateKey", "github-app-private-key.pem", "ZASP_OKTA_CLIENT_ID", "ZASP_OKTA_CLIENT_SECRET_REFERENCE",
    "/api/v1/integrations/{id}/authorize", "/api/v1/integrations/oauth/callback", "assertRejectedConnectorResponse",
    "connector authorization operations remain absent from product UI", "browserConnectorForensics", "Page.getNavigationHistory",
    "live AWS/GitHub/Okta connector success remains typed external evidence", "zero provider/AWS calls",
    "integrationDeleteRequests", "malformNextIntegrationDeleteResponse", "completeHarnessConnectorRevocation",
    "external-provider completion simulation", "real DELETE 202 durable revoking receipt",
    "same idempotency key + If-Match", "Retry pending integration deletion", "no premature deleted toast/removal",
    "reload revocation receipt remained locked", "live provider revocation NOT RUN",
		"malformed public 202 response replay", "harness direct-public-API replay",
    "schema 13 production_discovery_execution verified", "agentsec-worker",
    "ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL", "ZASP_PROJECTION_RISK_DB_PRINCIPAL",
    "ZASP_PROJECTION_GRAPH_DB_PRINCIPAL", "ZASP_PROJECTION_SEARCH_DB_PRINCIPAL",
    "ZASP_WORKER_MODE", "outbox", "discovery", "scheduler", "projection-risk", "projection-graph", "projection-search",
    "ZASP_DATABASE_AUTHORITY", "zasp_outbox_worker", "zasp_discovery_worker", "zasp_discovery_scheduler",
    "zasp_projection_risk_worker", "zasp_projection_graph_worker", "zasp_projection_search_worker",
    "ZASP_WORKER_ID", "ZASP_POLL_INTERVAL", "ZASP_LEASE_DURATION", "ZASP_BATCH_SIZE", "ZASP_SHUTDOWN_TIMEOUT",
    "/api/v1/integrations/{id}/sync", "/api/v1/integrations/{id}/syncs", "/api/v1/integrations/{id}/syncs/{syncId}",
    "/api/v1/integrations/{id}/schedule", "/api/v1/integrations/{id}/freshness",
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
    "provisionPostgresPrincipals", "apiDSN", "zasp.production-e2e.test", "--host-resolver-rules", "SIGQUIT",
  ]) assert.match(source, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  const apiEnvironment = source.slice(source.indexOf("const apiEnvironment = {"), source.indexOf("api = startChild(apiBinary"));
  for (const value of ["HOSTNAME", "ZASP_DISCOVERY_PARSER_VERSION", "ZASP_DISCOVERY_TOOL_VERSION", "ZASP_AWS_CUSTOMER_ROLE_PREFIXES", "ZASP_AWS_CUSTOMER_ROLE_ARNS", "ZASP_KUBERNETES_EGRESS_CIDRS"]) assert.match(apiEnvironment, new RegExp(value));
  const outboxBoundary = source.slice(source.indexOf("const outbox = startTask4Worker"), source.indexOf("for (const candidate of", source.indexOf("const outbox = startTask4Worker")));
  assert.match(outboxBoundary, /waitForChildExit\(outbox, 10_000\)/);
  assert.match(outboxBoundary, /status: 1, signal: null/);
  assert.doesNotMatch(outboxBoundary, /assertFailClosedTask4Worker/);
  const discoveryBrowserBoundary = source.slice(source.indexOf("async function assertTask4BrowserPublicState"), source.indexOf("async function navigateBrowser", source.indexOf("async function assertTask4BrowserPublicState")));
  assert.equal(discoveryBrowserBoundary.match(/await waitForBrowserText\(cdp, \/Risk projection: unavailable\/\)/g)?.length, 2);
  assert.equal(discoveryBrowserBoundary.match(/await waitForBrowserText\(cdp, \/No automatic sync schedule\/\)/g)?.length, 2);
  assert.match(discoveryBrowserBoundary, /const \{ resources, \.\.\.persistentForensics \} = forensics/);
  assert.match(discoveryBrowserBoundary, /resources\.every\(\(resource\) => new URL\(resource\)\.origin === publicOrigin\)/);
  assert.doesNotMatch(source, /Shown only once/);
  assert.doesNotMatch(source, /"Page\.(?:navigate|reload)"/);
  assert.doesNotMatch(source, /zasp_execution_(?:finish_job|finish_projection|apply_complete_snapshot)\s*\(/i);
  for (const unsafeControl of ["Enroll sensor", "Create enrollment", "Start bounded run", "waiting_approval", "one-time sensor credential", "Simulate policy", "Decision history"]) {
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

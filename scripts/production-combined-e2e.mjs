import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createHmac, generateKeyPairSync } from "node:crypto";
import { once } from "node:events";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";
import { reloadBrowserPage } from "./browser-e2e-helpers.mjs";
import { createRuntimePipelineDependencies } from "./runtime-pipeline-dependencies.mjs";

const FIXED_NODE_VERSION = "v22.23.1";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const platform = path.join(root, "services", "platform");
const postgresBin = "/opt/homebrew/bin";
const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const productHostname = "zasp.production-e2e.test";
const recoveryHostname = "zasp.production-e2e.localhost";
const findingTicketOperation = "/api/v1/findings/{id}/ticket";
const terminalRevocationIntegrationID = "pid_72000001-0000-4000-8000-000000000001";
const reloadRevocationIntegrationID = "pid_72000002-0000-4000-8000-000000000002";
const task4DiscoveryIntegrationID = "pid_73000001-0000-4000-8000-000000000001";
const task5KubernetesAIntegrationID = "pid_74000001-0000-4000-8000-000000000001";
const task5KubernetesBIntegrationID = "pid_74000002-0000-4000-8000-000000000002";
const task5KubernetesPartialIntegrationID = "pid_74000003-0000-4000-8000-000000000003";
const task5KubernetesFailedIntegrationID = "pid_74000004-0000-4000-8000-000000000004";
const task5GitHubIntegrationID = "pid_75000001-0000-4000-8000-000000000001";
const task5OktaIntegrationID = "pid_76000001-0000-4000-8000-000000000001";
const attackLabSourceRunID = "pid_7f300001-0000-4000-8000-000000000001";
const attackLabDefinitionID = "pid_7f300002-0000-4000-8000-000000000002";
const attackLabTargetID = "pid_7f300003-0000-4000-8000-000000000003";
const attackLabBindingID = "pid_7f300004-0000-4000-8000-000000000004";
const identityGroupReference = "scim-group-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c88";
const stytchWebhookSecret = "whsec_MTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTE=";

if (process.version !== FIXED_NODE_VERSION) throw new Error(`production combined E2E requires Node ${FIXED_NODE_VERSION}`);

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "zasp-production-e2e-"));
const children = [];
const runtimePipelineDependencies = createRuntimePipelineDependencies(command);
let proxy;
let identity;
let policyHistory;
let api;
let postgres;
let web;
let browser;
let secondBrowserTab;
const task4Workers = [];
let observedSessionCookie = false;
const lostPolicyResponseKeys = [];
const integrationDeleteRequests = [];
const workflowPageRequests = { policies: [], integrations: [] };
const riskPageRequests = { findings: [], attackPaths: [] };
const riskRecoverySequence = [];
const delayedRiskDetailResponses = [];
const lostFindingResponseKeys = [];
const findingTicketRequests = [];
const integrationWebhookTestRequests = [];
const connectorAuthorizationRequests = [];
const productAPIRequests = [];
const policyHistoryRequests = [];
const browserConsoleErrors = [];
const browserConsoleMessages = [];
const administrationRequests = [];
const lostTokenResponses = { create: false, rotate: false, reveal: false, acknowledge: false };
const tokenMutationKeys = { create: [], rotate: [] };
let identityOAuthStarts = 0;
let nextIdentityLogin = "admin";
let pendingIdentityLogin = "admin";
const stytchProviderRequests = [];
const stytchSSOConnections = [{
  organization_id: "organization-test-local",
  connection_id: "saml-connection-live-e2e",
  status: "active",
  display_name: "Corporate SAML",
  identity_provider: "okta",
}];
let stytchSCIMConnection;
let browserStage = "startup";
const scopeOverlapProof = {
  delayNextFirstTabBootstrap: false,
  delayedFirstTabBootstrap: undefined,
  events: [],
  firstTabScopeStaleResponses: 0,
  secondTabBootstrapWhileFirstDelayed: false,
};
let injectLaterReceiptOnNextAcknowledgement = false;
let expireNextReceiptBeforeAcknowledgement = false;
let malformNextIntegrationDeleteResponse = true;
let loseNextFindingResponse = true;
let loseNextFindingTicketResponse = true;
let loseNextConnectorAuthorizationResponse = true;
let failNextRiskRecoveryRefetch = false;
let delayRiskDetailResponses = false;
let proxyFailure;
const recoveryAPIResponses = [];
const recoveryBackupRequestKeys = [];
const securityAgentApprovalResponses = [];
let loseNextRecoveryBackupResponse = true;
const cleanupController = installBoundedSignalCleanup(cleanupOwnedResources);

try {
  const ports = await Promise.all(Array.from({ length: 8 }, reservePort));
  const [postgresPort, identityPort, policyHistoryPort, apiPort, healthPort, webPort, proxyPort, chromePort] = ports;
  const githubAppPrivateKey = path.join(temporaryRoot, "github-app-private-key.pem");
  await generateHarnessGitHubAppPrivateKey(githubAppPrivateKey);
  const actionSigningPair = generateKeyPairSync("ed25519");
  const actionPrivateJWK = actionSigningPair.privateKey.export({ format: "jwk" });
  const actionPrivateKey = Buffer.concat([Buffer.from(actionPrivateJWK.d, "base64url"), Buffer.from(actionPrivateJWK.x, "base64url")]).toString("base64url");
  const dsn = `postgres://zasp_e2e@127.0.0.1:${postgresPort}/postgres?sslmode=disable`;
  const apiDSN = `postgres://zasp_e2e_api@127.0.0.1:${postgresPort}/postgres?sslmode=disable`;
  postgres = await startPostgres(postgresPort);
  await provisionPostgresPrincipals(dsn);
  console.log("combined E2E: disposable PostgreSQL ready");

  const migrate = path.join(temporaryRoot, "agentsec-migrate");
  const apiBinary = path.join(temporaryRoot, "agentsec-api");
  const workerBinary = path.join(temporaryRoot, "agentsec-worker");
  const workerE2EBinary = path.join(temporaryRoot, "agentsec-worker-e2e");
	const gatewayE2EBinary = path.join(temporaryRoot, "runtime-gateway-e2e");
	const agentsecctl = path.join(temporaryRoot, "agentsecctl");
  await command("go", ["build", "-o", migrate, "./agentsec-migrate"], { cwd: platform });
  await command("go", ["build", "-o", apiBinary, "./agentsec-api"], { cwd: platform });
  await command("go", ["build", "-o", workerBinary, "./agentsec-worker"], { cwd: platform });
  await command("go", ["test", "-c", "-o", workerE2EBinary, "./agentsec-worker"], { cwd: platform, timeout: 120_000 });
	await command("go", ["test", "-c", "-o", gatewayE2EBinary, "."], { cwd: path.join(root, "services", "runtime-gateway"), timeout: 120_000 });
	await command("go", ["build", "-o", agentsecctl, "."], { cwd: path.join(root, "cmd", "agentsecctl") });
  const migrationResult = await command(migrate, ["up"], { reject: false, env: {
    ...process.env,
    ZASP_POSTGRES_DSN: dsn,
    ZASP_MIGRATION_TIMEOUT: "20s",
    ZASP_MIGRATION_DB_PRINCIPAL: "zasp_e2e",
    ZASP_DISCOVERY_API_DB_PRINCIPAL: "zasp_e2e_api",
    ZASP_DISCOVERY_WORKER_DB_PRINCIPAL: "zasp_e2e_discovery",
    ZASP_RUNTIME_INGEST_DB_PRINCIPAL: "zasp_e2e_ingest",
    ZASP_RUNTIME_WORKER_DB_PRINCIPAL: "zasp_e2e_runtime",
    ZASP_OUTBOX_WORKER_DB_PRINCIPAL: "zasp_e2e_outbox",
    ZASP_RUNTIME_GATEWAY_DB_PRINCIPAL: "zasp_e2e_gateway",
    ZASP_DISCOVERY_SCHEDULER_DB_PRINCIPAL: "zasp_e2e_scheduler",
    ZASP_PROJECTION_RISK_DB_PRINCIPAL: "zasp_e2e_projection_risk",
    ZASP_PROJECTION_GRAPH_DB_PRINCIPAL: "zasp_e2e_projection_graph",
    ZASP_PROJECTION_SEARCH_DB_PRINCIPAL: "zasp_e2e_projection_search",
    ZASP_RUNTIME_COORDINATOR_DB_PRINCIPAL: "zasp_e2e_coordinator",
    ZASP_RUNTIME_ARCHIVE_DB_PRINCIPAL: "zasp_e2e_archive",
    ZASP_RUNTIME_INDEX_DB_PRINCIPAL: "zasp_e2e_index",
    ZASP_RUNTIME_CORRELATION_DB_PRINCIPAL: "zasp_e2e_correlation",
    ZASP_RUNTIME_PROJECTION_DB_PRINCIPAL: "zasp_e2e_runtime_projection",
    ZASP_GATEWAY_CONTROL_DB_PRINCIPAL: "zasp_e2e_gateway_control",
    ZASP_SECURITY_AGENT_API_DB_PRINCIPAL: "zasp_e2e_security_agent_api",
    ZASP_SECURITY_AGENT_WORKER_DB_PRINCIPAL: "zasp_e2e_security_agent_worker",
    ZASP_SECURITY_AGENT_ACTION_DB_PRINCIPAL: "zasp_e2e_security_agent_action",
		ZASP_POLICY_DEPLOYMENT_DB_PRINCIPAL: "zasp_e2e_policy_deployment",
		ZASP_RED_TEAM_WORKER_DB_PRINCIPAL: "zasp_e2e_red_team_worker",
		ZASP_RED_TEAM_OUTBOX_DB_PRINCIPAL: "zasp_e2e_red_team_outbox",
		ZASP_RED_TEAM_ADAPTER_DB_PRINCIPAL: "zasp_e2e_red_team_adapter",
		ZASP_ATTACK_LAB_CONTROLLER_DB_PRINCIPAL: "zasp_e2e_attack_lab_controller",
		ZASP_ATTACK_LAB_OUTBOX_DB_PRINCIPAL: "zasp_e2e_attack_lab_outbox",
		ZASP_ATTACK_LAB_PROXY_DB_PRINCIPAL: "zasp_e2e_attack_lab_proxy",
		ZASP_RECOVERY_WORKER_DB_PRINCIPAL: "zasp_e2e_recovery",
		ZASP_RECOVERY_OUTBOX_DB_PRINCIPAL: "zasp_e2e_recovery_outbox",
  } });
	if (migrationResult.status !== 0) {
		const installed = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", "SELECT version || '|' || name FROM zasp_schema_versions ORDER BY version;"], { reject: false });
		throw new Error(`agentsec-migrate failed at installed releases ${installed.stdout.trim()}: ${migrationResult.stderr || migrationResult.stdout}`);
	}
  const schemaRelease = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", "SELECT version || '|' || name FROM zasp_schema_versions WHERE version IN (14,15,16,17,18,19,20,21,22,23,24,27,28,29,30,31,32,33,34,35,36) ORDER BY version;"]);
  assert.equal(schemaRelease.stdout.trim(), "14|typed_inventory_cutover\n15|runtime_data_plane\n16|runtime_gateway_reconciliation\n17|runtime_ingest_reconciliation\n18|security_agent_execution\n19|identity_administration\n20|security_agent_controls\n21|security_agent_autonomous_response\n22|security_agent_temporary_policy\n23|security_agent_connector_revocation\n24|security_agent_session_isolation\n27|production_recovery\n28|production_policy_deployment\n29|production_home_attention\n30|production_approval_notification\n31|production_workflow_compatibility\n32|production_security_agent_planner\n33|production_security_agent_attack_path\n34|production_integration_setup\n35|production_integration_webhook\n36|production_runtime_queue_replay", "combined E2E did not migrate through the typed inventory, runtime data-plane, Security Agent, identity administration, execution-control, autonomous-response, temporary-policy, connector-revocation, session-isolation, recovery, central policy deployment, Home attention, approval notification, workflow compatibility, production planner, attack-path trigger, and integration setup releases");
  console.log("combined E2E: schema 14 typed_inventory_cutover verified");
  console.log("combined E2E: schema 15 runtime_data_plane verified");
  console.log("combined E2E: schema 17 runtime_ingest_reconciliation verified");
  console.log("combined E2E: schema 18 security_agent_execution verified");
  console.log("combined E2E: schema 19 identity_administration verified");
  console.log("combined E2E: schema 20 security_agent_controls verified");
  console.log("combined E2E: schema 21 security_agent_autonomous_response verified");
  console.log("combined E2E: schema 24 security_agent_session_isolation verified");
	console.log("combined E2E: schema 27 production_recovery verified");
	console.log("combined E2E: schema 28 production_policy_deployment verified");
	console.log("combined E2E: schema 29 production_home_attention verified");
	console.log("combined E2E: schema 30 production_approval_notification verified");
	console.log("combined E2E: schema 31 production_workflow_compatibility verified");
	console.log("combined E2E: schema 32 production_security_agent_planner verified");
	console.log("combined E2E: schema 33 production_security_agent_attack_path verified");
	console.log("combined E2E: schema 34 production_integration_setup verified");
	console.log("combined E2E: schema 35 production_integration_webhook verified");
  console.log("combined E2E: schema 36 production_runtime_queue_replay verified");
  await seedPostgres(dsn);
  console.log("combined E2E: migrations and durable seed ready");

  await runtimePipelineDependencies.prepare();
  const [runtimeAWSEndpoint, runtimeSearchEndpoint] = await Promise.all([
    runtimePipelineDependencies.start("aws"), runtimePipelineDependencies.start("search"),
  ]);
  console.log("combined E2E: owned runtime dependencies ready");
  const runtimePipelineResult = await command(workerE2EBinary, ["-test.run", "^TestProductionCombinedE2ERuntimeQueueIndex$", "-test.v", "-test.timeout", "240s"], {
    timeout: 250_000,
    env: { ...process.env, ZASP_COMBINED_E2E_RUNTIME_PIPELINE_DSN: dsn, ZASP_COMBINED_E2E_RUNTIME_AWS_ENDPOINT: runtimeAWSEndpoint, ZASP_COMBINED_E2E_RUNTIME_SEARCH_ENDPOINT: runtimeSearchEndpoint },
  });
  assert.match(runtimePipelineResult.stdout, /runtime pipeline proof passed:/);
  assert.match(runtimePipelineResult.stdout, /--- PASS: TestProductionCombinedE2ERuntimeQueueIndex/);
  assert.doesNotMatch(runtimePipelineResult.stdout, /--- SKIP:/);
  console.log("combined E2E: local runtime SQS/S3/OpenSearch pipeline passed");

  if (process.env.ZASP_COMBINED_E2E_RUNTIME_PIPELINE_ONLY !== "true") {
  const publicOrigin = `https://${productHostname}:${proxyPort}`;
  identity = await startIdentityServer(identityPort, publicOrigin);
  policyHistory = await startPolicyHistoryServer(policyHistoryPort);
  const apiEnvironment = {
    ...process.env,
    HOSTNAME: "agentsec-api-production-e2e",
    ZASP_ENVIRONMENT: "test",
    ZASP_DEPLOYMENT_MODE: "saas",
    ZASP_ORGANIZATION_ID: "",
    ZASP_PRODUCT_LISTEN_ADDRESS: `127.0.0.1:${apiPort}`,
    ZASP_INTERNAL_LISTEN_ADDRESS: `127.0.0.1:${healthPort}`,
    ZASP_PUBLIC_ORIGIN: publicOrigin,
    ZASP_TRUSTED_PROXY_CIDRS: "127.0.0.0/8",
    ZASP_REQUEST_RATE_PER_SECOND: "1000",
    ZASP_REQUEST_BURST: "2000",
    ZASP_COOKIE_SECURE: "true",
    ZASP_PROVIDER_TIMEOUT: "5s",
    ZASP_REQUEST_TIMEOUT: "10s",
    ZASP_SHUTDOWN_TIMEOUT: "5s",
    ZASP_READINESS_INTERVAL: "100ms",
    ZASP_READINESS_MAX_INTERVAL: "1s",
    ZASP_DISCOVERY_PARSER_VERSION: "inventory-parser-2026.08.20",
    ZASP_DISCOVERY_TOOL_VERSION: "collector-tool-2026.08.20",
    ZASP_POSTGRES_DSN: apiDSN,
    ZASP_SECURITY_AGENT_POSTGRES_DSN: `postgres://zasp_e2e_security_agent_api@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
    ZASP_STYTCH_BASE_URL: `http://127.0.0.1:${identityPort}`,
    ZASP_STYTCH_AUTHORIZE_URL: `http://127.0.0.1:${identityPort}/v1/b2b/public/oauth/google/start`,
    ZASP_STYTCH_PROJECT_ID: "project-test-local",
    ZASP_STYTCH_SECRET: "secret-test-local",
    ZASP_STYTCH_WEBHOOK_SECRET: stytchWebhookSecret,
    ZASP_STYTCH_PUBLIC_TOKEN: "public-token-test-local",
    ZASP_STYTCH_ORGANIZATION_ID: "organization-test-local",
    ZASP_WORKFLOW_SIGNING_KEY: "0123456789abcdef0123456789abcdef",
    ZASP_TOKEN_REVEAL_KEY: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
    ZASP_CONNECTOR_AWS_REGION: "us-east-1",
    ZASP_CONNECTOR_ROLE_ARN: "arn:aws:iam::000000000000:role/zasp-production-e2e-api-connectors",
    ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    ZASP_CONNECTOR_KMS_KEY_ARN: "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-1111-1111-111111111111",
    ZASP_CONNECTOR_SECRET_PREFIX: "zasp-production-e2e/connectors/oauth",
    ZASP_POLICY_HISTORY_ENDPOINT: `http://127.0.0.1:${policyHistoryPort}`,
    ZASP_POLICY_HISTORY_INDEX: "zasp-runtime-events-v1",
    ZASP_AWS_CUSTOMER_ROLE_PREFIXES: '["arn:aws:iam::123456789012:role/zasp-reference/"]',
    ZASP_AWS_CUSTOMER_ROLE_ARNS: '["arn:aws:iam::123456789012:role/zasp-reference/production-e2e"]',
    ZASP_KUBERNETES_EGRESS_CIDRS: "203.0.113.0/24",
    ZASP_FINDING_TICKET_EGRESS_CIDRS: "192.0.2.64/28",
    ZASP_GITHUB_CLIENT_ID: "Iv1.1234567890abcdef",
    ZASP_GITHUB_CLIENT_SECRET_REFERENCE: "ref:github/client-secret",
    ZASP_GITHUB_APP_ID: "123456",
    ZASP_GITHUB_PRIVATE_KEY_REFERENCE: "ref:github/app-private-key",
    ZASP_OKTA_CLIENT_ID: "0oa1234567890abcdef",
    ZASP_OKTA_CLIENT_SECRET_REFERENCE: "ref:okta/client-secret",
  };
  api = startChild(apiBinary, [], { env: apiEnvironment });
	try {
		await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
	} catch (error) {
		if (api.exitCode === null && api.signalCode === null) {
			api.kill("SIGQUIT");
			await Promise.race([once(api, "exit"), delay(1_000)]);
		}
		throw new Error(`${error instanceof Error ? error.message : "API readiness failed"}; exit=${api.exitCode}; signal=${api.signalCode}: ${api.output()}`);
	}
  console.log("combined E2E: Go product and internal listeners ready");

  web = startChild(path.join(root, "node_modules", ".bin", "vinext"), ["start", "--port", String(webPort), "--hostname", "127.0.0.1"], { cwd: root });
  await waitForHTTP(`http://127.0.0.1:${webPort}/sign-in`, 200);
  console.log("combined E2E: built web server ready");

  const key = path.join(temporaryRoot, "tls.key");
  const certificate = path.join(temporaryRoot, "tls.crt");
	await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", `/CN=${productHostname}`, "-addext", `subjectAltName=DNS:${productHostname},DNS:${recoveryHostname}`, "-keyout", key, "-out", certificate]);
	const recoveryCredentialFile = path.join(temporaryRoot, "recovery-api-token");
	await writeFile(recoveryCredentialFile, "production-e2e-product-token-with-at-least-32-bytes", { mode: 0o600 });
	await chmod(recoveryCredentialFile, 0o600);
  proxy = await startProxy(proxyPort, apiPort, webPort, key, certificate, dsn);
  await waitForHTTP(`${publicOrigin}/sign-in`, 200, true);

  const connectorAuthorizeOperation = "/api/v1/integrations/{id}/authorize";
  const connectorAuthorizePath = connectorAuthorizeOperation.replace("{id}", "pid_71000001-0000-4000-8000-000000000001");
  const connectorCallbackPath = "/api/v1/integrations/oauth/callback";
  const providerCallsBeforeRejections = identityOAuthStarts;
  const connectorCountsBeforeRejections = await connectorDurableCounts(dsn);
  const unauthorizedAuthorize = await requestHTTPSJSON(`${publicOrigin}${connectorAuthorizePath}`, {
    method: "POST",
    headers: { "content-type": "application/json", "idempotency-key": "connector-e2e-unauthorized-authorize" },
  }, "{}");
  assertRejectedConnectorResponse(unauthorizedAuthorize, 401, "authentication_required", "unauthorized connector authorization");
  const unauthorizedCallback = await requestHTTPSJSON(`${publicOrigin}${connectorCallbackPath}?code=connector-code-probe&state=connector-state-probe`, { method: "GET" });
  assertRejectedConnectorResponse(unauthorizedCallback, 401, "authentication_required", "unauthorized connector callback");
  const rejectedConnectorCounts = await connectorDurableCounts(dsn);
  assert.equal(rejectedConnectorCounts, connectorCountsBeforeRejections, "unauthorized connector requests wrote durable state");
  assert.equal(identityOAuthStarts, providerCallsBeforeRejections, "rejected connector requests unexpectedly started an identity/provider flow");
  console.log("combined E2E: unauthorized connector boundaries, no-store/no-referrer, and zero provider/AWS calls proven");

  const patHeaders = { authorization: "Bearer production-e2e-product-token-with-at-least-32-bytes", "content-type": "application/json", "idempotency-key": "production-e2e-pat-0001" };
  const patBody = JSON.stringify({ id: "policy-pat-e2e", name: "PAT E2E boundary", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "read" }], action: "monitor", rollout: "draft", failure_mode: "open" });
  const patCreated = await requestHTTPSJSON(`${publicOrigin}/api/v1/policies`, { method: "POST", headers: patHeaders }, patBody);
  const patReplayed = await requestHTTPSJSON(`${publicOrigin}/api/v1/policies`, { method: "POST", headers: patHeaders }, patBody);
  assert.equal(patCreated.status, 201, `PAT create failed: ${JSON.stringify(patCreated)}; api=${api.output()}`);
  assert.equal(patReplayed.status, 201, `PAT replay failed: ${JSON.stringify(patReplayed)}`);
  assert.equal(patCreated.headers["x-mutation-receipt-id"], undefined);
  assert.equal(patReplayed.headers["x-mutation-receipt-id"], undefined);
  assert.deepEqual(patReplayed.body, patCreated.body);
  const patCounts = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation='createPolicy' AND idempotency_key='production-e2e-pat-0001'),
    (SELECT count(*) FROM zasp_workflow_audit WHERE operation='createPolicy' AND resource_id='policy-pat-e2e'),
    (SELECT count(*) FROM zasp_workflow_receipts WHERE operation='createPolicy' AND idempotency_key='production-e2e-pat-0001');`]);
  assert.equal(patCounts.stdout.trim(), "1|1|0", "PAT create/replay inserted a browser mutation receipt");
  console.log("combined E2E: PAT success, replay, and zero browser receipts proven");

  const patFindingID = "pid_30000002-0000-4000-8000-000000000002";
  const patFinding = await requestHTTPSJSON(`${publicOrigin}/api/v1/findings/${patFindingID}`, { method: "GET", headers: { authorization: patHeaders.authorization } });
  assert.equal(patFinding.status, 200);
  assert.match(String(patFinding.headers.etag), /^"[1-9][0-9]*"$/);
  const patRiskHeaders = { ...patHeaders, "idempotency-key": "production-e2e-risk-pat-0001", "if-match": String(patFinding.headers.etag) };
  const patRiskBody = JSON.stringify({ status: "under_review" });
  const patRiskUpdated = await requestHTTPSJSON(`${publicOrigin}/api/v1/findings/${patFindingID}`, { method: "PATCH", headers: patRiskHeaders }, patRiskBody);
  const patRiskReplayed = await requestHTTPSJSON(`${publicOrigin}/api/v1/findings/${patFindingID}`, { method: "PATCH", headers: patRiskHeaders }, patRiskBody);
  assert.equal(patRiskUpdated.status, 200, `PAT risk mutation failed: ${JSON.stringify(patRiskUpdated)}`);
  assert.deepEqual(patRiskReplayed.body, patRiskUpdated.body);
  assert.equal(patRiskUpdated.headers["x-mutation-receipt-id"], undefined);
  assert.equal(patRiskReplayed.headers["x-mutation-receipt-id"], undefined);
  const patRiskCounts = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation='updateFinding' AND idempotency_key='production-e2e-risk-pat-0001'),
    (SELECT count(*) FROM zasp_workflow_audit WHERE operation='updateFinding' AND resource_id='${patFindingID}'),
    (SELECT count(*) FROM zasp_workflow_receipts WHERE operation='updateFinding' AND idempotency_key='production-e2e-risk-pat-0001');`]);
  assert.equal(patRiskCounts.stdout.trim(), "1|1|0", "PAT risk mutation inserted a browser receipt");
  console.log("combined E2E: PAT risk mutation and zero browser receipts proven");

  const task4Public = await exercisePublicDiscoveryLifecycle(publicOrigin, dsn, patHeaders.authorization);
  assert.equal(task4Public.integrationID, task4DiscoveryIntegrationID);
  await exerciseTask4ProductionWorkerBoundaries(workerBinary, postgresPort, dsn);
  await exerciseTypedInventoryDiscoveryLifecycle(publicOrigin, dsn, postgresPort, workerE2EBinary, patHeaders.authorization, task4Public);

  const profile = path.join(temporaryRoot, "chrome-profile");
  browser = await startBrowser(profile, chromePort, `${publicOrigin}/api/v1/session/start?return_to=%2Fdiscovery%2Fassets`);
  let signedIn;
  try {
    signedIn = await waitForBrowserText(browser.cdp, /Support agent/);
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : "browser sign-in failed"}: ${api.output()}`);
  }
  assert.equal(observedSessionCookie, true, "__Host-zasp_session was not issued through the combined origin");
  assert.match(signedIn, /Agents/);
  assert.match(signedIn, /Support agent/);
  assert.doesNotMatch(signedIn, /Product API unavailable|Sign-in failed/);
  assert.doesNotMatch(signedIn, /Recover committed operations|PAT E2E boundary/);
  console.log("combined E2E: browser callback, cookie, bootstrap, and durable data proven");
  const securityAgentCookie = await getBrowserSessionCookie(browser.cdp, publicOrigin);
  const securityAgentHeaders = { cookie: `__Host-zasp_session=${securityAgentCookie.value}`, "x-zasp-expected-scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003" };
  const securityAgentPage = await requestHTTPSJSON(`${publicOrigin}/api/v1/security-agents?limit=50`, { method: "GET", headers: securityAgentHeaders });
  assert.equal(securityAgentPage.status, 200, `security agent public page failed: ${JSON.stringify(securityAgentPage)}`);
  assert.deepEqual(securityAgentPage.body, { items: [], page_info: { has_more: false, next_cursor: null } }, "security agent public page was not the exact empty scoped state");
  for (const target of ["/api/v1/security-agent-templates", "/api/v1/security-actions", "/api/v1/security-agent-runs?limit=100", "/api/v1/security-agent-approvals?limit=100"]) {
    const catalog = await requestHTTPSJSON(`${publicOrigin}${target}`, { method: "GET", headers: securityAgentHeaders });
    assert.equal(catalog.status, 200, `security agent catalog failed at ${target}: ${JSON.stringify(catalog)}`);
  }
  await assertTask4BrowserPublicState(browser.cdp, publicOrigin, task4Public.syncID);
  await assertTypedInventoryBrowserState(browser.cdp, publicOrigin);
  await assertTask6SensorBrowserState(browser.cdp, publicOrigin, dsn);
  const sharedSessionCookie = await getBrowserSessionCookie(browser.cdp, publicOrigin);
  const providerCallsBeforeScopedRejections = identityOAuthStarts;
  const scopedRejectionCountsBefore = (await connectorDurableCounts(dsn)).split("|").map(Number);
  const crossScopeState = "connector-cross-scope-state-0001";
  await seedCrossScopeConnectorAttempt(dsn, crossScopeState);
  const crossScopeCallback = await requestHTTPSJSON(`${publicOrigin}${connectorCallbackPath}?code=connector-cross-scope-code-0001&state=${crossScopeState}`, {
    method: "GET",
    headers: { cookie: `${sharedSessionCookie.name}=${sharedSessionCookie.value}` },
  });
  assertRejectedConnectorResponse(crossScopeCallback, 404, "not_found", "cross-scope connector callback");
  const crossScopeAuthorize = await browserConnectorAuthorizeRejection(
    browser.cdp,
    connectorAuthorizePath,
    "pid_10000001-0000-4000-8000-000000000001/pid_10000022-0000-4000-8000-000000000022/pid_10000023-0000-4000-8000-000000000023",
  );
  assertRejectedConnectorResponse(crossScopeAuthorize, 409, "scope_stale", "cross-scope connector authorization");
  const scopedRejectionCounts = await connectorDurableCounts(dsn);
  assert.equal(scopedRejectionCounts, [scopedRejectionCountsBefore[0] + 1, ...scopedRejectionCountsBefore.slice(1)].join("|"), "scope-bound connector rejections mutated their pending witness or created effects");
  assert.equal(identityOAuthStarts, providerCallsBeforeScopedRejections, "scope-bound connector rejections unexpectedly started a provider flow");
  console.log("combined E2E: callback and authorization scope boundaries rejected with zero provider/AWS calls");

  await setBrowserTabHeader(browser.cdp, "first");
  secondBrowserTab = await startBrowserTab(chromePort, `${publicOrigin}/`, sharedSessionCookie);
  await waitForBrowserText(secondBrowserTab, /Security overview/);
  await setBrowserTabHeader(secondBrowserTab, "second");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserSelectedOption(secondBrowserTab, "Authorized scope", "Production");
  scopeOverlapProof.delayNextFirstTabBootstrap = true;
  await selectBrowserOption(secondBrowserTab, "Authorized scope", "Staging");
  await waitForBrowserSelectedOption(secondBrowserTab, "Authorized scope", "Staging");
  await clickBrowserAria(browser.cdp, "Overview");
  await waitForBrowserText(browser.cdp, /Loading authenticated session/);
  await waitForScopeOverlap(() => scopeOverlapProof.delayedFirstTabBootstrap?.ready === true, "first-tab B bootstrap was not delayed");
  await selectBrowserOption(secondBrowserTab, "Authorized scope", "Production");
  try {
    await waitForBrowserSelectedOption(secondBrowserTab, "Authorized scope", "Production");
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : "second-tab recovery failed"}; body=${JSON.stringify(await browserBodyText(secondBrowserTab))}; events=${JSON.stringify(scopeOverlapProof.events)}`);
  }
  assert.equal(scopeOverlapProof.secondTabBootstrapWhileFirstDelayed, true, "second-tab A bootstrap did not overlap the delayed first-tab B bootstrap");
  releaseDelayedFirstTabBootstrap();
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Production");
  await waitForScopeOverlap(() => scopeOverlapProof.firstTabScopeStaleResponses >= 2, "first tab did not receive two scope_stale responses");
  const authoritativeScope = await browserBodyText(browser.cdp);
  assert.doesNotMatch(authoritativeScope, /Loading authenticated session|Product API unavailable/);
  await secondBrowserTab.dispose();
  secondBrowserTab = undefined;
  workflowPageRequests.policies.length = 0;
  workflowPageRequests.integrations.length = 0;
  console.log("combined E2E: actual two-tab delayed out-of-order ABA stale-scope recovery proven");

  riskPageRequests.findings.length = 0;
  riskPageRequests.attackPaths.length = 0;
  await navigateBrowser(browser.cdp, `${publicOrigin}/violations`);
  await waitForBrowserText(browser.cdp, /Production credential exposure 0102/);
  assert.equal(await browserCountAriaPrefix(browser.cdp, "Open Production credential exposure"), 102, "finding UI did not traverse exactly 102 stable IDs");
  assert.equal(riskPageRequests.findings.length, 2, "finding UI did not perform exactly two signed-keyset page requests");
  await assertResponsiveRiskLayout(browser.cdp, "Findings");
  await clickBrowserText(browser.cdp, "Production credential exposure 0001");
  const findingDetail = await waitForBrowserText(browser.cdp, /Public production input/);
  assert.match(findingDetail, /Public production input/);
  assert.match(findingDetail, /pid_70000001-0000-4000-8000-000000000001/);
  await clickBrowserText(browser.cdp, "Create ticket");
  await waitForBrowserText(browser.cdp, /Injected finding ticket response loss/);
  await clickBrowserText(browser.cdp, "Retry retained ticket creation");
  await waitForBrowserText(browser.cdp, /Ticket SEC-E2E-0001 created/);
  assert.equal(findingTicketRequests.length, 2, "finding ticket response-loss retry did not make exactly two bodyless requests");
  assert.match(findingTicketRequests[0].idempotencyKey, /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/);
  assert.equal(new Set(findingTicketRequests.map((request) => request.idempotencyKey)).size, 1, "finding ticket retry changed its idempotency key");
  assert.equal(new Set(findingTicketRequests.map((request) => request.ifMatch)).size, 1, "finding ticket retry changed If-Match");
  assert.equal(findingTicketRequests[0].ifMatch, '"1"');
  assert.equal(findingTicketRequests.every((request) => request.body === "" && request.contentType === ""), true, "finding ticket request was not bodyless");
  assert.equal(findingTicketRequests.every((request) => request.csrf.length >= 16 && request.expectedScope === "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003"), true, "finding ticket request lost browser CSRF or exact scope authority");
  assert.equal(findingTicketRequests.every((request) => request.origin === publicOrigin), true, "finding ticket request escaped the browser origin");
  await reloadBrowser(browser.cdp);
  await waitForBrowserText(browser.cdp, /Production credential exposure 0102/);
  await clickBrowserText(browser.cdp, "Production credential exposure 0001");
  await waitForBrowserText(browser.cdp, /Ticket SEC-E2E-0001 created/);
  assert.equal(findingTicketRequests.length, 2, "finding ticket reload emitted a duplicate delivery");
  console.log("combined E2E: finding ticket retained one idempotency key across retry and reload");
  await clickBrowserText(browser.cdp, "Mark under review");
  await waitForBrowserText(browser.cdp, /network error/);
  assert.equal(lostFindingResponseKeys.length, 1, "committed finding response was not interrupted exactly once");
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows"]'::jsonb WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003'; UPDATE zasp_product_sessions SET permissions='["view","manage_workflows"]'::jsonb WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
  await reloadBrowser(browser.cdp);
  const recoveredFinding = await waitForBrowserText(browser.cdp, /Recover committed operations/);
  assert.match(recoveredFinding, /Update Finding/);
  assert.match(recoveredFinding, /Production credential exposure 0001/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Mark under review|Accept risk|Retry retained finding update|Retry retained risk acceptance)$/i), false, "findings.write downgrade retained an interactive mutation or retry");
  const downgradedPatchCount = productAPIRequests.filter((request) => request.method === "PATCH" && request.path === "/api/v1/findings/pid_30000001-0000-4000-8000-000000000001").length;
  await delay(100);
  assert.equal(productAPIRequests.filter((request) => request.method === "PATCH" && request.path === "/api/v1/findings/pid_30000001-0000-4000-8000-000000000001").length, downgradedPatchCount, "capability downgrade emitted a hidden finding retry");
  riskRecoverySequence.length = 0;
  failNextRiskRecoveryRefetch = true;
  await clickBrowserText(browser.cdp, "Acknowledge recovered result");
  await waitForBrowserText(browser.cdp, /Injected authoritative refetch failure/);
  assert.match(await browserBodyText(browser.cdp), /Recover committed operations/);
  assert.equal(riskRecoverySequence.some((event) => event.startsWith("POST:")), false, "failed authoritative refetch still issued receipt ACK");
  await clickBrowserText(browser.cdp, "Acknowledge recovered result");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Mutation recovery"]');
  const refetchIndex = riskRecoverySequence.findIndex((event) => event === "GET:200");
  const acknowledgementIndex = riskRecoverySequence.findIndex((event) => event === "POST:204");
  assert.ok(refetchIndex >= 0 && acknowledgementIndex > refetchIndex, `receipt ACK did not follow authoritative refetch: ${riskRecoverySequence.join(",")}`);
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","manage_findings"]'::jsonb WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003'; UPDATE zasp_product_sessions SET permissions='["view","manage_workflows","manage_findings"]'::jsonb WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
  await reloadBrowser(browser.cdp);
  await waitForBrowserText(browser.cdp, /Production credential exposure 0102/);
  await clickBrowserText(browser.cdp, "Production credential exposure 0001");
  const recoveredDetail = await waitForBrowserText(browser.cdp, /version 2/);
  assert.match(recoveredDetail, /under review/);
  await fillBrowserLabel(browser.cdp, "Risk acceptance reason", "Accepted production exception");
  await clickBrowserText(browser.cdp, "Accept risk");
  const acceptedFinding = await waitForBrowserText(browser.cdp, /Accepted production exception/);
  assert.match(acceptedFinding, /accepted/);
  const durableFinding = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT status || '|' || acceptance_reason || '|' || version || '|' ||
    (SELECT count(*) FROM zasp_workflow_receipts WHERE operation IN ('updateFinding','acceptFindingRisk') AND resource_id='pid_30000001-0000-4000-8000-000000000001' AND acknowledged_at IS NOT NULL)
    FROM zasp_risk_findings WHERE id='pid_30000001-0000-4000-8000-000000000001' AND organization_id='pid_10000001-0000-4000-8000-000000000001';`]);
  assert.equal(durableFinding.stdout.trim(), "accepted|Accepted production exception|3|2", "Finding status updated through committed-response recovery was not durable");
  await clickBrowserAria(browser.cdp, "Close");
  await waitForBrowserActive(browser.cdp, "Open Production credential exposure 0001");

  await navigateBrowser(browser.cdp, `${publicOrigin}/exposure/attack-paths`);
  await waitForBrowserText(browser.cdp, /pid_50000102-0000-4000-8000-000000000102/);
  assert.equal(await browserCountAriaPrefix(browser.cdp, "Open attack path"), 102, "attack-path UI did not traverse exactly 102 stable IDs");
  assert.equal(riskPageRequests.attackPaths.length, 2, "attack-path UI did not perform exactly two signed-keyset page requests");
  await assertResponsiveRiskLayout(browser.cdp, "Attack Paths");
  delayedRiskDetailResponses.length = 0;
  delayRiskDetailResponses = true;
  await clickBrowserAria(browser.cdp, "Open attack path pid_40000001-0000-4000-8000-000000000001");
  await waitForScopeOverlap(() => delayedRiskDetailResponses.length === 2 && delayedRiskDetailResponses.every((entry) => entry.ready), "attack-path detail responses were not captured");
  const initialPathDetail = await waitForBrowserText(browser.cdp, /Loading path detail/);
  assert.match(initialPathDetail, /Loading break options/);
  releaseRiskDetailResponse("path");
  const partialPathDetail = await waitForBrowserText(browser.cdp, /State verified/);
  assert.match(partialPathDetail, /Loading break options/);
  releaseRiskDetailResponse("options", { status: 503, body: JSON.stringify({ code: "dependency_unavailable", message: "Injected break-option failure", retryable: true, correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }) });
  const pathDetail = await waitForBrowserText(browser.cdp, /Injected break-option failure/);
  assert.match(pathDetail, /pid_70000001-0000-4000-8000-000000000001/, "Ranked break option evidence was not rendered");
  assert.doesNotMatch(pathDetail, /ticket|rerun|simulate/i);
  await clickBrowserAria(browser.cdp, "Close");

  delayedRiskDetailResponses.length = 0;
  delayRiskDetailResponses = true;
  await clickBrowserAria(browser.cdp, "Open attack path pid_40000001-0000-4000-8000-000000000001");
  await waitForScopeOverlap(() => delayedRiskDetailResponses.length === 2 && delayedRiskDetailResponses.every((entry) => entry.ready), "cancellable attack-path responses were not captured");
  await waitForBrowserText(browser.cdp, /Loading path detail/);
  await navigateBrowser(browser.cdp, `${publicOrigin}/violations`);
  await waitForBrowserText(browser.cdp, /Production credential exposure 0102/);
  await waitForScopeOverlap(() => delayedRiskDetailResponses.every((entry) => entry.closed), "route unmount did not abort both attack-path detail responses");
  assert.equal((await browserBodyText(browser.cdp)).includes("Attack path detail"), false, "late attack-path response remained visible after route unmount");
  delayRiskDetailResponses = false;
  delayedRiskDetailResponses.length = 0;
  await navigateBrowser(browser.cdp, `${publicOrigin}/exposure/attack-paths`);
  await waitForBrowserText(browser.cdp, /pid_50000102-0000-4000-8000-000000000102/);
  await selectBrowserOption(browser.cdp, "Authorized scope", "Staging");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Staging");
  await waitForBrowserText(browser.cdp, /pid_80000002-0000-4000-8000-000000000002/);
  assert.equal(await browserCountAriaPrefix(browser.cdp, "Open attack path"), 1, "scope switch retained production attack paths");
  await selectBrowserOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Production");

	await navigateBrowser(browser.cdp, `${publicOrigin}/red-team/results`);
	const redTeamState = await waitForBrowserText(browser.cdp, /No Red Team tests in this scope/);
	assert.match(redTeamState, /No Red Team runs in this scope/);
	console.log("combined E2E: tenant-scoped Red Team route loaded through isolated Security Agent API authority");

	const hiddenRequestStart = productAPIRequests.length;
	for (const hiddenPath of ["/reports", "/guardrails/dashboard", "/prompt-hardening"]) {
    await navigateBrowser(browser.cdp, `${publicOrigin}${hiddenPath}`);
    await waitForBrowserText(browser.cdp, /Security overview/);
    assert.equal(new URL(await browserCurrentURL(browser.cdp)).pathname, "/", `hidden route was not canonicalized: ${hiddenPath}`);
  }
  const hiddenRequests = productAPIRequests.slice(hiddenRequestStart).map((request) => request.path);
  assert.equal(hiddenRequests.some((requestPath) => /red-team|attack-lab|reports|guardrails|prompt-hardening|ai|tickets/i.test(requestPath)), false);
  console.log("combined E2E: hidden risk-adjacent routes canonicalized without hidden API calls");

  const browserPersistence = await browserStorageHistoryAndCaches(browser.cdp);
  assert.deepEqual(browserPersistence.local, {});
  assert.deepEqual(browserPersistence.session, {});
  assert.deepEqual(browserPersistence.cacheKeys, []);
  assert.deepEqual(browserPersistence.indexedDatabases, []);
  assert.doesNotMatch(JSON.stringify(browserPersistence), /Accepted production exception|zasp_pat_|pid_30000001/);
  assert.equal(productAPIRequests.every((request) => request.path.startsWith("/api/v1/") && request.host === new URL(publicOrigin).host), true, "a product API request escaped the TLS same-origin /api/v1 boundary");
  console.log("combined E2E: risk pagination, detail, recovery, acceptance, and persistence proven");

  await navigateBrowser(browser.cdp, `${publicOrigin}/policies`);
  await waitForBrowserText(browser.cdp, /Durable scoped runtime controls/);
  await waitForBrowserText(browser.cdp, /Paged policy 1000/);
  assert.equal(await browserCountAriaPrefix(browser.cdp, "Open "), 1001, "policy UI did not traverse exactly 1001 stable IDs");
  assert.equal(workflowPageRequests.policies.length, 11, "policy UI pagination requested an extra or missing page");
  await clickBrowserText(browser.cdp, "Create policy");
  await waitForBrowserText(browser.cdp, /exact operation and idempotency key are retained/);
  await reloadBrowser(browser.cdp);
  const recoveredMutation = await waitForBrowserText(browser.cdp, /Recover committed operations/);
  assert.match(recoveredMutation, /Create Policy/);
  assert.match(recoveredMutation, /Committed resource\s+policy-production/);
  assert.equal(await browserTextControlDisabled(browser.cdp, "Create policy"), true, "reloaded create was enabled before receipt reconciliation");
  await clickBrowserText(browser.cdp, "Acknowledge recovered result");
  await waitForBrowserText(browser.cdp, /Production runtime policy/);
  assert.equal(lostPolicyResponseKeys.length, 2);
  assert.equal(new Set(lostPolicyResponseKeys).size, 1, "two lost browser responses changed idempotency key");
  const durableCounts = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_workflow_records WHERE kind='policy' AND id='policy-production'),
    (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation='createPolicy'),
    (SELECT count(*) FROM zasp_workflow_audit WHERE operation='createPolicy'),
    (SELECT count(*) FROM zasp_workflow_receipts WHERE operation='createPolicy');`]);
  assert.equal(durableCounts.stdout.trim(), "1|2|2|1", "full reload recovery duplicated durable workflow state");
  await clickBrowserAria(browser.cdp, "Open Production runtime policy");
  await waitForBrowserText(browser.cdp, /Policy detail · policy-production/);
	await waitForBrowserText(browser.cdp, /Runtime decision history/);
	await waitForBrowserText(browser.cdp, /pid_78000004-0000-4000-8000-000000000004/);
	await clickBrowserText(browser.cdp, "Simulate against runtime history");
	await waitForBrowserText(browser.cdp, /1 matched historical actions · 0 would block/);
  assert.equal(policyHistoryRequests.filter((request) => request.method === "POST" && request.path === "/zasp-runtime-events-v1/_search").length, 1, "policy simulation did not perform exactly one bounded history query");
  injectLaterReceiptOnNextAcknowledgement = true;
  await clickBrowserText(browser.cdp, "Roll to monitor");
  await waitForBrowserText(browser.cdp, /Policy is monitor\. Audit pid_/);
  const laterRecovery = await waitForBrowserText(browser.cdp, /Second-tab committed policy/);
  assert.match(laterRecovery, /Recover committed operations/);
  assert.equal(await browserTextControlDisabled(browser.cdp, "Enforce policy"), true, "later receipt did not keep mutations locked");
  await clickBrowserText(browser.cdp, "Acknowledge recovered result");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Mutation recovery"]');

  await seedExpiringReceipt(dsn);
  await reloadBrowser(browser.cdp);
  const expiringRecovery = await waitForBrowserText(browser.cdp, /Expiry-race committed policy/);
  assert.match(expiringRecovery, /Recover committed operations/);
  expireNextReceiptBeforeAcknowledgement = true;
  await clickBrowserText(browser.cdp, "Acknowledge recovered result");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Mutation recovery"]');
  assert.equal(await waitForBrowserControlDisabled(browser.cdp, "Create policy", false), false, "expired receipt left workflow mutations locked");
  await clickBrowserAria(browser.cdp, "Open Production runtime policy");
  await waitForBrowserText(browser.cdp, /Policy detail · policy-production/);
  await clickBrowserText(browser.cdp, "Enforce policy");
  await waitForBrowserText(browser.cdp, /Policy is enforced\. Audit pid_/);

  const connectorUIRequestStart = productAPIRequests.length;
  await navigateBrowser(browser.cdp, `${publicOrigin}/connectors`);
  await waitForBrowserText(browser.cdp, /Durable connector configuration, provider authorization, and automatic inventory discovery/);
  await waitForBrowserText(browser.cdp, /Paged integration 1001/);
  assert.equal(await browserCountAriaPrefix(browser.cdp, "Open "), 1004, "integration UI did not traverse exactly 1001 paged, two revocation, and one Task4 discovery fixture IDs");
  assert.equal(workflowPageRequests.integrations.length, 11, "integration UI pagination requested an extra or missing page");
  for (const [configure, steps] of [
    ["Configure Amazon Web Services", ["Review access", "Configure", "Test connection", "Initial sync", "Review coverage"]],
    ["Configure Kubernetes", ["Choose coverage", "Authorize cluster", "Enroll Runtime sensor", "Verify heartbeat", "Initial sync", "Review coverage"]],
  ]) {
    const provider = configure.slice("Configure ".length);
    assert.equal(await browserHasInteractiveText(browser.cdp, new RegExp(`^${configure}$`)), true, `${provider} was absent from the live production catalog`);
    await clickBrowserText(browser.cdp, configure);
    await waitForBrowserText(browser.cdp, /Setup progress/);
    const setup = await browserBodyText(browser.cdp);
    for (const step of steps) assert.match(setup, new RegExp(step));
    assert.doesNotMatch(setup, /ref:(?:aws|kubernetes)\//);
    await clickBrowserText(browser.cdp, "Cancel");
    await waitForBrowserActive(browser.cdp, configure);
  }
  console.log("combined E2E: browser launch connector setup catalog proven");
  await clickBrowserAria(browser.cdp, "Open Harness terminal revocation");
  await waitForBrowserText(browser.cdp, /Provider authorization controls are unavailable for this connector/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^Authorize GitHub$/), false, "unavailable managed provider exposed an authorization side effect");
  assert.equal(connectorAuthorizationRequests.length, 0, "fail-closed provider unexpectedly reached the authorization boundary");
  assert.equal(productAPIRequests.slice(connectorUIRequestStart).some((request) => request.path === `/api/v1/integrations/${terminalRevocationIntegrationID}/authorize`), false, "fail-closed provider invoked connector authorization");
  assert.doesNotMatch(await browserBodyText(browser.cdp), /authorization_(?:url|attempt_id)|code_verifier|opaque-e2e-state/i);
  await clickBrowserText(browser.cdp, "Close");
  await waitForBrowserText(browser.cdp, /Harness terminal revocation/);
  console.log("combined E2E: unavailable managed OAuth authority remained fail-closed with zero provider calls");

  const expectedProductionScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
  const terminalDeleteStart = integrationDeleteRequests.length;
  await clickBrowserAria(browser.cdp, "Open Harness terminal revocation");
  await waitForBrowserText(browser.cdp, /Harness terminal revocation/);
  await clickBrowserText(browser.cdp, "Delete integration");
  const terminalPending = await waitForBrowserText(browser.cdp, /Provider revocation is pending/);
  await waitForScopeOverlap(() => integrationDeleteRequests.length >= terminalDeleteStart + 2, "malformed public 202 response replay was not observed");
  const terminalPendingRequests = integrationDeleteRequests.slice(terminalDeleteStart);
  assert.deepEqual(terminalPendingRequests.map((request) => request.status), [202, 202], "malformed public 202 response replay did not reach the real asynchronous response");
  assert.match(terminalPendingRequests[0].idempotencyKey, /^wf_[0-9a-f-]+$/);
  assert.equal(terminalPendingRequests[0].ifMatch, '"1"');
  assert.equal(new Set(terminalPendingRequests.map((request) => request.idempotencyKey)).size, 1, "same idempotency key + If-Match was not retained across malformed 202 response");
  assert.equal(new Set(terminalPendingRequests.map((request) => request.ifMatch)).size, 1, "same idempotency key + If-Match was not retained across malformed 202 response");
  assert.equal(await connectorRevocationWitness(dsn, terminalRevocationIntegrationID), "revoking|degraded|revoke:unknown|revoking|revoking|verified", "real DELETE 202 durable revoking receipt/effect state was incomplete");
  assert.match(terminalPending, /Harness terminal revocation[\s\S]*revoking/);
  assert.doesNotMatch(terminalPending, /Integration deleted/);
  assert.equal(await browserHasAriaLabel(browser.cdp, "Open Harness terminal revocation"), true, "202 removed the integration before terminal provider completion");
  assert.equal(await browserTextControlDisabled(browser.cdp, "Close"), true, "202 did not lock modal dismissal");
  assert.equal(await browserTextControlDisabled(browser.cdp, "Save changes"), true, "202 did not lock integration edits");
  assert.equal(await browserTextControlDisabled(browser.cdp, "Delete integration"), true, "202 did not lock a competing delete");
  assert.equal(await browserTextControlDisabled(browser.cdp, "Retry pending integration deletion"), true, "202 did not defer the retained exact retry until Retry-After elapsed");
  await delay(250);
  assert.equal(integrationDeleteRequests.length, terminalDeleteStart + 2, "202 Retry-After window emitted an early integration DELETE");
  await waitForBrowserControlDisabled(browser.cdp, "Retry pending integration deletion", false);
  console.log("combined E2E: real DELETE 202 durable revoking receipt and no premature deleted toast/removal proven");

  await completeHarnessConnectorRevocation(dsn, terminalRevocationIntegrationID);
  await clickBrowserText(browser.cdp, "Retry pending integration deletion");
  await waitForScopeOverlap(() => integrationDeleteRequests.length >= terminalDeleteStart + 3, "retained terminal DELETE was not sent");
  const terminalRequests = integrationDeleteRequests.slice(terminalDeleteStart);
  console.log(`combined E2E: retained terminal DELETE responses ${JSON.stringify(terminalRequests)}`);
  assert.deepEqual(terminalRequests.map((request) => request.status), [202, 202, 204]);
  assert.equal(new Set(terminalRequests.map((request) => request.idempotencyKey)).size, 1, "same idempotency key + If-Match changed before terminal 204");
  assert.equal(new Set(terminalRequests.map((request) => request.ifMatch)).size, 1, "same idempotency key + If-Match changed before terminal 204");
  await waitForBrowserText(browser.cdp, /Integration deleted\. Audit pid_/);
  await waitForBrowserAction(browser.cdp, `document.querySelector(${JSON.stringify('[aria-label="Open Harness terminal revocation"]')}) === null`);

  const reloadDeleteStart = integrationDeleteRequests.length;
  await clickBrowserAria(browser.cdp, "Open Harness reload revocation");
  await waitForBrowserText(browser.cdp, /Harness reload revocation/);
  await clickBrowserText(browser.cdp, "Delete integration");
  await waitForBrowserText(browser.cdp, /Provider revocation is pending/);
  await waitForScopeOverlap(() => integrationDeleteRequests.length >= reloadDeleteStart + 1, "reload integration DELETE did not reach the product API");
  const reloadPendingRequest = integrationDeleteRequests[reloadDeleteStart];
  assert.equal(reloadPendingRequest.status, 202);
  assert.match(reloadPendingRequest.idempotencyKey, /^wf_[0-9a-f-]+$/);
  assert.equal(reloadPendingRequest.ifMatch, '"1"');
  assert.equal(await connectorRevocationWitness(dsn, reloadRevocationIntegrationID), "revoking|degraded|revoke:unknown|revoking|revoking|verified", "reload DELETE did not durably stage revocation");
  await reloadBrowser(browser.cdp);
  const reloadRecovery = await waitForBrowserText(browser.cdp, /Recover committed operations/);
  assert.match(reloadRecovery, /Delete Integration[\s\S]*revoking/);
  assert.doesNotMatch(reloadRecovery, /Integration deleted/);
  await waitForBrowserAction(browser.cdp, `document.querySelector(${JSON.stringify('[aria-label="Open Harness reload revocation"]')})?.disabled === true`);
  assert.equal(await browserHasAriaLabel(browser.cdp, "Open Harness reload revocation"), true, "reload hid a still-revoking integration");
  assert.equal(await browserTextControlDisabled(browser.cdp, "Configure Generic Webhook"), true, "reload enabled a competing integration mutation");
  console.log("combined E2E: reload revocation receipt remained locked and pending without a deleted claim");

  await completeHarnessConnectorRevocation(dsn, reloadRevocationIntegrationID);
  const reloadTerminal = await browserHarnessDirectIntegrationDeleteReplay(browser.cdp, reloadRevocationIntegrationID, reloadPendingRequest.idempotencyKey, reloadPendingRequest.ifMatch, expectedProductionScope);
  assert.equal(reloadTerminal.status, 204, `harness direct-public-API replay did not reach terminal 204: ${JSON.stringify(reloadTerminal)}`);
  assert.equal(reloadTerminal.body, "");
  await waitForScopeOverlap(() => integrationDeleteRequests.length >= reloadDeleteStart + 2, "harness direct-public-API replay was not observed at the public API");
  const reloadRequests = integrationDeleteRequests.slice(reloadDeleteStart);
  assert.deepEqual(reloadRequests.map((request) => request.status), [202, 204]);
  assert.equal(new Set(reloadRequests.map((request) => request.idempotencyKey)).size, 1, "same idempotency key + If-Match changed across reload");
  assert.equal(new Set(reloadRequests.map((request) => request.ifMatch)).size, 1, "same idempotency key + If-Match changed across reload");
  const integrationRefetchStart = workflowPageRequests.integrations.length;
  await clickBrowserText(browser.cdp, "Acknowledge recovered result");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Mutation recovery"]');
  await waitForScopeOverlap(() => workflowPageRequests.integrations.length > integrationRefetchStart, "terminal recovery did not refetch integrations");
  await waitForBrowserAction(browser.cdp, `document.querySelector(${JSON.stringify('[aria-label="Open Harness reload revocation"]')}) === null`);
  assert.doesNotMatch(await browserBodyText(browser.cdp), /Integration deleted/);
  console.log("combined E2E: public 202-to-204 integration deletion and harness direct-public-API replay after reload proven; this is not frontend persistence");

  await clickBrowserText(browser.cdp, "Configure Generic Webhook");
  await waitForBrowserActive(browser.cdp, "Close");
  assert.equal(await browserDialogIsolation(browser.cdp), true, "active production modal did not isolate its background");
  await dispatchBrowserKey(browser.cdp, "Tab", { shift: true });
  await waitForBrowserActive(browser.cdp, "Cancel");
  await dispatchBrowserKey(browser.cdp, "Tab");
  await waitForBrowserActive(browser.cdp, "Close");
  await dispatchBrowserKey(browser.cdp, "Escape");
  await waitForBrowserActive(browser.cdp, "Configure Generic Webhook");
  await clickBrowserText(browser.cdp, "Configure Generic Webhook");
  await waitForBrowserActive(browser.cdp, "Close");
  console.log("combined E2E: keyboard focus trap and restoration proven");
  await fillBrowserLabel(browser.cdp, "HTTPS destination", "https://hooks.customer.invalid/zasp");
  await fillBrowserLabel(browser.cdp, "Signing secret", "secret_ref_combined_e2e");
  await clickBrowserText(browser.cdp, "Save integration");
  await waitForBrowserText(browser.cdp, /Integration created\. Audit pid_/);
  await waitForBrowserText(browser.cdp, /No delivery test for the current configuration/);
  await clickBrowserText(browser.cdp, "Test signed delivery");
  await waitForBrowserText(browser.cdp, /Webhook test failed\. Audit pid_/);
  await waitForBrowserText(browser.cdp, /Signature and acceptance are unconfirmed/);
  assert.equal(integrationWebhookTestRequests.length, 2, "webhook lost-response replay was not exercised");
  assert.equal(new Set(integrationWebhookTestRequests.map((item) => item.idempotencyKey)).size, 1, "webhook retry changed its idempotency key");
  assert.equal(new Set(integrationWebhookTestRequests.map((item) => item.auditID)).size, 1, "webhook retry changed its audit record");
  assert.equal(integrationWebhookTestRequests.every((item) => item.body === "{}" && item.ifMatch === '"1"' && item.csrf.length >= 16 && item.status === 200), true, "webhook test lost saved-configuration authority");
  const webhookDurability = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", "SELECT count(*) || '|' || min(state) FROM zasp_integration_webhook_tests;"]);
  assert.equal(webhookDurability.stdout.trim(), "1|failed", "webhook failure was not durably retained once");
  await clickBrowserAria(browser.cdp, "Close");
  await reloadBrowserPage(browser.cdp);
  await clickBrowserAria(browser.cdp, "Open Generic Webhook");
  await waitForBrowserText(browser.cdp, /Delivery status: failed/);
  assert.equal(integrationWebhookTestRequests.length, 2, "webhook status reload emitted another delivery");
  await clickBrowserAria(browser.cdp, "Close");
  console.log("combined E2E: webhook delivery failure remained truthful and durable across lost response and reload");

  await navigateBrowser(browser.cdp, `${publicOrigin}/protect/security-agents`);
  await waitForBrowserText(browser.cdp, /Tenant-scoped response definitions/);
  await clickBrowserText(browser.cdp, "Create Security Agent");
  await clickBrowserText(browser.cdp, "Save Security Agent definition");
  await waitForBrowserText(browser.cdp, /Bounded response definition/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Simulate plan|Start supervised run|Approve|Reject|Cancel run)$/i), false);
	await exerciseSecurityAgentAutomaticLifecycle(browser.cdp, workerE2EBinary, gatewayE2EBinary, apiBinary, apiEnvironment, healthPort, postgresPort, dsn, publicOrigin, actionPrivateKey);
	console.log("combined E2E: full-document receipt recovery, local integration, and automatic Security Agent authority proven");
	await exerciseTypedInventoryRetention(publicOrigin, dsn, postgresPort, workerE2EBinary, patHeaders.authorization);
	await navigateBrowser(browser.cdp, `${publicOrigin}/discovery/assets`);
	await waitForBrowserText(browser.cdp, /No records in this scope/);
	await exerciseProductionAttackLabLifecycle(browser.cdp, workerE2EBinary, postgresPort, dsn, publicOrigin);
	await runProductionRecoveryLifecycle(browser.cdp, agentsecctl, workerE2EBinary, postgresPort, dsn, publicOrigin, certificate, recoveryCredentialFile, expectedProductionScope);

  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/identity-access`);
  const identityAccess = await waitForBrowserText(browser.cdp, /member-target-local[\s\S]*E2E Organization/);
  assert.match(identityAccess, /E2E Organization/);
  assert.match(identityAccess, /Enterprise identity[\s\S]*Configured/);
  assert.match(identityAccess, /Corporate SAML[\s\S]*active/);
  assert.match(identityAccess, /No SCIM connections/);
  await clickBrowserText(browser.cdp, "Test Corporate SAML");
  await waitForBrowserText(browser.cdp, /Corporate SAML connection is healthy/);
  await fillBrowserLabel(browser.cdp, "SSO display name", "E2E SSO");
  await clickBrowserText(browser.cdp, "Add SSO connection");
  assert.match(await waitForBrowserText(browser.cdp, /SSO connection created/), /E2E SSO/);
  await fillBrowserLabel(browser.cdp, "SCIM display name", "E2E SCIM");
  await clickBrowserText(browser.cdp, "Add SCIM connection");
  const scimCreated = await waitForBrowserText(browser.cdp, /Copy the SCIM bearer token now/);
  assert.match(scimCreated, /scim_bearer_token_e2e_only_copy_once/);
  await clickBrowserText(browser.cdp, "Hide token");
  await waitForBrowserTextMissing(browser.cdp, "scim_bearer_token_e2e_only_copy_once");
  const providerConnectionProof = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT count(*) FROM zasp_identity_provider_connections WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND connection_reference IN('saml-connection-e2e-created','scim-connection-e2e-created')),
    (SELECT count(*) FROM zasp_identity_provider_mutations WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND state='completed' AND operation IN('createSSOConnection','createSCIMConnection','testSSOConnection')),
    (SELECT count(*) FROM zasp_identity_secret_reveal_grants WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND acknowledged_at IS NULL AND ciphertext IS NOT NULL AND position(convert_to('scim_bearer_token_e2e_only_copy_once','UTF8') IN ciphertext)=0),
    (SELECT count(*) FROM zasp_identity_provider_mutations WHERE response::text LIKE '%scim_bearer_token_e2e_only_copy_once%')
  );`]);
  assert.equal(providerConnectionProof.stdout.trim(), "2|3|1|0", "SSO/SCIM mutations were not durably bound or retained a raw bearer credential");
  assert.deepEqual(stytchProviderRequests.map((request) => `${request.method} ${request.path}`).sort(), [
    "GET /v1/b2b/scim/organization-test-local/connection",
    "GET /v1/b2b/scim/organization-test-local/connection",
    "GET /v1/b2b/sso/organization-test-local",
    "GET /v1/b2b/sso/organization-test-local",
    "GET /v1/b2b/sso/organization-test-local",
    "GET /v1/b2b/sso/organization-test-local",
    "POST /v1/b2b/scim/organization-test-local/connection",
    "POST /v1/b2b/sso/saml/organization-test-local",
  ]);
	console.log("combined E2E: production SSO and SCIM browser workflow proven");
	assert.doesNotMatch(identityAccess, /Unpermitted environment/, "scope selector exposed an environment without an authorized-scope row");
	const identityAccessReauthenticationStarts = identityOAuthStarts;
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_product_sessions SET authenticated_at=transaction_timestamp()-interval '10 minutes' WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
  await reloadBrowser(browser.cdp);
  const expiredFreshAuth = await waitForBrowserText(browser.cdp, /Fresh authentication expired/);
  assert.match(expiredFreshAuth, /Reauthenticate/);
  assert.equal(await browserTextControlDisabled(browser.cdp, "Update role"), true, "fresh-auth-expired role mutation remained enabled");
  await clickBrowserText(browser.cdp, "Reauthenticate");
  await waitForBrowserText(browser.cdp, /Continue through the configured identity provider/);
  await clickBrowserText(browser.cdp, "Continue to sign in");
  const reauthenticatedIdentity = await waitForBrowserText(browser.cdp, /member-target-local/);
  assert.doesNotMatch(reauthenticatedIdentity, /Fresh authentication expired/);
	assert.equal(identityOAuthStarts, identityAccessReauthenticationStarts + 1, "fresh reauthentication did not use the provider-faithful start/callback path exactly once");
  assert.match(await browserCurrentURL(browser.cdp), /\/administration\/identity-access$/);
  await selectBrowserOption(browser.cdp, "Role for member-target-local", "read only viewer");
  const reauthenticatedRoleControl = await browserRoleControlState(browser.cdp, "Role for member-target-local", "Update role");
  assert.deepEqual(reauthenticatedRoleControl, { selected: "read_only_viewer", disabled: false }, `fresh reauthentication left sensitive role control unavailable: ${JSON.stringify(reauthenticatedRoleControl)}`);
  await selectBrowserOptionAndClickSibling(browser.cdp, "Role for member-target-local", "read only viewer", "Update role");
  await waitForBrowserText(browser.cdp, /Member role updated; active sessions revoked/);
  const roleResult = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT role || '|' || (SELECT count(*) FROM zasp_product_sessions WHERE session_id='session-role-change-e2e' AND revoked_at IS NOT NULL) FROM zasp_identity_memberships WHERE principal_id='pid_10000005-0000-4000-8000-000000000005';`]);
  assert.equal(roleResult.stdout.trim(), "read_only_viewer|1", "member role and session revocation were not atomic");
  await exerciseStytchDeprovision(publicOrigin, dsn);
  await fillBrowserLabel(browser.cdp, "New workspace name", "E2E Workspace");
  await clickBrowserText(browser.cdp, "Create workspace");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized workspace", "E2E Workspace");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized environment", "Development");
  const onboardedScope = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT count(*) || '|' || count(environment.id) || '|' || count(scope.environment_id) || '|' || count(controls.environment_id) || '|' || count(payload.environment_id) FROM zasp_workspaces workspace JOIN zasp_environments environment ON environment.organization_id=workspace.organization_id AND environment.workspace_id=workspace.id JOIN zasp_authorized_scopes scope ON scope.organization_id=environment.organization_id AND scope.workspace_id=environment.workspace_id AND scope.environment_id=environment.id AND scope.principal_id='pid_10000004-0000-4000-8000-000000000004' JOIN zasp_data_controls controls ON controls.organization_id=environment.organization_id AND controls.workspace_id=environment.workspace_id AND controls.environment_id=environment.id JOIN zasp_core_payloads payload ON payload.organization_id=environment.organization_id AND payload.workspace_id=environment.workspace_id AND payload.environment_id=environment.id AND payload.operation='session_bootstrap:pid_10000004-0000-4000-8000-000000000004' WHERE workspace.name='E2E Workspace';`]);
  assert.equal(onboardedScope.stdout.trim(), "1|1|1|1|1", "workspace onboarding did not atomically create its first authorized environment and reload boundary");
  await fillBrowserLabel(browser.cdp, "New environment name", "E2E Development");
  await clickBrowserText(browser.cdp, "Create environment");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "E2E Development");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized environment", "E2E Development");
  const onboardedDevelopmentScope = await browserSelectedOptionValue(browser.cdp, "Authorized scope");
  assert.notEqual(onboardedDevelopmentScope, "pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003", "environment onboarding did not select its new scope");
  await waitForBrowserScope(browser.cdp, `pid_10000001-0000-4000-8000-000000000001/${onboardedDevelopmentScope}`);
  await selectBrowserOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized workspace", "Production Workspace");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized environment", "Production");
  await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");

  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/api-access`);
  await waitForBrowserText(browser.cdp, /Create scoped automation credentials/);
  const seededTokenCount = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT count(*) || '|' || count(*) FILTER (WHERE revoked_at IS NULL) || '|' || count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM zasp_product_api_tokens WHERE organization_id='pid_10000001-0000-4000-8000-000000000001';`]);
  assert.equal(seededTokenCount.stdout.trim(), "2|1|1", "identity deprovision did not preserve one revoked token while retaining the active administrator token");
  const browserTokenInventory = await browserFetchJSON(browser.cdp, "/api/v1/admin/api-tokens", {
    "X-Zasp-Expected-Scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
  });
  assert.equal(browserTokenInventory.status, 200, JSON.stringify(browserTokenInventory.body));
  assert.equal(browserTokenInventory.body.items.length, 2);
  assert.equal(browserTokenInventory.body.items.filter((item) => item.revoked_at === null).length, 1, "API token inventory omitted or duplicated the active administrator token");
  assert.equal(browserTokenInventory.body.items.filter((item) => item.revoked_at !== null).length, 1, "API token inventory omitted the deprovisioned member's revoked audit state");
  await waitForBrowserText(browser.cdp, /New credentials use the authenticated active scope/);
  assert.equal(await browserLabeledControlDisabled(browser.cdp, "Workspace ID"), null, "token create exposed an editable workspace ID");
  assert.equal(await browserLabeledControlDisabled(browser.cdp, "Environment ID"), null, "token create exposed an editable environment ID");

  await fillBrowserLabel(browser.cdp, "Token name", "Accessibility token");
  await clickBrowserText(browser.cdp, "Create API token");
  const accessibleTokenOutcome = await waitForBrowserText(browser.cdp, /Save API token|Create response was interrupted/);
  assert.match(accessibleTokenOutcome, /Save API token/, `accessible token create failed: ${JSON.stringify(administrationRequests.slice(-8))}`);
  await waitForBrowserActive(browser.cdp, "Close");
  assert.equal(await browserDialogIsolation(browser.cdp), true, "one-time token dialog did not isolate its background");
  await dispatchBrowserKey(browser.cdp, "Tab");
  await waitForBrowserActive(browser.cdp, "Copy token");
	await clickBrowserText(browser.cdp, "Copy token");
	assert.match(await waitForBrowserText(browser.cdp, /Token copied to clipboard|Copy failed/), /Token copied to clipboard|Copy failed/);
	const tokenDialogReauthenticationStarts = identityOAuthStarts;
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_product_sessions SET authenticated_at=transaction_timestamp()-interval '10 minutes' WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
  await clickBrowserText(browser.cdp, "I saved it — destroy recovery copy");
  await waitForBrowserText(browser.cdp, /revealed token was cleared/);
  assert.doesNotMatch(await browserBodyText(browser.cdp), /zasp_pat_[A-Za-z0-9_-]{43}/, "fresh-auth expiry left a raw token in the document");
  assert.equal(await browserHasInteractiveText(browser.cdp, /^Copy token$/), false, "fresh-auth expiry left token copy enabled");
  await clickBrowserText(browser.cdp, "Reauthenticate");
  await waitForBrowserText(browser.cdp, /Continue through the configured identity provider/);
  await clickBrowserText(browser.cdp, "Continue to sign in");
  await waitForBrowserText(browser.cdp, /Created token/);
	assert.equal(identityOAuthStarts, tokenDialogReauthenticationStarts + 1, "token-dialog reauthentication did not use the provider-faithful flow exactly once");
  await clickBrowserText(browser.cdp, "Reveal token");
  await waitForBrowserText(browser.cdp, /Save API token/);
  await clickBrowserText(browser.cdp, "I saved it — destroy recovery copy");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Save API token"]');
  await waitForBrowserControlDisabled(browser.cdp, "Create API token", false);

  await fillBrowserLabel(browser.cdp, "Token name", "E2E API token");
  lostTokenResponses.create = true;
  await clickBrowserText(browser.cdp, "Create API token");
  const tokenCreateOutcome = await waitForBrowserText(browser.cdp, /Create response was interrupted/);
  assert.match(tokenCreateOutcome, /Created token/, `lost create did not expose its durable grant: ${JSON.stringify(administrationRequests.slice(-12))}`);
  assert.equal(await browserLabeledControlDisabled(browser.cdp, "Token name"), true, "ambiguous create did not lock token inputs");
  assert.equal(await browserTextControlDisabled(browser.cdp, "Retry retained API token create"), true, "pending durable grant did not lock create retry");
  const createdTokenCounts = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_product_api_tokens WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND name='E2E API token'),
    (SELECT count(*) FROM zasp_api_token_reveal_grants reveal_grant JOIN zasp_product_api_tokens token ON token.id=reveal_grant.token_id WHERE token.name='E2E API token' AND reveal_grant.operation='createAPIToken' AND reveal_grant.acknowledged_at IS NULL),
    (SELECT count(*) FROM zasp_admin_idempotency WHERE operation='createAPIToken' AND response->'token'->>'name'='E2E API token'),
    (SELECT count(*) FROM zasp_admin_audit audit JOIN zasp_product_api_tokens token ON token.id=audit.target_id WHERE token.name='E2E API token' AND audit.action='api_token.create');`]);
  assert.equal(createdTokenCounts.stdout.trim(), "1|1|1|1", "lost create response did not reconcile one token, grant, idempotency claim, and audit");
  const createGrant = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT reveal_grant.grant_id FROM zasp_api_token_reveal_grants reveal_grant JOIN zasp_product_api_tokens token ON token.id=reveal_grant.token_id WHERE token.name='E2E API token' AND reveal_grant.operation='createAPIToken';`])).stdout.trim();
  lostTokenResponses.reveal = true;
  await clickBrowserText(browser.cdp, "Reveal token");
  await waitForBrowserText(browser.cdp, /API token reveal grant is unavailable or expired/);
  await clickBrowserText(browser.cdp, "Reveal token");
  await waitForBrowserText(browser.cdp, /Save API token/);
  await waitForBrowserActive(browser.cdp, "Close");
  const originalAPIToken = await waitForBrowserTextMatch(browser.cdp, /zasp_pat_[A-Za-z0-9_-]{43}/);
  assert.equal((await browserBodyText(browser.cdp)).match(/zasp_pat_[A-Za-z0-9_-]{43}/g)?.length, 1, "one-time token appeared outside its dialog");
  assert.doesNotMatch(await browserStorageAndHistoryText(browser.cdp), /zasp_pat_/, "one-time token entered browser storage or history");
  const originalTokenAccess = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents`, { method: "GET", headers: { authorization: `Bearer ${originalAPIToken}` } });
  assert.equal(originalTokenAccess.status, 200);
  lostTokenResponses.acknowledge = true;
  await clickBrowserText(browser.cdp, "I saved it — destroy recovery copy");
  await waitForBrowserText(browser.cdp, /Acknowledgement failed/);
  assert.match(await browserBodyText(browser.cdp), /Save API token/);
  await clickBrowserText(browser.cdp, "I saved it — destroy recovery copy");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Save API token"]');
  const destroyedCreateGrant = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT (acknowledged_at IS NOT NULL)::text || '|' || (ciphertext IS NULL)::text || '|' || (nonce IS NULL)::text || '|' || (authentication_tag IS NULL)::text || '|' || (SELECT count(*) FROM zasp_admin_audit WHERE action='api_token.reveal.acknowledge' AND metadata->>'grant_id'='${createGrant}') FROM zasp_api_token_reveal_grants WHERE grant_id='${createGrant}';`]);
  assert.equal(destroyedCreateGrant.stdout.trim(), "true|true|true|true|1", "ack retry did not atomically destroy the encrypted recovery copy exactly once");
  const revealAfterAck = await browserScopedMutationJSON(browser.cdp, `/api/v1/admin/api-token-reveal-grants/${createGrant}/reveal`, "POST", "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
  assert.equal(revealAfterAck.status, 404, "acknowledged API token could be replayed");

  lostTokenResponses.rotate = true;
  await clickBrowserAria(browser.cdp, "Rotate E2E API token");
  const tokenRotateOutcome = await waitForBrowserText(browser.cdp, /Rotate response was interrupted/);
  assert.match(tokenRotateOutcome, /Rotated token/);
  const rotateGrant = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT reveal_grant.grant_id FROM zasp_api_token_reveal_grants reveal_grant JOIN zasp_product_api_tokens token ON token.id=reveal_grant.token_id WHERE token.name='E2E API token' AND reveal_grant.operation='rotateAPIToken';`])).stdout.trim();
  const restartReloadURL = await browserCurrentURL(browser.cdp);
  await stopChild(api);
  api = startChild(apiBinary, [], { env: apiEnvironment });
  await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
  await navigateBrowser(browser.cdp, restartReloadURL);
  await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
  const restartPendingGrant = await waitForBrowserText(browser.cdp, /Rotated token/);
  assert.doesNotMatch(restartPendingGrant, /zasp_pat_/, "restart-pending reveal grant exposed a token before reveal");
  assert.equal(await browserTextControlDisabled(browser.cdp, "Create API token"), true, "restart-pending reveal grant did not lock token mutations");
  await clickBrowserText(browser.cdp, "Reveal token");
  await waitForBrowserTextMissing(browser.cdp, originalAPIToken);
  const rotatedAPIToken = await waitForBrowserTextMatch(browser.cdp, /zasp_pat_[A-Za-z0-9_-]{43}/);
  assert.notEqual(rotatedAPIToken, originalAPIToken);
  const oldTokenAccess = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents`, { method: "GET", headers: { authorization: `Bearer ${originalAPIToken}` } });
  assert.equal(oldTokenAccess.status, 401, "old API token remained valid after rotation");
  const rotatedTokenAccess = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents`, { method: "GET", headers: { authorization: `Bearer ${rotatedAPIToken}` } });
  assert.equal(rotatedTokenAccess.status, 200);
  await clickBrowserText(browser.cdp, "I saved it — destroy recovery copy");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Save API token"]');
  const rotatedTokenCounts = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_product_api_tokens WHERE name='E2E API token'),
    (SELECT count(*) FROM zasp_admin_idempotency WHERE operation='rotateAPIToken' AND grant_id='${rotateGrant}'),
    (SELECT count(*) FROM zasp_admin_audit WHERE action='api_token.rotate' AND metadata->>'replacement_id' IS NOT NULL),
    (SELECT count(*) FROM zasp_api_token_reveal_grants WHERE grant_id='${rotateGrant}' AND acknowledged_at IS NOT NULL AND ciphertext IS NULL AND nonce IS NULL AND authentication_tag IS NULL);`]);
  assert.equal(rotatedTokenCounts.stdout.trim(), "2|1|1|1", "lost rotate/restart recovery duplicated or retained token/grant state");
  assert.equal(tokenMutationKeys.create.length, 2, "unexpected API token create request count");
  assert.equal(new Set(tokenMutationKeys.create).size, 2, "distinct token creates reused an idempotency key");
  assert.equal(tokenMutationKeys.rotate.length, 1, "lost rotate recovery sent a second mutation instead of reconciling its grant");
  const reloadedAPIInventory = await waitForBrowserText(browser.cdp, /E2E API token/);
  assert.doesNotMatch(reloadedAPIInventory, /zasp_pat_/, "one-time API token survived a browser reload");
  await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");

  await seedInvestigationSession(dsn);
  await navigateBrowser(browser.cdp, `${publicOrigin}/investigate/sessions`);
  await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
  const investigation = await waitForBrowserText(browser.cdp, /Shell requested by E2E/);
  assert.match(investigation, /evidence-session-e2e/);
  await clickBrowserAria(browser.cdp, "Revoke session session-investigation-e2e");
  const sessionRevokeOutcome = await waitForBrowserText(browser.cdp, /Session revoked|Session could not be revoked/);
  assert.match(sessionRevokeOutcome, /Session revoked/, `administration requests: ${JSON.stringify(administrationRequests)}`);
  const revokedSession = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT (revoked_at IS NOT NULL)::text || '|' || version FROM zasp_product_sessions WHERE session_id='session-investigation-e2e';`]);
  assert.equal(revokedSession.stdout.trim(), "true|2");
	await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");

	const auditInventory = await browserFetchJSON(browser.cdp, "/api/v1/audit-events?limit=100", {
		"X-Zasp-Expected-Scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
	});
	assert.equal(auditInventory.status, 200, JSON.stringify(auditInventory.body));
	assert.equal(auditInventory.body.items.every((item) => Object.values(item.metadata).every((value) => typeof value === "string")), true, "public audit metadata escaped its string-only contract");
	const auditActions = new Set(auditInventory.body.items.map((item) => item.action));
	for (const action of ["session.revoke", "member.role.update", "api_token.create", "api_token.rotate", "identity.member.deprovision"]) assert.equal(auditActions.has(action), true, `public audit inventory omitted ${action}`);
	await navigateBrowser(browser.cdp, `${publicOrigin}/administration/audit-log`);
	await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
	await waitForBrowserAction(browser.cdp, `document.querySelector('select[aria-label="Authorized scope"]')?.value === "pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003"`);
	const auditSelectedScope = await browserSelectedOptionValue(browser.cdp, "Authorized scope");
	assert.equal(auditSelectedScope, "pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003", "audit target retained stale scope after server reconciliation");
  const auditLog = await waitForBrowserText(browser.cdp, /session\.revoke/);
  assert.match(auditLog, /member\.role\.update/);
  assert.match(auditLog, /api_token\.create/);
  assert.match(auditLog, /api_token\.rotate/);
  assert.match(auditLog, /Audit exports unavailable/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^Export$/i), false);
  await navigateBrowser(browser.cdp, `${publicOrigin}/compliance/evidence`);
  const compliance = await waitForBrowserText(browser.cdp, /evidence-membership/);
  assert.match(compliance, /SOC 2/);
  assert.match(compliance, /Evidence exports unavailable/);
  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/data-retention`);
  const dataControls = await waitForBrowserText(browser.cdp, /production controls/);
  assert.match(dataControls, /metadata only/);
  assert.match(dataControls, /Data deletion unavailable/);
  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/external-data-flows`);
  const externalFlows = await waitForBrowserText(browser.cdp, /identity-provider/);
  assert.match(externalFlows, /degraded/);
  assert.doesNotMatch(externalFlows, /analytics|warehouse|support/i);
  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/system-health`);
  const systemHealth = await waitForBrowserText(browser.cdp, /postgresql/);
  assert.match(systemHealth, /identity-provider/);
  assert.match(systemHealth, /Security plane degraded/);
  assert.match(systemHealth, /identity-provider\s+degraded/);
  assert.doesNotMatch(systemHealth, /Security plane healthy/, "configured provider remained falsely healthy without a live verifier");
  const tokenResponses = administrationRequests.filter((request) => request.path.includes("api-token"));
  assert.ok(tokenResponses.length >= 10, `missing token lifecycle requests: ${JSON.stringify(tokenResponses)}`);
  assert.equal(tokenResponses.every((request) => request.cacheControl === "no-store"), true, "API token response omitted cache-control no-store");
  console.log("combined E2E: production administration lifecycle and hidden provider/export mutations proven");

  await selectBrowserOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
  await waitForBrowserTextMissing(browser.cdp, "Switching scope…");
  await stopChild(api);
  api = startChild(apiBinary, [], { env: apiEnvironment });
  await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
  await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
  await navigateBrowser(browser.cdp, `${publicOrigin}/violations`);
  await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserText(browser.cdp, /Production credential exposure 0001/);
  await clickBrowserText(browser.cdp, "Production credential exposure 0001");
  assert.match(await waitForBrowserText(browser.cdp, /Accepted production exception/), /accepted/);
  await clickBrowserAria(browser.cdp, "Close");
  await navigateBrowser(browser.cdp, `${publicOrigin}/exposure/attack-paths`);
  await clickBrowserAria(browser.cdp, "Open attack path pid_40000001-0000-4000-8000-000000000001");
  assert.match(await waitForBrowserText(browser.cdp, /Remove node/), /pid_70000001-0000-4000-8000-000000000001/);
  await clickBrowserAria(browser.cdp, "Close");
  await navigateBrowser(browser.cdp, `${publicOrigin}/policies`);
  const reloaded = await waitForBrowserText(browser.cdp, /Production runtime policy/);
  assert.match(reloaded, /Production runtime policy/);
  assert.doesNotMatch(reloaded, /Sign in to Zasp|Product API unavailable/);
  await clickBrowserAria(browser.cdp, "Open Production runtime policy");
  assert.match(await waitForBrowserText(browser.cdp, /Policy detail · policy-production/), /enforced/);
  await navigateBrowser(browser.cdp, `${publicOrigin}/connectors`);
  assert.match(await waitForBrowserText(browser.cdp, /Generic Webhook[\s\S]*configured/), /configured/);
	const reloadedSecurityAgentID = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT definition_id FROM zasp_security_agent_definitions WHERE body->>'name'='Bounded response definition' AND deleted_at IS NULL;`])).stdout.trim();
	assert.match(reloadedSecurityAgentID, /^pid_[0-9a-f-]{36}$/);
	const reloadedSecurityAgentCookie = await getBrowserSessionCookie(browser.cdp, publicOrigin);
	const reloadedSecurityAgentHeaders = { cookie: `__Host-zasp_session=${reloadedSecurityAgentCookie.value}`, "x-zasp-expected-scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003" };
	const reloadedSecurityAgentDefinition = await requestHTTPSJSON(`${publicOrigin}/api/v1/security-agents/${reloadedSecurityAgentID}`, { method: "GET", headers: reloadedSecurityAgentHeaders });
	const reloadedSecurityAgentActivation = await requestHTTPSJSON(`${publicOrigin}/api/v1/security-agents/${reloadedSecurityAgentID}/activation`, { method: "GET", headers: reloadedSecurityAgentHeaders });
	assert.equal(reloadedSecurityAgentDefinition.status, 200, `reloaded Security Agent definition failed: ${JSON.stringify(reloadedSecurityAgentDefinition)}`);
	assert.equal(reloadedSecurityAgentActivation.status, 200, `reloaded Security Agent activation failed: ${JSON.stringify(reloadedSecurityAgentActivation)}`);
	assert.equal(reloadedSecurityAgentDefinition.headers.etag, `"${reloadedSecurityAgentActivation.body.version}"`, "reloaded Security Agent definition and activation versions diverged");
  await navigateBrowser(browser.cdp, `${publicOrigin}/protect/security-agents`);
  await waitForBrowserText(browser.cdp, /Bounded response definition/);
  await clickBrowserAria(browser.cdp, "Open Bounded response definition");
  const persistedSecurityAgent = await waitForBrowserText(browser.cdp, /Resource version/);
  assert.match(persistedSecurityAgent, /finding · pid_10000003-0000-4000-8000-000000000003 · supervised/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Simulate plan|Start supervised run)$/i), true);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Approve|Reject|Cancel run)$/i), false);
  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/audit-log`);
  assert.match(await waitForBrowserText(browser.cdp, /session\.revoke/), /api_token\.rotate/);
  await navigateBrowser(browser.cdp, `${publicOrigin}/compliance/evidence`);
  assert.match(await waitForBrowserText(browser.cdp, /evidence-membership/), /Evidence exports unavailable/);
  console.log("combined E2E: API restart, browser reload, and durable local workflows proven");

  const denied = await browserFetchJSON(browser.cdp, "/api/v1/agents/pid_90000001-0000-4000-8000-000000000001", {
    "X-Zasp-Expected-Scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
  });
  assert.equal(denied.status, 404);
  assert.equal(denied.body.code, "not_found");
  assert.doesNotMatch(JSON.stringify(denied.body), /Foreign tenant agent/);
  const deniedFinding = await browserFetchJSON(browser.cdp, "/api/v1/findings/pid_90000007-0000-4000-8000-000000000007", {
    "X-Zasp-Expected-Scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
  });
  assert.equal(deniedFinding.status, 404);
  assert.equal(deniedFinding.body.code, "not_found");
  assert.doesNotMatch(JSON.stringify(deniedFinding.body), /Foreign tenant finding/);

  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/identity-access`);
  const identityForGroupMapping = await waitForBrowserText(browser.cdp, /member-group-e2e/);
  if (/Fresh authentication expired/.test(identityForGroupMapping)) {
    await clickBrowserText(browser.cdp, "Reauthenticate");
    await waitForBrowserText(browser.cdp, /Continue through the configured identity provider/);
    await clickBrowserText(browser.cdp, "Continue to sign in");
    await waitForBrowserText(browser.cdp, /member-group-e2e/);
  }
  await fillBrowserLabel(browser.cdp, "Stytch SCIM group ID", identityGroupReference);
  await selectBrowserOption(browser.cdp, "Mapped role", "read only viewer");
  await fillBrowserLabel(browser.cdp, "Workspace ID", "pid_10000002-0000-4000-8000-000000000002");
  await fillBrowserLabel(browser.cdp, "Environment ID", "pid_10000003-0000-4000-8000-000000000003");
  await clickBrowserText(browser.cdp, "Save group mapping");
  await waitForBrowserText(browser.cdp, /Group mapping saved; affected sessions revoked/);

  nextIdentityLogin = "group";
  await navigateBrowser(browser.cdp, `${publicOrigin}/sign-in?return_to=%2F`);
  await waitForBrowserText(browser.cdp, /Sign in to Zasp[\s\S]*Continue through the configured identity provider/);
  await clickBrowserText(browser.cdp, "Continue to sign in");
  const groupOnlyHome = await waitForBrowserText(browser.cdp, /Security overview/);
  nextIdentityLogin = "admin";
	assert.doesNotMatch(groupOnlyHome, /Scope unavailable|Session unavailable|No product capabilities/);
	await waitForBrowserScope(browser.cdp, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
	assert.doesNotMatch(await browserBodyText(browser.cdp), /Staging|Unpermitted environment/, "group-only session exposed an unmapped tenant scope");
  const staleForeignScope = await browserFetchJSON(browser.cdp, "/api/v1/agents", {
    "X-Zasp-Expected-Scope": "pid_90000001-0000-4000-8000-000000000001/pid_90000002-0000-4000-8000-000000000002/pid_90000003-0000-4000-8000-000000000003",
  });
  assert.equal(staleForeignScope.status, 409);
  assert.equal(staleForeignScope.body.code, "scope_stale");
  const foreignAgentFromGroupSession = await browserFetchJSON(browser.cdp, "/api/v1/agents/pid_90000001-0000-4000-8000-000000000001", {
    "X-Zasp-Expected-Scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
  });
  assert.equal(foreignAgentFromGroupSession.status, 404);
  assert.equal(foreignAgentFromGroupSession.body.code, "not_found");
  const groupAuthorityProof = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT count(*) FROM zasp_group_mappings WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND group_reference='${identityGroupReference}' AND role='read_only_viewer' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003'),
    (SELECT count(*) FROM zasp_identity_member_groups WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND principal_id='pid_10000007-0000-4000-8000-000000000007' AND group_reference='${identityGroupReference}'),
    (SELECT count(*) FROM zasp_authorized_scopes WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND principal_id='pid_10000007-0000-4000-8000-000000000007'),
    (SELECT count(*) FROM zasp_product_sessions WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND principal_id='pid_10000007-0000-4000-8000-000000000007' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND permissions @> '["view"]'::jsonb AND revoked_at IS NULL)
  );`]);
  assert.equal(groupAuthorityProof.stdout.trim(), "1|1|0|1", "group-only login did not derive its exact tenant scope from the verified provider group");
  console.log("combined E2E: production SSO, SCIM, and group-mapping browser workflow proven");
  console.log("combined E2E: group-derived browser login scope and cross-tenant denial proven");

  const connectorForensics = await browserConnectorForensics(browser.cdp);
  assert.deepEqual(connectorForensics.local, {});
  assert.deepEqual(connectorForensics.session, {});
  assert.deepEqual(connectorForensics.cacheKeys, []);
  assert.deepEqual(connectorForensics.indexedDatabases, []);
  const connectorBrowserSurface = JSON.stringify({ connectorForensics, browserConsoleMessages });
  assert.doesNotMatch(connectorBrowserSurface, /zasp_pat_|scim_bearer_token|access_token|refresh_token|code_verifier|client_secret|authorization_url|authorization_attempt_id|connector-(?:code|state|cross-scope)|secret-test-local|ref:(?:github\/(?:client-secret|app-private-key)|okta\/client-secret)|MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY/i);
  assert.equal(connectorForensics.navigationHistory.some((entry) => /[?&](?:code|state)=/i.test(`${entry.url} ${entry.userTypedURL}`)), false, "connector code/state remained in browser navigation history");
  console.log("combined E2E: connector tokens, state, verifier, and secrets absent from DOM, URL/history, storage, caches, IndexedDB, and console");
  assert.deepEqual(browserConsoleErrors, [], `browser console/exception errors: ${JSON.stringify(browserConsoleErrors)}`);
  console.log("combined E2E: browser console and exception stream remained clean");
  assert.equal(proxyFailure, undefined, `proxy fixture failed: ${proxyFailure}`);
  console.log("combined E2E: live provider revocation NOT RUN; harness exercised only explicit external-provider completion simulation");
  console.log("combined E2E: live AWS/GitHub/Okta connector success remains typed external evidence");
  console.log("combined E2E: live AWS/Kubernetes/GitHub/Okta collection and managed SQS/S3/OpenSearch/Neo4j remain NOT RUN");

  console.log("production combined E2E passed: callback/cookie/bootstrap, risk pagination/recovery, administration, PAT/receipt recovery, responsive keyboard focus, durable restart/reload, tenant denial");
  }
} finally {
	await cleanupController.run();
	cleanupController.dispose();
}

async function cleanupOwnedResources() {
  let runtimeCleanupError;
  try { await runtimePipelineDependencies.close(); } catch (error) { runtimeCleanupError = error; }
  console.log("combined E2E: cleanup browser");
  if (secondBrowserTab) await secondBrowserTab.dispose();
  if (browser) {
    browser.cdp.close();
    await stopChild(browser.child);
  }
  console.log("combined E2E: cleanup Task4 workers");
  for (const worker of task4Workers.reverse()) await stopChild(worker);
  task4Workers.length = 0;
  console.log("combined E2E: cleanup api");
  if (api) await stopChild(api);
  console.log("combined E2E: cleanup proxy");
  if (proxy) await closeServer(proxy);
  console.log("combined E2E: cleanup identity");
  if (identity) await closeServer(identity);
  console.log("combined E2E: cleanup policy history");
  if (policyHistory) await closeServer(policyHistory);
  console.log("combined E2E: cleanup web");
  if (web) await stopChild(web);
  console.log("combined E2E: cleanup postgres");
  if (postgres) await stopPostgres(postgres);
  console.log("combined E2E: cleanup remaining processes");
  for (const child of children.reverse()) await stopChild(child);
  console.log("combined E2E: cleanup files");
  await rm(temporaryRoot, { recursive: true, force: true });
  if (runtimeCleanupError) throw runtimeCleanupError;
}

async function generateHarnessGitHubAppPrivateKey(target) {
  await command("openssl", ["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", target]);
  await chmod(target, 0o600);
  await command("openssl", ["rsa", "-in", target, "-check", "-noout"]);
}

async function startPostgres(port) {
  const data = path.join(temporaryRoot, "postgres-data");
  await command(path.join(postgresBin, "initdb"), ["--no-locale", "--encoding=UTF8", "--auth-local=trust", "--auth-host=trust", "--username=zasp_e2e", "-D", data]);
  const child = startChild(path.join(postgresBin, "postgres"), ["-D", data, "-h", "127.0.0.1", "-p", String(port), "-k", ""]);
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const ready = await command(path.join(postgresBin, "pg_isready"), ["-h", "127.0.0.1", "-p", String(port), "-U", "zasp_e2e", "-d", "postgres"], { reject: false });
    if (ready.status === 0) return { child, data };
    await delay(25);
  }
  throw new Error(`disposable PostgreSQL did not become ready: ${child.output()}`);
}

async function stopPostgres(value) {
  await command(path.join(postgresBin, "pg_ctl"), ["-D", value.data, "-m", "fast", "-w", "stop"], { reject: false, timeout: 10_000 });
  await stopChild(value.child);
}

async function provisionPostgresPrincipals(dsn) {
  const sql = `
CREATE ROLE zasp_e2e_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_discovery LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_ingest LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_runtime LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_gateway LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_scheduler LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_projection_risk LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_projection_graph LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_projection_search LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_coordinator LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_archive LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_index LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_correlation LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_runtime_projection LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_gateway_control LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_security_agent_api LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_security_agent_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_security_agent_action LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_policy_deployment LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_red_team_worker LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_red_team_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_red_team_adapter LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_attack_lab_controller LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_attack_lab_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_attack_lab_proxy LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_recovery LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE zasp_e2e_recovery_outbox LOGIN INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
}

async function seedPostgres(dsn) {
  const sql = `
INSERT INTO zasp_authorized_scopes (principal_id, organization_id, workspace_id, environment_id, label, permissions, is_default) VALUES
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','Production','["view","manage_workflows","manage_findings"]'::jsonb,true),
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','Staging','["view","manage_workflows","manage_findings"]'::jsonb,false),
('pid_10000006-0000-4000-8000-000000000006','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','Webhook member production','["view"]'::jsonb,true),
('pid_90000004-0000-4000-8000-000000000004','pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','Foreign','["view","manage_identity"]'::jsonb,true);
INSERT INTO zasp_identity_memberships (principal_id, organization_id, organization_reference, member_reference, role) VALUES
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','organization-test-local','member-test-local','security_admin'),
('pid_10000005-0000-4000-8000-000000000005','pid_10000001-0000-4000-8000-000000000001','organization-test-local','member-target-local','security_engineer'),
('pid_10000006-0000-4000-8000-000000000006','pid_10000001-0000-4000-8000-000000000001','organization-test-local','member-webhook-e2e','security_engineer'),
('pid_10000007-0000-4000-8000-000000000007','pid_10000001-0000-4000-8000-000000000001','organization-test-local','member-group-e2e','read_only_viewer'),
('pid_90000004-0000-4000-8000-000000000004','pid_90000001-0000-4000-8000-000000000001','organization-foreign-e2e','member-foreign-e2e','security_admin');
INSERT INTO zasp_organizations(id,name,domain) VALUES
('pid_10000001-0000-4000-8000-000000000001','E2E Organization','e2e.invalid'),
('pid_90000001-0000-4000-8000-000000000001','Foreign E2E Organization','foreign-e2e.invalid');
INSERT INTO zasp_workspaces(id,organization_id,name) VALUES
('pid_10000002-0000-4000-8000-000000000002','pid_10000001-0000-4000-8000-000000000001','Production Workspace'),
('pid_10000022-0000-4000-8000-000000000022','pid_10000001-0000-4000-8000-000000000001','Staging Workspace'),
('pid_90000002-0000-4000-8000-000000000002','pid_90000001-0000-4000-8000-000000000001','Foreign Workspace');
INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES
('pid_10000003-0000-4000-8000-000000000003','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','Production','production'),
('pid_10000023-0000-4000-8000-000000000023','pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','Staging','staging'),
('pid_10000033-0000-4000-8000-000000000033','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','Unpermitted environment','test'),
('pid_90000003-0000-4000-8000-000000000003','pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','Foreign Production','production');
INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,migration_seeded) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','production','metadata_only',30,true,false),
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','staging','metadata_only',30,true,false),
('pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','production','metadata_only',30,true,false);
INSERT INTO zasp_compliance_controls(organization_id,id,framework,name,fresh_until) VALUES
('pid_10000001-0000-4000-8000-000000000001','access-control','SOC 2','Logical access controls',transaction_timestamp()+interval '24 hours');
INSERT INTO zasp_compliance_evidence(organization_id,control_id,id,asset_id,source,at) VALUES
('pid_10000001-0000-4000-8000-000000000001','access-control','evidence-membership','pid_10000004-0000-4000-8000-000000000004','product-membership',transaction_timestamp());
INSERT INTO zasp_product_sessions(token_digest,csrf_token,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES
(digest('target-role-session','sha256'),'target-role-csrf-with-at-least-32-bytes','session-role-change-e2e','pid_10000005-0000-4000-8000-000000000005','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view"]'::jsonb,transaction_timestamp()+interval '1 hour'),
(digest('webhook-member-session-e2e','sha256'),'webhook-member-csrf-at-least-32-bytes','session-webhook-member-e2e','pid_10000006-0000-4000-8000-000000000006','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view"]'::jsonb,transaction_timestamp()+interval '1 hour');
INSERT INTO zasp_product_api_tokens (token_digest, principal_id, organization_id, workspace_id, environment_id, permissions, expires_at) VALUES
(digest('production-e2e-product-token-with-at-least-32-bytes', 'sha256'),'pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view","manage_workflows","manage_findings","manage_identity"]'::jsonb,transaction_timestamp() + interval '1 hour'),
(digest('production-e2e-foreign-recovery-token-with-at-least-32-bytes', 'sha256'),'pid_90000004-0000-4000-8000-000000000004','pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','["view","manage_identity"]'::jsonb,transaction_timestamp() + interval '1 hour'),
(digest('webhook-member-product-token-with-at-least-32-bytes','sha256'),'pid_10000006-0000-4000-8000-000000000006','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view"]'::jsonb,transaction_timestamp()+interval '1 hour');
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state,replay_floor) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_78000001-0000-4000-8000-000000000001','Policy history E2E gateway','active',1);
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_78000002-0000-4000-8000-000000000002','pid_78000001-0000-4000-8000-000000000001','runtime-gateway-enroll',decode(repeat('31',16),'hex'),decode(repeat('32',32),'hex'),transaction_timestamp()+interval '1 hour');
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_78000003-0000-4000-8000-000000000003','pid_78000001-0000-4000-8000-000000000001','pid_78000002-0000-4000-8000-000000000002',decode(repeat('33',32),'hex'),'runtime-gateway','ref:gateway/public/policy-history-e2e',decode(repeat('34',32),'hex'),transaction_timestamp()+interval '1 hour',1,1,'gateway-policy-history-key','Ed25519',transaction_timestamp());
INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,policy_ids,occurred_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_78000001-0000-4000-8000-000000000001','pid_78000003-0000-4000-8000-000000000003','pid_78000004-0000-4000-8000-000000000004',1,decode(repeat('35',32),'hex'),1,'monitor','http',jsonb_build_object('category','policy'),'["policy-production"]'::jsonb,'2026-08-28T12:00:00Z');
INSERT INTO zasp_core_payloads (organization_id, workspace_id, environment_id, operation, payload) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','session_bootstrap:pid_10000004-0000-4000-8000-000000000004','{"principal":{"id":"pid_10000004-0000-4000-8000-000000000004","organization_id":"pid_10000001-0000-4000-8000-000000000001","organization_reference":"organization-local","member_reference":"member-local","role":"security_admin","active":true},"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","permissions":["view"],"capabilities":["inventory.read","scope.switch"],"csrf_token":"cccccccccccccccccccccccccccccccc","correlation_id":"pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}'::jsonb),
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','session_bootstrap:pid_10000004-0000-4000-8000-000000000004','{"principal":{"id":"pid_10000004-0000-4000-8000-000000000004","organization_id":"pid_10000001-0000-4000-8000-000000000001","organization_reference":"organization-local","member_reference":"member-local","role":"security_admin","active":true},"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000022-0000-4000-8000-000000000022","environment_id":"pid_10000023-0000-4000-8000-000000000023","permissions":["view"],"capabilities":["inventory.read","scope.switch"],"csrf_token":"dddddddddddddddddddddddddddddddd","correlation_id":"pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}'::jsonb);
INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,rule,title,severity,status,agent_id,path_id,created_at,updated_at)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',
  'pid_' || (30000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'), 'posture','public_input',
  'Production credential exposure ' || lpad(ordinal::text,4,'0'), CASE WHEN ordinal=1 THEN 'critical' ELSE 'high' END,'open',
  'pid_20000001-0000-4000-8000-000000000001','pid_' || (40000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),
  '2026-08-18T09:00:00Z','2026-08-18T10:00:00Z'
FROM generate_series(1,102) AS ordinal;
INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',
  'pid_' || (30000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),1,
  'pid_' || (70000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0')
FROM generate_series(1,102) AS ordinal;
INSERT INTO zasp_risk_finding_factors (organization_id,workspace_id,environment_id,finding_id,position,name,evidence_id)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',
  'pid_' || (30000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),1,'Public production input',
  'pid_' || (70000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0')
FROM generate_series(1,102) AS ordinal;
INSERT INTO zasp_risk_findings (organization_id,workspace_id,environment_id,id,source,title,severity,status,created_at,updated_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_39000001-0000-4000-8000-000000000001','prowler','Irrelevant provider row','medium','open','2026-08-18T09:00:00Z','2026-08-18T10:00:00Z'),
('pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','pid_90000007-0000-4000-8000-000000000007','posture','Foreign tenant finding','critical','open','2026-08-18T09:00:00Z','2026-08-18T10:00:00Z');
INSERT INTO zasp_risk_finding_evidence (organization_id,workspace_id,environment_id,finding_id,position,evidence_id) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_39000001-0000-4000-8000-000000000001',1,'pid_79000001-0000-4000-8000-000000000001'),
('pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','pid_90000007-0000-4000-8000-000000000007',1,'pid_90000006-0000-4000-8000-000000000006');
INSERT INTO zasp_risk_attack_paths (organization_id,workspace_id,environment_id,id,entry_id,sink_id,state,blocked_edge,created_at,updated_at)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',
  'pid_' || (40000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),
  'pid_' || (50000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),
  'pid_' || (60000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),
  'verified',-1,'2026-08-18T09:00:00Z','2026-08-18T10:00:00Z'
FROM generate_series(1,102) AS ordinal;
INSERT INTO zasp_risk_attack_path_nodes (organization_id,workspace_id,environment_id,path_id,position,node_id)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',
  'pid_' || (40000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'), position,
  'pid_' || ((CASE position WHEN 1 THEN 50000000 ELSE 60000000 END)+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0')
FROM generate_series(1,102) AS ordinal CROSS JOIN generate_series(1,2) AS position;
INSERT INTO zasp_risk_attack_path_evidence (organization_id,workspace_id,environment_id,path_id,position,evidence_id)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',
  'pid_' || (40000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),1,
  'pid_' || (70000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0')
FROM generate_series(1,102) AS ordinal;
INSERT INTO zasp_risk_break_options (organization_id,workspace_id,environment_id,path_id,rank,target_id,evidence_id,kind)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',
  'pid_' || (40000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),1,
  'pid_' || (50000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),
  'pid_' || (70000000+ordinal)::text || '-0000-4000-8000-' || lpad(ordinal::text,12,'0'),'remove_node'
FROM generate_series(1,102) AS ordinal;
INSERT INTO zasp_risk_attack_paths (organization_id,workspace_id,environment_id,id,entry_id,sink_id,state,blocked_edge,created_at,updated_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','pid_80000001-0000-4000-8000-000000000001','pid_80000002-0000-4000-8000-000000000002','pid_80000003-0000-4000-8000-000000000003','observed',-1,'2026-08-18T09:00:00Z','2026-08-18T10:00:00Z');
INSERT INTO zasp_risk_attack_path_nodes (organization_id,workspace_id,environment_id,path_id,position,node_id) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','pid_80000001-0000-4000-8000-000000000001',1,'pid_80000002-0000-4000-8000-000000000002'),
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','pid_80000001-0000-4000-8000-000000000001',2,'pid_80000003-0000-4000-8000-000000000003');
INSERT INTO zasp_risk_attack_path_evidence (organization_id,workspace_id,environment_id,path_id,position,evidence_id) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','pid_80000001-0000-4000-8000-000000000001',1,'pid_80000004-0000-4000-8000-000000000004');
INSERT INTO zasp_workflow_records (organization_id, workspace_id, environment_id, kind, id, body)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','policy',
  'policy-page-' || lpad(ordinal::text, 4, '0'),
  jsonb_build_object('id', 'policy-page-' || lpad(ordinal::text, 4, '0'), 'name', 'Paged policy ' || lpad(ordinal::text, 4, '0'), 'scope', 'environment', 'trigger', 'tool', 'conditions', jsonb_build_array(jsonb_build_object('field', 'action', 'operator', 'equals', 'value', 'read')), 'action', 'monitor', 'rollout', 'draft', 'failure_mode', 'open')
FROM generate_series(1, 1000) AS ordinal;
INSERT INTO zasp_workflow_records (organization_id, workspace_id, environment_id, kind, id, body)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','integration',
  'pid_' || lpad(ordinal::text, 8, '0') || '-0000-4000-8000-' || lpad(ordinal::text, 12, '0'),
  jsonb_build_object('id', 'pid_' || lpad(ordinal::text, 8, '0') || '-0000-4000-8000-' || lpad(ordinal::text, 12, '0'), 'connector_key', 'generic-webhook', 'name', 'Paged integration ' || lpad(ordinal::text, 4, '0'), 'configuration', jsonb_build_object('destination_url', 'https://paged.invalid/' || ordinal, 'signing_secret_reference', 'secret_ref_paged_' || ordinal), 'status', 'configured', 'created_at', '2026-08-18T10:00:00Z', 'updated_at', '2026-08-18T10:00:00Z')
FROM generate_series(1, 1001) AS ordinal;
INSERT INTO zasp_workflow_records (organization_id,workspace_id,environment_id,kind,id,body) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','integration','${terminalRevocationIntegrationID}',jsonb_build_object('id','${terminalRevocationIntegrationID}','connector_key','github','name','Harness terminal revocation','configuration',jsonb_build_object('authorization_mode','github_app'),'status','configured','created_at','2026-08-18T10:00:00Z','updated_at','2026-08-18T10:00:00Z')),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','integration','${reloadRevocationIntegrationID}',jsonb_build_object('id','${reloadRevocationIntegrationID}','connector_key','github','name','Harness reload revocation','configuration',jsonb_build_object('authorization_mode','github_app'),'status','configured','created_at','2026-08-18T10:00:00Z','updated_at','2026-08-18T10:00:00Z'));
INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${terminalRevocationIntegrationID}','github','1.0.0','Harness terminal revocation','{"authorization_mode":"github_app"}'::jsonb,'active'),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${reloadRevocationIntegrationID}','github','1.0.0','Harness reload revocation','{"authorization_mode":"github_app"}'::jsonb,'active');
INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${terminalRevocationIntegrationID}','pid_72000011-0000-4000-8000-000000000011','github','ref:github/harness-terminal-revocation','verified',transaction_timestamp()),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${reloadRevocationIntegrationID}','pid_72000012-0000-4000-8000-000000000012','github','ref:github/harness-reload-revocation','verified',transaction_timestamp());
INSERT INTO zasp_workflow_records (organization_id,workspace_id,environment_id,kind,id,body) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','integration','${task4DiscoveryIntegrationID}','{"id":"${task4DiscoveryIntegrationID}","connector_key":"aws","name":"Harness AWS discovery","configuration":{"external_id_reference":"ref:aws/external-id/production-e2e","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"},"status":"active","created_at":"2026-08-19T00:00:00Z","updated_at":"2026-08-19T00:00:00Z"}'::jsonb);
INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task4DiscoveryIntegrationID}','aws','1.0.0','Harness AWS discovery','{"external_id_reference":"ref:aws/external-id/production-e2e","region":"us-east-1","role_arn":"arn:aws:iam::123456789012:role/zasp-discovery"}'::jsonb,'active');
INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task4DiscoveryIntegrationID}','pid_73000002-0000-4000-8000-000000000002','aws','ref:aws/external-id/production-e2e','verified',transaction_timestamp());
INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
SELECT organization_id,workspace_id,environment_id,id,'pid_73000002-0000-4000-8000-000000000002','aws','aws_account','123456789012',1,digest(convert_to(configuration::text,'UTF8'),'sha256'),'reference'
FROM zasp_integrations WHERE id='${task4DiscoveryIntegrationID}';
INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesAIntegrationID}','kubernetes','1.0.0','Harness Kubernetes source A','{"cluster":"prod.example/cluster-a"}'::jsonb,'active'),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesBIntegrationID}','kubernetes','1.0.0','Harness Kubernetes source B','{"cluster":"prod.example/cluster-a"}'::jsonb,'active'),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesPartialIntegrationID}','kubernetes','1.0.0','Harness Kubernetes partial','{"cluster":"prod.example/cluster-partial"}'::jsonb,'active'),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesFailedIntegrationID}','kubernetes','1.0.0','Harness Kubernetes failed','{"cluster":"prod.example/cluster-failed"}'::jsonb,'active'),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5GitHubIntegrationID}','github','1.0.0','Harness GitHub inventory','{"installation_id":"424242"}'::jsonb,'active'),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5OktaIntegrationID}','okta','1.0.0','Harness Okta inventory','{"tenant":"e2e.okta.com"}'::jsonb,'active');
INSERT INTO zasp_integration_connections(organization_id,workspace_id,environment_id,integration_id,id,provider,connection_reference,state,verified_at) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesAIntegrationID}','pid_74000011-0000-4000-8000-000000000011','kubernetes','ref:kubernetes/cluster/e2e-a','verified',transaction_timestamp()),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesBIntegrationID}','pid_74000012-0000-4000-8000-000000000012','kubernetes','ref:kubernetes/cluster/e2e-b','verified',transaction_timestamp()),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesPartialIntegrationID}','pid_74000013-0000-4000-8000-000000000013','kubernetes','ref:kubernetes/cluster/e2e-partial','verified',transaction_timestamp()),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5KubernetesFailedIntegrationID}','pid_74000014-0000-4000-8000-000000000014','kubernetes','ref:kubernetes/cluster/e2e-failed','verified',transaction_timestamp()),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5GitHubIntegrationID}','pid_75000011-0000-4000-8000-000000000011','github','ref:github/installation/424242','verified',transaction_timestamp()),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5OktaIntegrationID}','pid_76000011-0000-4000-8000-000000000011','okta','ref:okta/refresh/e2e-tenant','verified',transaction_timestamp());
INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
SELECT organization_id,workspace_id,environment_id,id,
 CASE id WHEN '${task5KubernetesAIntegrationID}' THEN 'pid_74000011-0000-4000-8000-000000000011' WHEN '${task5KubernetesBIntegrationID}' THEN 'pid_74000012-0000-4000-8000-000000000012' WHEN '${task5KubernetesPartialIntegrationID}' THEN 'pid_74000013-0000-4000-8000-000000000013' ELSE 'pid_74000014-0000-4000-8000-000000000014' END,
 'kubernetes','kubernetes_cluster',CASE id WHEN '${task5KubernetesAIntegrationID}' THEN 'prod.example/cluster-a' WHEN '${task5KubernetesBIntegrationID}' THEN 'prod.example/cluster-a' WHEN '${task5KubernetesPartialIntegrationID}' THEN 'prod.example/cluster-partial' ELSE 'prod.example/cluster-failed' END,1,digest(convert_to(configuration::text,'UTF8'),'sha256'),'reference'
FROM zasp_integrations WHERE id IN('${task5KubernetesAIntegrationID}','${task5KubernetesBIntegrationID}','${task5KubernetesPartialIntegrationID}','${task5KubernetesFailedIntegrationID}');
INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_75000021-0000-4000-8000-000000000021','${task5GitHubIntegrationID}','github','github_installation_reference','ref:github/installation/424242',1,'{"installation_id":"424242","account_type":"Organization","account_login":"zasp","repository_selection":"selected","permissions":{"actions":"read","contents":"read","metadata":"read"}}'::jsonb),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_76000021-0000-4000-8000-000000000021','${task5OktaIntegrationID}','okta','okta_refresh_reference','ref:okta/refresh/e2e-tenant',1,'{"tenant":"e2e.okta.com","scopes":["offline_access","okta.apps.read","okta.groups.read","okta.users.read"]}'::jsonb);
SELECT zasp_inventory_backfill_scope('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003');
SELECT zasp_inventory_cutover_scope('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003');
SELECT zasp_inventory_backfill_scope('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023');
SELECT zasp_inventory_cutover_scope('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023');
`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
}

async function exercisePublicDiscoveryLifecycle(publicOrigin, dsn, authorization) {
  const syncOperation = "/api/v1/integrations/{id}/sync";
  const syncHistoryOperation = "/api/v1/integrations/{id}/syncs";
  const syncDetailOperation = "/api/v1/integrations/{id}/syncs/{syncId}";
  const scheduleOperation = "/api/v1/integrations/{id}/schedule";
  const freshnessOperation = "/api/v1/integrations/{id}/freshness";
  const integrationPath = (operation) => operation.replace("{id}", task4DiscoveryIntegrationID);
  const mutationHeaders = (idempotencyKey, version) => ({
    authorization,
    "content-type": "application/json",
    "idempotency-key": idempotencyKey,
    "if-match": `"${version}"`,
  });

  const syncHeaders = mutationHeaders("production-e2e-manual-sync-0001", 1);
  const syncAccepted = await requestHTTPSJSON(`${publicOrigin}${integrationPath(syncOperation)}`, { method: "POST", headers: syncHeaders }, "{}");
  const syncReplayed = await requestHTTPSJSON(`${publicOrigin}${integrationPath(syncOperation)}`, { method: "POST", headers: syncHeaders }, "{}");
  assertTask4PublicResponse(syncAccepted, 202, "manual sync");
  assertTask4PublicResponse(syncReplayed, 202, "manual sync replay");
  assert.deepEqual(syncReplayed.body, syncAccepted.body, "manual sync replay changed the canonical body");
  assert.equal(syncReplayed.headers.etag, syncAccepted.headers.etag, "manual sync replay changed ETag");
  assert.equal(syncReplayed.headers["x-audit-id"], syncAccepted.headers["x-audit-id"], "manual sync replay changed audit identity");
  assert.equal(syncAccepted.headers["x-mutation-receipt-id"], undefined, "PAT manual sync created a browser receipt");
  assert.equal(syncAccepted.headers.etag, '"1"');
  assert.equal(syncAccepted.body.integration_id, task4DiscoveryIntegrationID);
  assert.equal(syncAccepted.body.trigger_kind, "manual");
  assert.equal(syncAccepted.body.status, "queued");
  assert.equal(syncAccepted.body.attempt, 0);
  assert.equal(syncAccepted.body.snapshot_id, null);
  console.log("combined E2E: real public manual sync returned 202 and exact replay without a browser receipt");

  const scheduleHeaders = mutationHeaders("production-e2e-schedule-put-0001", 0);
  const scheduleBody = JSON.stringify({ cadence_seconds: 3600, state: "enabled" });
  const scheduleSaved = await requestHTTPSJSON(`${publicOrigin}${integrationPath(scheduleOperation)}`, { method: "PUT", headers: scheduleHeaders }, scheduleBody);
  const scheduleReplayed = await requestHTTPSJSON(`${publicOrigin}${integrationPath(scheduleOperation)}`, { method: "PUT", headers: scheduleHeaders }, scheduleBody);
  assertTask4PublicResponse(scheduleSaved, 200, "schedule create");
  assertTask4PublicResponse(scheduleReplayed, 200, "schedule replay");
  assert.deepEqual(scheduleReplayed.body, scheduleSaved.body, "schedule replay changed the canonical body");
  assert.equal(scheduleSaved.headers.etag, '"1"');
  assert.equal(scheduleSaved.headers["x-mutation-receipt-id"], undefined, "PAT schedule create created a browser receipt");
  assert.equal(scheduleSaved.body.integration_id, task4DiscoveryIntegrationID);
  assert.equal(scheduleSaved.body.cadence_seconds, 3600);
  assert.equal(scheduleSaved.body.state, "enabled");
  assert.equal(scheduleSaved.body.time_zone, "UTC");

  const readHeaders = { authorization };
  const scheduleRead = await requestHTTPSJSON(`${publicOrigin}${integrationPath(scheduleOperation)}`, { method: "GET", headers: readHeaders });
  assertTask4PublicResponse(scheduleRead, 200, "schedule read");
  assert.deepEqual(scheduleRead.body, scheduleSaved.body, "schedule read disagreed with the accepted mutation");
  assert.equal(scheduleRead.headers.etag, '"1"');

  const history = await requestHTTPSJSON(`${publicOrigin}${integrationPath(syncHistoryOperation)}?limit=100`, { method: "GET", headers: readHeaders });
  assertTask4PublicResponse(history, 200, "sync history");
  assert.equal(history.body.items.length, 1);
  assert.deepEqual(history.body.items[0], syncAccepted.body);
  assert.deepEqual(history.body.page_info, { has_more: false, next_cursor: null });
  const syncDetailPath = integrationPath(syncDetailOperation).replace("{syncId}", syncAccepted.body.id);
  const detail = await requestHTTPSJSON(`${publicOrigin}${syncDetailPath}`, { method: "GET", headers: readHeaders });
  assertTask4PublicResponse(detail, 200, "sync detail");
  assert.deepEqual(detail.body, syncAccepted.body);
  assert.equal(detail.headers.etag, '"1"');

  const freshness = await requestHTTPSJSON(`${publicOrigin}${integrationPath(freshnessOperation)}`, { method: "GET", headers: readHeaders });
  assertTask4PublicResponse(freshness, 200, "discovery freshness");
  assert.equal(freshness.body.integration_id, task4DiscoveryIntegrationID);
  assert.equal(freshness.body.last_good, null);
  assert.deepEqual(freshness.body.latest_sync, syncAccepted.body);
  for (const kind of ["risk", "graph", "search"]) {
    assert.deepEqual(freshness.body.projections[kind], { state: "unavailable", snapshot_id: null, completed_at: null, last_error_code: null });
  }
  console.log("combined E2E: public sync history/detail/freshness proven with independent unavailable projection truth");

  const deleteHeaders = mutationHeaders("production-e2e-schedule-delete-0001", 1);
  const scheduleDeleted = await requestHTTPSJSON(`${publicOrigin}${integrationPath(scheduleOperation)}`, { method: "DELETE", headers: deleteHeaders });
  const deleteReplayed = await requestHTTPSJSON(`${publicOrigin}${integrationPath(scheduleOperation)}`, { method: "DELETE", headers: deleteHeaders });
  assertTask4PublicResponse(scheduleDeleted, 204, "schedule delete");
  assertTask4PublicResponse(deleteReplayed, 204, "schedule delete replay");
  assert.equal(scheduleDeleted.body, null);
  assert.equal(deleteReplayed.body, null);
  assert.equal(scheduleDeleted.headers.etag, '"2"');
  assert.equal(scheduleDeleted.headers["x-mutation-receipt-id"], undefined, "PAT schedule delete created a browser receipt");
  const scheduleMissing = await requestHTTPSJSON(`${publicOrigin}${integrationPath(scheduleOperation)}`, { method: "GET", headers: readHeaders });
  assertTask4PublicResponse(scheduleMissing, 404, "deleted schedule read");
  assert.equal(scheduleMissing.body.code, "not_found");
  console.log("combined E2E: public schedule create/read/delete proven with exact idempotent replay");

  const durable = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation='syncIntegration' AND idempotency_key='production-e2e-manual-sync-0001'),
    (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation='putIntegrationSchedule' AND idempotency_key='production-e2e-schedule-put-0001'),
    (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation='deleteIntegrationSchedule' AND idempotency_key='production-e2e-schedule-delete-0001'),
    (SELECT count(*) FROM zasp_workflow_receipts WHERE operation IN('syncIntegration','putIntegrationSchedule','deleteIntegrationSchedule')),
    (SELECT state FROM zasp_discovery_syncs WHERE integration_id='${task4DiscoveryIntegrationID}'),
    (SELECT CASE WHEN snapshot_id IS NULL THEN 0 ELSE 1 END FROM zasp_discovery_syncs WHERE integration_id='${task4DiscoveryIntegrationID}')
  );`]);
  assert.equal(durable.stdout.trim(), "1|1|1|0|queued|0", "Task4 public replay or no-completion boundary drifted");
  console.log("combined E2E: zero fake collection/projection database completion; queued public work awaits real workers");
  return { integrationID: task4DiscoveryIntegrationID, syncID: syncAccepted.body.id };
}

async function exerciseTypedInventoryDiscoveryLifecycle(publicOrigin, dsn, postgresPort, workerE2EBinary, authorization, task4Public) {
  await runDeterministicLocalDiscovery(workerE2EBinary, postgresPort, dsn, task4Public.syncID, "complete");
  const completed = [];
  for (const [integrationID, suffix, scenario] of [
    [task5KubernetesAIntegrationID, "kubernetes-a", "complete"],
    [task5KubernetesBIntegrationID, "kubernetes-b", "shared"],
    [task5GitHubIntegrationID, "github", "complete"],
    [task5OktaIntegrationID, "okta", "complete"],
  ]) {
    const sync = await requestManualDiscoverySync(publicOrigin, authorization, integrationID, `production-e2e-typed-${suffix}-0001`);
    await runDeterministicLocalDiscovery(workerE2EBinary, postgresPort, dsn, sync.id, scenario);
    completed.push(sync);
  }

	const headers = { authorization };
	await assertIntegrationSetupStatus(publicOrigin, headers, task4DiscoveryIntegrationID, {
		connector_key: "aws",
		authorization: { state: "verified", scope_kind: "aws_account", scope_label: "123456789012", repository_selection: null, permissions: [] },
		runtime_coverage: { state: "not_applicable", reason: "not_applicable", sensor_count: 0, healthy_sensor_count: 0 },
	});
	await assertIntegrationSetupStatus(publicOrigin, headers, task5KubernetesAIntegrationID, {
		connector_key: "kubernetes",
		authorization: { state: "verified", scope_kind: "kubernetes_cluster", scope_label: "prod.example/cluster-a", repository_selection: null, permissions: [] },
		runtime_coverage: { state: "not_enrolled", reason: "not_enrolled", sensor_count: 0, healthy_sensor_count: 0 },
	});
	await assertIntegrationSetupStatus(publicOrigin, headers, task5GitHubIntegrationID, {
		connector_key: "github",
		authorization: { state: "verified", scope_kind: "github_organization", scope_label: "zasp", repository_selection: "selected", permissions: ["actions:read", "contents:read", "metadata:read"] },
		runtime_coverage: { state: "not_applicable", reason: "not_applicable", sensor_count: 0, healthy_sensor_count: 0 },
	});
	await assertIntegrationSetupStatus(publicOrigin, headers, task5OktaIntegrationID, {
		connector_key: "okta",
		authorization: { state: "verified", scope_kind: "okta_tenant", scope_label: "e2e.okta.com", repository_selection: null, permissions: ["offline_access", "okta.apps.read", "okta.groups.read", "okta.users.read"] },
		runtime_coverage: { state: "not_applicable", reason: "not_applicable", sensor_count: 0, healthy_sensor_count: 0 },
	});
	console.log("combined E2E: multi-tenant AWS, Kubernetes, GitHub, and Okta setup scope remained exact and credential-redacted");
	const typedState = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
		(SELECT count(*) FROM zasp_inventory_entities WHERE state='active' AND product_kind='agent'),
		(SELECT count(*) FROM zasp_inventory_entities WHERE state='active'),
		(SELECT count(*) FROM zasp_inventory_source_observations WHERE source_state='present'),
		(SELECT string_agg(concat_ws(':',id,state,COALESCE(product_kind,'null')),',' ORDER BY id) FROM zasp_inventory_entities),
		(SELECT string_agg(concat_ws(':',input.integration_id,input.source,jsonb_array_length(input.entities),jsonb_array_length(input.evidence)),',' ORDER BY input.integration_id) FROM zasp_discovery_snapshot_inputs input JOIN zasp_discovery_snapshots snapshot ON (snapshot.organization_id,snapshot.workspace_id,snapshot.environment_id,snapshot.integration_id,snapshot.id)=(input.organization_id,input.workspace_id,input.environment_id,input.integration_id,input.snapshot_id) WHERE snapshot.is_last_good),
		(SELECT string_agg(concat_ws(':',integration_id,state,COALESCE(last_error_code,'none')),',' ORDER BY integration_id) FROM zasp_discovery_syncs WHERE integration_id=ANY(ARRAY[${[task4DiscoveryIntegrationID, task5KubernetesAIntegrationID, task5KubernetesBIntegrationID, task5GitHubIntegrationID, task5OktaIntegrationID].map((value) => `'${value}'`).join(",")}]))
	);`]);
	const home = await requestHTTPSJSON(`${publicOrigin}/api/v1/home/summary`, { method: "GET", headers });
	assert.equal(home.status, 200, `typed inventory home failed: ${JSON.stringify(home)}`);
	assert.equal(home.body.agent_count, 1, `typed home disagreed with current inventory: ${typedState.stdout.trim()}`);
  const agents = await assertTypedInventoryPage(publicOrigin, headers, "/api/v1/agents", [["Support agent", "agent"]]);
  await assertTypedInventoryPage(publicOrigin, headers, "/api/v1/tools", [["Automation repository", "tool"]]);
  await assertTypedInventoryPage(publicOrigin, headers, "/api/v1/identities", [["Support agent identity", "identity"], ["Security operators", "identity"]]);
  await assertTypedInventoryPage(publicOrigin, headers, "/api/v1/runtimes", [["Production runtime", "runtime"]]);
  assert.equal(agents[0].id, "pid_21000001-0000-4000-8000-000000000001");

  const agentDetail = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents/pid_21000001-0000-4000-8000-000000000001`, { method: "GET", headers });
  assert.equal(agentDetail.status, 200, `typed agent detail failed: ${JSON.stringify(agentDetail)}`);
  assert.equal(agentDetail.body.summary.name, "Support agent");
  assert.equal(agentDetail.body.sources.length, 2);
  assert.equal(agentDetail.body.evidence.length, 2);
  assert.equal(agentDetail.body.sources.filter((source) => source.winning).length, 1);
  assert.equal(agentDetail.body.sources.every((source) => source.provider === "kubernetes" && /^sha256:[0-9a-f]{64}$/.test(source.source_identifier)), true);
  assert.equal(agentDetail.body.evidence.every((evidence) => /^sha256:[0-9a-f]{64}$/.test(evidence.checksum) && evidence.parser_version === "inventory-parser-2026.08.20" && evidence.tool_version === "collector-tool-2026.08.20"), true);

  const relationships = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents/pid_21000001-0000-4000-8000-000000000001/relationships?limit=100`, { method: "GET", headers });
  assert.equal(relationships.status, 200, `typed relationship page failed: ${JSON.stringify(relationships)}`);
  assert.deepEqual(relationships.body.page_info, { has_more: false, next_cursor: null });
  assert.equal(relationships.body.items.length, 1);
  assert.equal(relationships.body.items[0].to_id, "pid_21000004-0000-4000-8000-000000000004");

  const completedSync = await requestHTTPSJSON(`${publicOrigin}/api/v1/integrations/${task4DiscoveryIntegrationID}/syncs/${task4Public.syncID}`, { method: "GET", headers });
  assert.equal(completedSync.status, 200);
  assert.equal(completedSync.body.status, "succeeded");
  assert.equal(completedSync.body.discovered_count, 1);
  const freshness = await requestHTTPSJSON(`${publicOrigin}/api/v1/integrations/${task4DiscoveryIntegrationID}/freshness`, { method: "GET", headers });
  assert.equal(freshness.status, 200);
  assert.equal(freshness.body.last_good.discovered_count, 1);
  assert.deepEqual(Object.values(freshness.body.projections).map((projection) => projection.state), ["pending", "pending", "pending"]);

  const forensics = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT count(*) FROM zasp_core_payloads WHERE operation IN('home','agents','tools','identities','runtimes') OR operation ~ '^(agent|tool|identity|runtime|asset):'),
    (SELECT count(*) FROM zasp_inventory_entities WHERE state='active' AND product_kind='agent'),
    (SELECT count(*) FROM zasp_inventory_entities WHERE state='active' AND product_kind='tool'),
    (SELECT count(*) FROM zasp_inventory_entities WHERE state='active' AND product_kind='identity'),
    (SELECT count(*) FROM zasp_inventory_entities WHERE state='active' AND product_kind='runtime'),
    (SELECT count(*) FROM zasp_inventory_entities WHERE state='active' AND product_kind='asset'),
    (SELECT count(*) FROM zasp_discovery_snapshots WHERE state='complete' AND is_last_good AND integration_id IN('${task4DiscoveryIntegrationID}','${task5KubernetesAIntegrationID}','${task5KubernetesBIntegrationID}','${task5GitHubIntegrationID}','${task5OktaIntegrationID}')),
    (SELECT count(*) FROM zasp_inventory_source_observations WHERE source_state='present'),
    (SELECT count(*) FROM zasp_inventory_evidence evidence JOIN zasp_inventory_source_observations observation ON (observation.organization_id,observation.workspace_id,observation.environment_id,observation.integration_id,observation.snapshot_id,observation.entity_id,observation.evidence_id)=(evidence.organization_id,evidence.workspace_id,evidence.environment_id,evidence.integration_id,evidence.snapshot_id,evidence.entity_id,evidence.id) WHERE observation.source_state='present'),
    (SELECT count(*) FROM zasp_inventory_relationships WHERE state='present')
  );`]);
  assert.equal(forensics.stdout.trim(), "0|1|1|2|1|1|5|7|7|1", "typed inventory authority was not derived from exact complete snapshots");
  assert.equal(completed.length, 4);
  console.log("combined E2E: typed inventory public routes derive only from complete discovery snapshots");
  console.log("combined E2E: typed inventory database forensics proved exact current source/snapshot/evidence bindings");
}

async function assertIntegrationSetupStatus(publicOrigin, headers, integrationID, expected) {
	const response = await requestHTTPSJSON(`${publicOrigin}/api/v1/integrations/${integrationID}/setup-status`, { method: "GET", headers });
	assert.equal(response.status, 200, `integration setup status failed for ${integrationID}: ${JSON.stringify(response)}`);
	assert.equal(response.headers["cache-control"], "no-store", "integration setup status was cacheable");
	assert.equal(response.headers.etag, undefined, "integration setup status exposed an unstable ETag");
	const { integration_id: returnedID, updated_at: updatedAt, ...body } = response.body;
	assert.equal(returnedID, integrationID, "integration setup status changed integration identity");
	assert.match(updatedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/, "integration setup status timestamp was not canonical UTC");
	assert.deepEqual(body, expected, "integration setup status disagreed with exact provider authority");
	assert.doesNotMatch(JSON.stringify(response.body), /credential_reference|installation_id|refresh_token|client_secret|ref:(?:aws|kubernetes|github|okta)\//i, "integration setup status leaked provider authority");
}

async function exerciseTypedInventoryRetention(publicOrigin, dsn, postgresPort, workerE2EBinary, authorization) {
  const headers = { authorization };
  const sourceAEmpty = await requestManualDiscoverySync(publicOrigin, authorization, task5KubernetesAIntegrationID, "production-e2e-typed-kubernetes-a-empty");
  await runDeterministicLocalDiscovery(workerE2EBinary, postgresPort, dsn, sourceAEmpty.id, "empty");
  let agents = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents?limit=100`, { method: "GET", headers });
  assert.equal(agents.status, 200);
  assert.equal(agents.body.items.length, 1);
  const retained = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT count(*) FROM zasp_inventory_source_observations WHERE entity_id='pid_21000001-0000-4000-8000-000000000001' AND source_state='present'),
    (SELECT state FROM zasp_inventory_entities WHERE id='pid_21000001-0000-4000-8000-000000000001'),
    (SELECT count(*) FROM zasp_inventory_relationships WHERE state='present')
  );`]);
  assert.equal(retained.stdout.trim(), "1|active|0", "complete-empty source A removed source B authority");
  console.log("combined E2E: second-source retention proven after complete-empty source A");

  const partial = await requestManualDiscoverySync(publicOrigin, authorization, task5KubernetesPartialIntegrationID, "production-e2e-typed-kubernetes-partial");
  await runDeterministicLocalDiscovery(workerE2EBinary, postgresPort, dsn, partial.id, "partial");
  const failed = await requestManualDiscoverySync(publicOrigin, authorization, task5KubernetesFailedIntegrationID, "production-e2e-typed-kubernetes-failed");
  await runDeterministicLocalDiscovery(workerE2EBinary, postgresPort, dsn, failed.id, "failed");
  agents = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents?limit=100`, { method: "GET", headers });
  assert.equal(agents.status, 200);
  assert.equal(agents.body.items.length, 1);
  const retainedAfterFailure = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT state FROM zasp_discovery_syncs WHERE id='${partial.id}'),
    (SELECT last_error_code FROM zasp_discovery_syncs WHERE id='${partial.id}'),
    (SELECT state FROM zasp_discovery_syncs WHERE id='${failed.id}'),
    (SELECT last_error_code FROM zasp_discovery_syncs WHERE id='${failed.id}'),
    (SELECT count(*) FROM zasp_inventory_source_observations WHERE entity_id='pid_21000001-0000-4000-8000-000000000001' AND source_state='present')
  );`]);
  assert.equal(retainedAfterFailure.stdout.trim(), "queued|partial|failed|malformed|1", "failed or partial collection changed last complete inventory");
  console.log("combined E2E: failed and partial discovery retained the last complete inventory");

  const sourceBEmpty = await requestManualDiscoverySync(publicOrigin, authorization, task5KubernetesBIntegrationID, "production-e2e-typed-kubernetes-b-empty");
  await runDeterministicLocalDiscovery(workerE2EBinary, postgresPort, dsn, sourceBEmpty.id, "empty");
  agents = await requestHTTPSJSON(`${publicOrigin}/api/v1/agents?limit=100`, { method: "GET", headers });
  assert.equal(agents.status, 200);
  assert.deepEqual(agents.body, { items: [], page_info: { has_more: false, next_cursor: null } });
  const removed = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT state FROM zasp_inventory_entities WHERE id='pid_21000001-0000-4000-8000-000000000001'),
    (SELECT count(*) FROM zasp_inventory_source_observations WHERE entity_id='pid_21000001-0000-4000-8000-000000000001' AND source_state='present')
  );`]);
  assert.equal(removed.stdout.trim(), "tombstoned|0", "complete-empty source removal left active authority");
  console.log("combined E2E: complete-empty source removal proven after the final authoritative source disappeared");
}

async function requestManualDiscoverySync(publicOrigin, authorization, integrationID, idempotencyKey) {
  const response = await requestHTTPSJSON(`${publicOrigin}/api/v1/integrations/${integrationID}/sync`, {
    method: "POST",
    headers: { authorization, "content-type": "application/json", "idempotency-key": idempotencyKey, "if-match": '"1"' },
  }, "{}");
  assertTask4PublicResponse(response, 202, `typed inventory sync ${integrationID}`);
  assert.equal(response.body.integration_id, integrationID);
  assert.equal(response.body.status, "queued");
  return response.body;
}

async function runDeterministicLocalDiscovery(workerE2EBinary, postgresPort, dsn, syncID, scenario) {
  const job = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT job.id FROM zasp_discovery_jobs job JOIN zasp_discovery_syncs sync ON (sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)=(job.organization_id,job.workspace_id,job.environment_id,job.authority_id) WHERE sync.id='${syncID}' AND job.kind='discovery';`]);
  const jobID = job.stdout.trim();
  assert.match(jobID, /^pid_[0-9a-f-]{36}$/, `missing deterministic worker job for ${syncID}`);
  const result = await command(workerE2EBinary, ["-test.run=^TestProductionCombinedE2EDiscoveryWorker$", "-test.v", "-test.count=1"], {
    cwd: platform,
    timeout: 60_000,
    env: {
      ...process.env,
      ZASP_COMBINED_E2E_WORKER_DSN: `postgres://zasp_e2e_discovery@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
      ZASP_COMBINED_E2E_JOB_ID: jobID,
      ZASP_COMBINED_E2E_SCENARIO: scenario,
      ZASP_COMBINED_E2E_PARSER_VERSION: "inventory-parser-2026.08.20",
      ZASP_COMBINED_E2E_TOOL_VERSION: "collector-tool-2026.08.20",
    },
  });
  assert.match(result.stdout, /deterministic local provider and artifact authority completed public sync/);
  console.log(`combined E2E: deterministic local provider and artifact authority completed public sync (${scenario})`);
}

async function assertTypedInventoryPage(publicOrigin, headers, pathValue, expectedItems) {
  const response = await requestHTTPSJSON(`${publicOrigin}${pathValue}?limit=100`, { method: "GET", headers });
  assert.equal(response.status, 200, `typed inventory page failed: ${pathValue} ${JSON.stringify(response)}`);
  assert.deepEqual(response.body.page_info, { has_more: false, next_cursor: null });
  assert.deepEqual(response.body.items.map((item) => [item.name, item.kind]), expectedItems);
  assert.equal(response.body.items.every((item) => /^pid_[0-9a-f-]{36}$/.test(item.evidence_id)), true);
  return response.body.items;
}

async function exerciseTask4ProductionWorkerBoundaries(workerBinary, postgresPort, dsn) {
  await assertPortAvailable(8081);
  const workerEnvironment = (mode, principal, authority) => ({
    ...process.env,
    ZASP_WORKER_MODE: mode,
    ZASP_POSTGRES_DSN: `postgres://zasp_e2e_${principal}@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
    ZASP_DATABASE_AUTHORITY: authority,
    ZASP_WORKER_ID: `production-e2e-${mode}`,
    ZASP_POLL_INTERVAL: "100ms",
    ZASP_LEASE_DURATION: "5s",
    ZASP_BATCH_SIZE: "1",
    ZASP_SHUTDOWN_TIMEOUT: "1s",
  });

  const scheduler = startTask4Worker(workerBinary, {
    ...workerEnvironment("scheduler", "scheduler", "zasp_discovery_scheduler"),
    ZASP_DISCOVERY_PARSER_VERSION: "parser_v1",
    ZASP_DISCOVERY_TOOL_VERSION: "tool_v1",
  });
  await assertReadyTask4Worker(scheduler, "scheduler");
  await stopChild(scheduler);

  const risk = startTask4Worker(workerBinary, workerEnvironment("projection-risk", "projection_risk", "zasp_projection_risk_worker"));
  await assertReadyTask4Worker(risk, "projection-risk");
  await stopChild(risk);

  const managedEnvironment = {
    ZASP_AWS_REGION: "us-east-1",
    ZASP_DISCOVERY_QUEUE_URL: "https://sqs.us-east-1.amazonaws.com/123456789012/agentsec-discovery-jobs",
    ZASP_DISCOVERY_ROLE_ARN: "arn:aws:iam::123456789012:role/zasp-production-e2e-discovery",
    ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    ZASP_DISCOVERY_SECRET_PREFIX: "zasp-production-e2e/connectors",
    ZASP_EVIDENCE_BUCKET: "zasp-production-e2e-evidence",
    ZASP_EVIDENCE_BUCKET_OWNER: "123456789012",
    ZASP_EVIDENCE_KMS_KEY_ARN: "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
    ZASP_DISCOVERY_AWS_COLLECTOR_VERSION: "aws_v1",
    ZASP_DISCOVERY_KUBERNETES_COLLECTOR_VERSION: "kubernetes_v1",
    ZASP_DISCOVERY_GITHUB_COLLECTOR_VERSION: "github_v1",
    ZASP_DISCOVERY_OKTA_COLLECTOR_VERSION: "okta_v1",
    ZASP_DISCOVERY_PARSER_VERSION: "parser_v1",
    ZASP_DISCOVERY_TOOL_VERSION: "tool_v1",
    ZASP_KUBERNETES_EGRESS_CIDRS: "10.0.0.0/8",
    ZASP_GITHUB_APP_ID: "123456",
    ZASP_GITHUB_PRIVATE_KEY_REFERENCE: "ref:github/app-private-key",
    ZASP_OKTA_CLIENT_ID: "0oa1234567890abcdef",
    ZASP_OKTA_CLIENT_SECRET_REFERENCE: "ref:okta/client-secret",
    ZASP_PROVIDER_TIMEOUT: "1s",
    ZASP_DISCOVERY_READINESS_TIMEOUT: "1s",
  };
  const discovery = startTask4Worker(workerBinary, {
    ...workerEnvironment("discovery", "discovery", "zasp_discovery_worker"),
    ...managedEnvironment,
  });
  await assertFailClosedTask4Worker(discovery, "discovery");
  await stopChild(discovery);

  const outbox = startTask4Worker(workerBinary, {
    ...workerEnvironment("outbox", "outbox", "zasp_outbox_worker"),
    ZASP_AWS_REGION: managedEnvironment.ZASP_AWS_REGION,
    ZASP_DISCOVERY_QUEUE_URL: managedEnvironment.ZASP_DISCOVERY_QUEUE_URL,
    ZASP_OUTBOX_ROLE_ARN: "arn:aws:iam::123456789012:role/zasp-production-e2e-outbox",
    ZASP_OUTBOX_WEB_IDENTITY_TOKEN_FILE: managedEnvironment.ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE,
  });
  const outboxExited = await waitForChildExit(outbox, 10_000);
  assert.deepEqual(outboxExited, { status: 1, signal: null }, `outbox did not fail closed without its exact projected identity and managed queue authority: ${outbox.output()}`);
  assert.doesNotMatch(outbox.output(), /(?:access|refresh|session|web_identity)_token|client_secret|private_key|credential_reference|lease_token/i, "outbox failure leaked authority");
  await assertPortAvailable(8081);

  for (const candidate of [
    {
      mode: "projection-search",
      principal: "projection_search",
      authority: "zasp_projection_search_worker",
      extra: {
        ZASP_AWS_REGION: "us-east-1",
        ZASP_PROJECTION_ROLE_ARN: "arn:aws:iam::123456789012:role/zasp-production-e2e-projection-search",
        ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE: managedEnvironment.ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE,
        ZASP_OPENSEARCH_ENDPOINT: "https://vpc-zasp-production-e2e.us-east-1.es.amazonaws.com",
        ZASP_OPENSEARCH_INDEX: "zasp-inventory-v1",
      },
    },
    {
      mode: "projection-graph",
      principal: "projection_graph",
      authority: "zasp_projection_graph_worker",
      extra: {
        ZASP_AWS_REGION: "us-east-1",
        ZASP_PROJECTION_ROLE_ARN: "arn:aws:iam::123456789012:role/zasp-production-e2e-projection-graph",
        ZASP_PROJECTION_WEB_IDENTITY_TOKEN_FILE: managedEnvironment.ZASP_DISCOVERY_WEB_IDENTITY_TOKEN_FILE,
        ZASP_PROJECTION_SECRET_PREFIX: "zasp-production-e2e/projection",
        ZASP_NEO4J_URI: "neo4j+s://neo4j.production-e2e.invalid:7687",
        ZASP_NEO4J_CREDENTIAL_REFERENCE: "ref:neo4j/auth/runtime",
        ZASP_NEO4J_EXPECTED_PRINCIPAL: "zasp_projection_runtime",
        ZASP_NEO4J_EXPECTED_ROLE: "publisher",
      },
    },
  ]) {
    const worker = startTask4Worker(workerBinary, {
      ...workerEnvironment(candidate.mode, candidate.principal, candidate.authority),
      ...candidate.extra,
    });
    const exited = await waitForChildExit(worker, 10_000);
    assert.deepEqual(exited, { status: 1, signal: null }, `${candidate.mode} did not fail closed without its exact managed authority: ${worker.output()}`);
    assert.doesNotMatch(worker.output(), /(?:access|refresh|session|web_identity)_token|client_secret|private_key|credential_reference|lease_token/i, `${candidate.mode} failure leaked authority`);
  }

  const durable = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',sync.state,job.state,job.attempt,job.lease_owner IS NULL,sync.snapshot_id IS NULL)
    FROM zasp_discovery_syncs sync
    JOIN zasp_discovery_jobs job ON (job.organization_id,job.workspace_id,job.environment_id,job.authority_id)=(sync.organization_id,sync.workspace_id,sync.environment_id,sync.id)
    WHERE sync.integration_id='${task4DiscoveryIntegrationID}' AND job.kind='discovery';`]);
  assert.equal(durable.stdout.trim(), "queued|queued|0|t|t", "managed-worker fail-closed probes claimed or completed public discovery work");
  console.log("combined E2E: real launched discovery and per-kind projection worker boundaries proven; scheduler/risk ready and managed dependencies fail closed");
}

async function exerciseSecurityAgentAutomaticLifecycle(cdp, workerE2EBinary, gatewayE2EBinary, apiBinary, apiEnvironment, healthPort, postgresPort, dsn, publicOrigin, actionPrivateKey) {
	const primaryOrganization = "pid_10000001-0000-4000-8000-000000000001";
	const primaryWorkspace = "pid_10000002-0000-4000-8000-000000000002";
	const primaryEnvironment = "pid_10000003-0000-4000-8000-000000000003";
	const primaryFinding = "pid_30000102-0000-4000-8000-000000000102";
	const temporaryFinding = "pid_30000101-0000-4000-8000-000000000101";
	const temporaryDefinition = "pid_78000010-0000-4000-8000-000000000010";
	const attackPathDefinition = "pid_78000011-0000-4000-8000-000000000011";
	const verifiedAttackPath = "pid_40000001-0000-4000-8000-000000000001";
	const connectorFinding = "pid_30000103-0000-4000-8000-000000000103";
	const connectorEvidence = "pid_77000001-0000-4000-8000-000000000001";
	const connectorDefinition = "pid_78000020-0000-4000-8000-000000000020";
	const sessionDefinition = "pid_78000030-0000-4000-8000-000000000030";
	const isolatedSession = "pid_79000010-0000-4000-8000-000000000010";
	const unrelatedSession = "pid_79000011-0000-4000-8000-000000000011";
	const dailyOpsRun = "pid_7a000001-0000-4000-8000-000000000001";
	const dailyOpsSensor = "pid_7a000002-0000-4000-8000-000000000002";
	const dailyOpsSensorToken = "pid_7a000004-0000-4000-8000-000000000004";
	const foreignDailyOpsRun = "pid_9a000001-0000-4000-8000-000000000001";
	const foreignDailyOpsSensor = "pid_9a000002-0000-4000-8000-000000000002";
	const foreignDailyOpsSensorToken = "pid_9a000004-0000-4000-8000-000000000004";
	const gatewayDevice = "pid_79000001-0000-4000-8000-000000000001";
	const gatewayEnrollment = "pid_79000002-0000-4000-8000-000000000002";
	const gatewayCredential = "pid_79000003-0000-4000-8000-000000000003";
	const foreignOrganization = "pid_90000001-0000-4000-8000-000000000001";
	const foreignWorkspace = "pid_90000002-0000-4000-8000-000000000002";
	const foreignEnvironment = "pid_90000003-0000-4000-8000-000000000003";
	const foreignDefinition = "pid_90000008-0000-4000-8000-000000000008";
	const foreignFinding = "pid_90000007-0000-4000-8000-000000000007";
	const foreignGatewayDevice = "pid_90000020-0000-4000-8000-000000000020";
	const foreignGatewayEnrollment = "pid_90000021-0000-4000-8000-000000000021";
	const foreignGatewayCredential = "pid_90000022-0000-4000-8000-000000000022";

	await clickBrowserAria(cdp, "Open Bounded response definition");
	await clickBrowserText(cdp, "Validate definition");
	await waitForBrowserText(cdp, /Resource version 2/);
	await clickBrowserText(cdp, "Enable supervised execution");
	await waitForBrowserText(cdp, /Resource version 3/);
	await waitForBrowserText(cdp, /Start supervised run/);
	await clickBrowserAria(cdp, "Close");

	const primaryDefinition = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT definition_id FROM zasp_security_agent_definitions WHERE (organization_id,workspace_id,environment_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}') AND body->>'name'='Bounded response definition' AND activation='supervised' AND body->>'autonomy'='supervised' AND deleted_at IS NULL;`])).stdout.trim();
	assert.match(primaryDefinition, /^pid_[0-9a-f-]{36}$/, "browser activation did not persist exact supervised definition authority");
	const seed = `
UPDATE zasp_risk_findings SET rule=CASE id WHEN '${primaryFinding}' THEN 'credential' ELSE 'temporary_policy' END WHERE (organization_id,workspace_id,environment_id,status)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','open') AND id IN('${primaryFinding}','${temporaryFinding}');
INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
VALUES('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignDefinition}','autonomous',1,1,
jsonb_build_object('id','${foreignDefinition}','name','Foreign autonomous response','trigger_kind','finding','trigger_source','posture','environment_ids',jsonb_build_array('${foreignEnvironment}'),'autonomy','autonomous','max_steps',1,'max_duration_seconds',300,'temporary_policy_seconds',600,'ai_token_budget',1000,'concurrency_limit',1,'allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state','definition_version',1,'enabled',true),'security-agent-actions-v1');
INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${temporaryDefinition}','supervised',1,1,
jsonb_build_object('id','${temporaryDefinition}','name','Temporary containment response','trigger_kind','finding','trigger_source','temporary_policy','environment_ids',jsonb_build_array('${primaryEnvironment}'),'autonomy','supervised','max_steps',1,'max_duration_seconds',900,'temporary_policy_seconds',600,'ai_token_budget',1000,'concurrency_limit',1,'allowed_actions',jsonb_build_array('create_temporary_policy'),'verification_kind','policy_state','definition_version',1,'enabled',true),'security-agent-actions-v1');
INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${attackPathDefinition}','supervised',1,1,
jsonb_build_object('id','${attackPathDefinition}','name','Verified attack path containment','trigger_kind','attack_path','trigger_source','verified','environment_ids',jsonb_build_array('${primaryEnvironment}'),'autonomy','supervised','max_steps',1,'max_duration_seconds',900,'temporary_policy_seconds',600,'ai_token_budget',1000,'concurrency_limit',1,'allowed_actions',jsonb_build_array('create_temporary_policy'),'verification_kind','policy_state','definition_version',1,'enabled',true),'security-agent-actions-v1');
INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${sessionDefinition}','supervised',1,1,
jsonb_build_object('id','${sessionDefinition}','name','Compromised runtime session','trigger_kind','runtime_decision','trigger_source','gateway','environment_ids',jsonb_build_array('${primaryEnvironment}'),'autonomy','supervised','max_steps',1,'max_duration_seconds',900,'temporary_policy_seconds',600,'ai_token_budget',1000,'concurrency_limit',1,'allowed_actions',jsonb_build_array('isolate_session'),'verification_kind','gateway_decision','definition_version',1,'enabled',true),'security-agent-actions-v1');
INSERT INTO zasp_workflow_records(organization_id,workspace_id,environment_id,kind,id,body)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','integration','${task5GitHubIntegrationID}',jsonb_build_object('id','${task5GitHubIntegrationID}','connector_key','github','name','Harness GitHub inventory','configuration',jsonb_build_object('installation_id','424242'),'status','active','created_at','2026-08-19T00:00:00Z','updated_at','2026-08-19T00:00:00Z'));
INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${connectorFinding}','posture','connector_revocation','Compromised GitHub integration','critical','open');
INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${connectorFinding}',1,'${connectorEvidence}');
INSERT INTO zasp_inventory_evidence(organization_id,workspace_id,environment_id,id,integration_id,snapshot_id,finding_id,object_reference,checksum,media_type,schema_version,parser_version,collected_at,artifact_reference,artifact_key,artifact_version_id,size_bytes,tool_version)
SELECT '${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${connectorEvidence}','${task5GitHubIntegrationID}',snapshot.id,'${connectorFinding}','s3://zasp-production-e2e/security-agent/connector-revocation.json',decode(repeat('7a',32),'hex'),'application/json','1','parser_v1',transaction_timestamp(),'${connectorEvidence}','security-agent/connector-revocation.json','version-e2e-1',128,'tool_v1'
FROM zasp_discovery_snapshots snapshot WHERE (snapshot.organization_id,snapshot.workspace_id,snapshot.environment_id,snapshot.integration_id,snapshot.state,snapshot.complete,snapshot.is_last_good)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${task5GitHubIntegrationID}','complete',true,true) ORDER BY snapshot.generation DESC LIMIT 1;
INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${connectorDefinition}','supervised',1,1,
jsonb_build_object('id','${connectorDefinition}','name','Compromised connector response','trigger_kind','finding','trigger_source','connector_revocation','environment_ids',jsonb_build_array('${primaryEnvironment}'),'autonomy','supervised','max_steps',1,'max_duration_seconds',300,'temporary_policy_seconds',600,'ai_token_budget',1000,'concurrency_limit',1,'allowed_actions',jsonb_build_array('revoke_integration_connection'),'verification_kind','connection_state','definition_version',1,'enabled',true),'security-agent-actions-v1');
INSERT INTO zasp_security_agent_runs(organization_id,workspace_id,environment_id,run_id,definition_id,definition_version,trigger_id,requested_by,state,last_error_code,completed_at)
VALUES
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${dailyOpsRun}','${primaryDefinition}',1,'pid_7a000003-0000-4000-8000-000000000003','pid_10000004-0000-4000-8000-000000000004','needs_human','manual_review_required',transaction_timestamp()),
('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignDailyOpsRun}','${foreignDefinition}',1,'pid_9a000003-0000-4000-8000-000000000003','pid_90000004-0000-4000-8000-000000000004','needs_human','manual_review_required',transaction_timestamp());
INSERT INTO zasp_sensors(organization_id,workspace_id,environment_id,id,name,kind,mode,state)
VALUES
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${dailyOpsSensor}','Daily ops stale sensor','tetragon','metadata_only','degraded'),
('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignDailyOpsSensor}','Foreign daily ops stale sensor','tetragon','metadata_only','degraded');
INSERT INTO zasp_sensor_tokens(organization_id,workspace_id,environment_id,id,sensor_id,audience,salt,token_hash,expires_at,format_version,locator_digest,token_generation,sensor_version_at_issue,v15_issued_at)
VALUES
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${dailyOpsSensorToken}','${dailyOpsSensor}','event-ingest',decode(repeat('a1',32),'hex'),decode(repeat('a2',32),'hex'),transaction_timestamp()+interval '1 hour',1,decode(repeat('a3',32),'hex'),1,1,transaction_timestamp()),
('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignDailyOpsSensorToken}','${foreignDailyOpsSensor}','event-ingest',decode(repeat('b1',32),'hex'),decode(repeat('b2',32),'hex'),transaction_timestamp()+interval '1 hour',1,decode(repeat('b3',32),'hex'),1,1,transaction_timestamp());
INSERT INTO zasp_security_agent_kill_switches(organization_id,workspace_id,environment_id,action_key,execution_enabled,updated_by) VALUES
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','*',true,'production-e2e-security-agent'),
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','update_finding_response',true,'production-e2e-security-agent'),
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','create_temporary_policy',true,'production-e2e-security-agent'),
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','isolate_session',true,'production-e2e-security-agent'),
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','revoke_integration_connection',true,'production-e2e-security-agent'),
('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','*',true,'production-e2e-security-agent'),
('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','update_finding_response',true,'production-e2e-security-agent')
ON CONFLICT(organization_id,workspace_id,environment_id,action_key) DO UPDATE SET execution_enabled=EXCLUDED.execution_enabled,updated_by=EXCLUDED.updated_by,updated_at=transaction_timestamp();
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state,replay_floor) VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayDevice}','Production E2E gateway','active',4);
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayEnrollment}','${gatewayDevice}','runtime-gateway-enroll',repeat(E'\\001',16)::bytea,repeat(E'\\002',32)::bytea,transaction_timestamp()+interval '1 hour');
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayCredential}','${gatewayDevice}','${gatewayEnrollment}',repeat(E'\\003',32)::bytea,'runtime-gateway','ref:gateway/public/production-e2e',repeat(E'\\004',32)::bytea,date_trunc('second',transaction_timestamp())+interval '1 hour',1,1,'gateway-device-key-01','Ed25519',date_trunc('second',transaction_timestamp()));
INSERT INTO zasp_gateway_devices(organization_id,workspace_id,environment_id,id,name,state,replay_floor) VALUES('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignGatewayDevice}','Foreign E2E gateway','active',1);
INSERT INTO zasp_gateway_enrollment_tokens(organization_id,workspace_id,environment_id,id,device_id,audience,salt,token_hash,expires_at) VALUES('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignGatewayEnrollment}','${foreignGatewayDevice}','runtime-gateway-enroll',decode(repeat('05',16),'hex'),decode(repeat('06',32),'hex'),transaction_timestamp()+interval '1 hour');
INSERT INTO zasp_gateway_credentials(organization_id,workspace_id,environment_id,id,device_id,enrollment_token_id,enrollment_digest,audience,key_reference,public_key,expires_at,format_version,credential_generation,key_id,algorithm,v15_issued_at) VALUES('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignGatewayCredential}','${foreignGatewayDevice}','${foreignGatewayEnrollment}',decode(repeat('07',32),'hex'),'runtime-gateway','ref:gateway/public/production-e2e-foreign',decode(repeat('08',32),'hex'),date_trunc('second',transaction_timestamp())+interval '1 hour',1,1,'gateway-device-key-foreign','Ed25519',date_trunc('second',transaction_timestamp()));
INSERT INTO zasp_runtime_gateway_events(organization_id,workspace_id,environment_id,device_id,credential_id,event_id,sequence,request_digest,policy_version,decision,action_kind,classification,policy_ids,occurred_at) VALUES
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayDevice}','${gatewayCredential}','pid_79000020-0000-4000-8000-000000000020',1,decode(repeat('21',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id','${isolatedSession}'),jsonb_build_array('policy-production'),transaction_timestamp()-interval '3 seconds'),
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayDevice}','${gatewayCredential}','pid_79000021-0000-4000-8000-000000000021',2,decode(repeat('22',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id','${isolatedSession}'),'[]'::jsonb,transaction_timestamp()-interval '2 seconds'),
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayDevice}','${gatewayCredential}','pid_79000022-0000-4000-8000-000000000022',3,decode(repeat('23',32),'hex'),1,'block','mcp',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id','${isolatedSession}'),'[]'::jsonb,transaction_timestamp()-interval '1 second'),
('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayDevice}','${gatewayCredential}','pid_79000023-0000-4000-8000-000000000023',4,decode(repeat('24',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id','${unrelatedSession}'),'[]'::jsonb,transaction_timestamp()),
('${foreignOrganization}','${foreignWorkspace}','${foreignEnvironment}','${foreignGatewayDevice}','${foreignGatewayCredential}','pid_90000023-0000-4000-8000-000000000023',1,decode(repeat('25',32),'hex'),1,'block','http',jsonb_build_object('category','security','route_class','runtime','resource_class','session','outcome','gateway','session_id','${isolatedSession}'),jsonb_build_array('policy-production'),transaction_timestamp());`;
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: seed });
	const connectorSeed = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-v", "ON_ERROR_STOP=1", "-c", `SELECT concat_ws('|',count(*),max(workflow.body->>'status'),max(connection.state),max(credential.status)) FROM zasp_inventory_evidence evidence JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.kind,workflow.id)=(evidence.organization_id,evidence.workspace_id,evidence.environment_id,'integration',evidence.integration_id) JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id)=(evidence.organization_id,evidence.workspace_id,evidence.environment_id,evidence.integration_id) JOIN zasp_connector_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.integration_id,credential.provider,credential.credential_reference)=(connection.organization_id,connection.workspace_id,connection.environment_id,connection.integration_id,connection.provider,connection.connection_reference) WHERE evidence.id='${connectorEvidence}';`])).stdout.trim();
	assert.equal(connectorSeed, "1|active|verified|active", "connector response seed was not fully actionable");

	await assertPortAvailable(8081);
	const securityAgentWorkerEnvironment = {
		...process.env,
		ZASP_WORKER_MODE: "security-agent",
		ZASP_POSTGRES_DSN: `postgres://zasp_e2e_security_agent_worker@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
		ZASP_DATABASE_AUTHORITY: "zasp_security_agent_worker",
		ZASP_WORKER_ID: "production-e2e-security-agent",
		ZASP_POLL_INTERVAL: "100ms",
		ZASP_LEASE_DURATION: "30s",
		ZASP_BATCH_SIZE: "10",
		ZASP_SHUTDOWN_TIMEOUT: "1s",
	};
	let worker = startSecurityAgentE2EWorker(workerE2EBinary, securityAgentWorkerEnvironment);
	await assertReadyTask4Worker(worker, "security-agent");

	let approvalID = "";
	let automaticState = "";
	for (let attempt = 0; attempt < 200; attempt += 1) {
		automaticState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
			COALESCE((SELECT run.state FROM zasp_security_agent_runs run WHERE (run.organization_id,run.trigger_id)=('${primaryOrganization}','${primaryFinding}')),''),
			COALESCE((SELECT approval.approval_id FROM zasp_security_agent_approvals approval JOIN zasp_security_agent_runs run USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.trigger_id,approval.state)=('${primaryOrganization}','${primaryFinding}','pending')),''),
			COALESCE((SELECT run.state FROM zasp_security_agent_runs run WHERE (run.organization_id,run.trigger_id)=('${foreignOrganization}','${foreignFinding}')),''),
			COALESCE((SELECT finding.status FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.id)=('${foreignOrganization}','${foreignFinding}')),''));`])).stdout.trim();
		const [primaryState, candidateApproval, foreignState, foreignFindingState] = automaticState.split("|");
		if (primaryState === "waiting_approval" && /^pid_[0-9a-f-]{36}$/.test(candidateApproval) && foreignState === "remediated" && foreignFindingState === "under_review") {
			approvalID = candidateApproval;
			break;
		}
		await delay(50);
	}
	assert.match(approvalID, /^pid_[0-9a-f-]{36}$/, `worker did not prepare supervised authority and execute autonomous authority: state=${automaticState}; output=${worker.output()}`);
	let attackPathState = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		attackPathState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',count(*),min(run.state),min(receipt.trigger_kind),min(receipt.trigger_id),min(receipt.trigger_version),count(approval.approval_id),bool_and(plan.plan->'evidence_ids'=jsonb_build_array('${verifiedAttackPath}') AND plan.plan->'steps'->0->>'action'='create_temporary_policy' AND plan.plan->'steps'->0->>'target_id'='${primaryEnvironment}')) FROM zasp_security_agent_runs run JOIN zasp_security_agent_trigger_receipts receipt USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_plans plan USING(organization_id,workspace_id,environment_id,run_id) LEFT JOIN zasp_security_agent_approvals approval USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${attackPathDefinition}');`])).stdout.trim();
		if (attackPathState === `1|waiting_approval|attack_path|${verifiedAttackPath}|1|1|t`) break;
		await delay(50);
	}
	assert.equal(attackPathState, `1|waiting_approval|attack_path|${verifiedAttackPath}|1|1|t`, "verified attack path did not create one exact version-bound supervised plan");
	await delay(250);
	const attackPathReplay = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',(SELECT count(*) FROM zasp_security_agent_runs WHERE (organization_id,workspace_id,environment_id,definition_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${attackPathDefinition}')),(SELECT count(*) FROM zasp_security_agent_trigger_receipts WHERE (organization_id,workspace_id,environment_id,definition_id,trigger_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${attackPathDefinition}','${verifiedAttackPath}')));`])).stdout.trim();
	assert.equal(attackPathReplay, "1|1", "attack-path scheduler duplicated a durable run or receipt");
	await exerciseHomeDailyOperations(cdp, publicOrigin, dsn, approvalID, dailyOpsRun, dailyOpsSensor);

	await navigateBrowser(cdp, `${publicOrigin}/protect/approvals`);
	await waitForBrowserText(cdp, /Move finding to under review/);
	await clickBrowserAria(cdp, `Open approval ${approvalID}`);
	await clickBrowserText(cdp, "Approve");
	await waitForBrowserText(cdp, /approved/);

	let finalState = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		finalState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
			(SELECT finding.status FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.id)=('${primaryOrganization}','${primaryFinding}')),
			(SELECT run.state FROM zasp_security_agent_runs run WHERE (run.organization_id,run.trigger_id)=('${primaryOrganization}','${primaryFinding}')),
			(SELECT step.authorization_result FROM zasp_security_agent_steps step JOIN zasp_security_agent_runs run USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.trigger_id)=('${primaryOrganization}','${primaryFinding}')),
			(SELECT approval.state FROM zasp_security_agent_approvals approval WHERE approval.approval_id='${approvalID}'),
			(SELECT finding.status FROM zasp_risk_findings finding WHERE (finding.organization_id,finding.id)=('${foreignOrganization}','${foreignFinding}')),
			(SELECT run.state FROM zasp_security_agent_runs run WHERE (run.organization_id,run.trigger_id)=('${foreignOrganization}','${foreignFinding}')),
			(SELECT step.authorization_result FROM zasp_security_agent_steps step JOIN zasp_security_agent_runs run USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.trigger_id)=('${foreignOrganization}','${foreignFinding}')),
			(SELECT count(*) FROM zasp_security_agent_approvals approval WHERE approval.organization_id='${foreignOrganization}'),
			(SELECT count(*) FROM zasp_security_agent_effects effect WHERE NOT EXISTS(SELECT 1 FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.run_id)=(effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id))));`])).stdout.trim();
		if (finalState === "under_review|remediated|approval_required|approved|under_review|remediated|autonomous|0|0") break;
		await delay(50);
	}
	assert.equal(finalState, "under_review|remediated|approval_required|approved|under_review|remediated|autonomous|0|0", "multi-tenant automatic response did not preserve supervised, autonomous, and isolation authority");

	let connectorApprovalID = "";
	let connectorRunID = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		const state = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',COALESCE(run.run_id,''),COALESCE(run.state,''),COALESCE(approval.approval_id,'')) FROM zasp_security_agent_runs run LEFT JOIN zasp_security_agent_approvals approval USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${connectorDefinition}');`])).stdout.trim();
		const [candidateRun, runState, candidateApproval] = state.split("|");
		if (/^pid_[0-9a-f-]{36}$/.test(candidateRun) && runState === "waiting_approval" && /^pid_[0-9a-f-]{36}$/.test(candidateApproval)) {
			connectorRunID = candidateRun;
			connectorApprovalID = candidateApproval;
			break;
		}
		await delay(50);
	}
	assert.match(connectorApprovalID, /^pid_[0-9a-f-]{36}$/, `connector revocation approval was not prepared: ${worker.output()}`);
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_identity_memberships SET role='security_engineer',version=version+1 WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND organization_id='${primaryOrganization}' AND active;`]);
	await navigateBrowser(cdp, `${publicOrigin}/protect/approvals`);
	await waitForBrowserText(cdp, /Revoke integration connection/);
	await clickBrowserAria(cdp, `Open approval ${connectorApprovalID}`);
	await waitForBrowserText(cdp, /Identity administrator approval required/);
	assert.equal(await browserHasInteractiveText(cdp, /^Approve$/i), false, "non-admin browser could approve irreversible connector revocation");
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_identity_memberships SET role='security_admin',version=version+1 WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND organization_id='${primaryOrganization}' AND active; UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","manage_findings","manage_identity"]'::jsonb WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND organization_id='${primaryOrganization}' AND workspace_id='${primaryWorkspace}' AND environment_id='${primaryEnvironment}'; UPDATE zasp_product_sessions SET permissions='["view","manage_workflows","manage_findings","manage_identity"]'::jsonb WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
	await reloadBrowser(cdp);
	await waitForBrowserText(cdp, /Revoke integration connection/);
	await clickBrowserAria(cdp, `Open approval ${connectorApprovalID}`);
	await stopChild(worker);
	await clickBrowserText(cdp, "Approve");
	await waitForBrowserText(cdp, /approved/);
	await stopChild(api);
	api = undefined;
	worker = startSecurityAgentE2EWorker(workerE2EBinary, securityAgentWorkerEnvironment);
	await assertReadyTask4Worker(worker, "security-agent");
	let connectorEffectState = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		connectorEffectState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,effect.state,approval.state) FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_approvals approval USING(organization_id,workspace_id,environment_id,run_id) WHERE run.run_id='${connectorRunID}' AND effect.action_key='revoke_integration_connection';`])).stdout.trim();
		if (connectorEffectState === "running|pending|approved") break;
		await delay(50);
	}
	assert.equal(connectorEffectState, "running|pending|approved", "approved connector revocation did not reach provider reconciliation");

	let temporaryApprovalID = "";
	let temporaryRunID = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		const state = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',COALESCE(run.run_id,''),COALESCE(run.state,''),COALESCE(approval.approval_id,'')) FROM zasp_security_agent_runs run LEFT JOIN zasp_security_agent_approvals approval USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${temporaryDefinition}');`])).stdout.trim();
		const [candidateRun, runState, candidateApproval] = state.split("|");
		if (/^pid_[0-9a-f-]{36}$/.test(candidateRun) && runState === "waiting_approval" && /^pid_[0-9a-f-]{36}$/.test(candidateApproval)) {
			temporaryRunID = candidateRun;
			temporaryApprovalID = candidateApproval;
			break;
		}
		await delay(50);
	}
	assert.match(temporaryApprovalID, /^pid_[0-9a-f-]{36}$/, `temporary policy approval was not prepared: ${worker.output()}`);
	await stopChild(worker);
	await runConnectorRevocationProviderWorker(workerE2EBinary, postgresPort, task5GitHubIntegrationID);
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_product_sessions SET authenticated_at=transaction_timestamp()-interval '10 minutes' WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
	const approvalReauthenticationStarts = identityOAuthStarts;
	api = startChild(apiBinary, [], { env: apiEnvironment });
	await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
	await navigateBrowser(cdp, `${publicOrigin}/protect/approvals`);
	await waitForBrowserText(cdp, /Apply temporary containment policy/);
	await clickBrowserAria(cdp, `Open approval ${temporaryApprovalID}`);
	await waitForBrowserText(cdp, /Apply temporary containment policy/);
	await waitForBrowserText(cdp, /TTL 600s/);
	assert.equal(await browserHasInteractiveText(cdp, /^Approve$/i), false, "expired fresh authentication exposed a containment approval action");
	await clickBrowserText(cdp, "Reauthenticate to decide");
	await waitForBrowserText(cdp, /Continue through the configured identity provider/);
	const reauthenticationDocumentMarker = `zasp-reauth-${Date.now()}`;
	const markedReauthenticationDocument = await cdp.send("Runtime.evaluate", { expression: `globalThis.__zaspE2EReauthenticationDocument = ${JSON.stringify(reauthenticationDocumentMarker)}; true`, returnByValue: true });
	assert.equal(markedReauthenticationDocument.result?.value, true, "reauthentication document marker was not installed");
	await clickBrowserText(cdp, "Continue to sign in");
	await waitForBrowserAction(cdp, `globalThis.__zaspE2EReauthenticationDocument !== ${JSON.stringify(reauthenticationDocumentMarker)} && location.origin === ${JSON.stringify(publicOrigin)} && location.pathname === "/protect/approvals" && document.readyState !== "loading"`);
	await waitForBrowserText(cdp, /Apply temporary containment policy/);
	assert.equal(identityOAuthStarts, approvalReauthenticationStarts + 1, "containment approval did not use exactly one provider-faithful reauthentication flow");
	await clickBrowserAria(cdp, `Open approval ${temporaryApprovalID}`);
	await waitForBrowserText(cdp, /TTL 600s/);
	const temporaryApprovalResponsesBefore = securityAgentApprovalResponses.length;
	await clickBrowserText(cdp, "Approve");
	await waitForScopeOverlap(() => securityAgentApprovalResponses.length > temporaryApprovalResponsesBefore, "temporary containment approval response was not observed");
	const temporaryApprovalResponse = securityAgentApprovalResponses.at(-1);
	if (temporaryApprovalResponse?.status !== 200) {
		const authority = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',approval.state,approval.version,approval.expires_at>transaction_timestamp(),approval.requester_id='pid_10000004-0000-4000-8000-000000000004',run.state,run.plan_hash=approval.plan_hash,step.action_key,zasp_security_agent_principal_ready('zasp_security_agent_api'),to_char(transaction_timestamp() AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),to_char(approval.expires_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')) FROM zasp_security_agent_approvals approval JOIN zasp_security_agent_runs run USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_steps step USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE approval.approval_id='${temporaryApprovalID}';`])).stdout.trim();
		assert.equal(temporaryApprovalResponse?.status, 200, `temporary containment approval rejected: response=${JSON.stringify(temporaryApprovalResponse)} authority=${authority}`);
	}
	await waitForBrowserText(cdp, /approved Version 2/);
	worker = startSecurityAgentE2EWorker(workerE2EBinary, securityAgentWorkerEnvironment);
	await assertReadyTask4Worker(worker, "security-agent");
	let effectState = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		effectState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,COALESCE(effect.state,''),approval.state,step.authorization_result,COALESCE(run.last_error_code,'')) FROM zasp_security_agent_runs run JOIN zasp_security_agent_steps step USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_approvals approval USING(organization_id,workspace_id,environment_id,run_id) LEFT JOIN zasp_security_agent_effects effect ON (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id,effect.step_id,effect.action_key)=(step.organization_id,step.workspace_id,step.environment_id,step.run_id,step.step_id,'create_temporary_policy') WHERE run.run_id='${temporaryRunID}' AND step.action_key='create_temporary_policy';`])).stdout.trim();
		if (effectState === "running|pending|approved|approval_required|") break;
		await delay(50);
	}
	assert.equal(effectState, "running|pending|approved|approval_required|", `approved temporary policy did not reach the isolated action queue: responses=${JSON.stringify(securityAgentApprovalResponses.slice(-4))}; browser=${JSON.stringify((await browserBodyText(cdp)).slice(-1000))}; worker=${worker.output()}`);
	await stopChild(worker);
	await stopChild(api);
	api = undefined;

	await runTemporaryPolicyActionWorker(workerE2EBinary, postgresPort, actionPrivateKey, "apply");
	const capabilityEdge = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-v", "ON_ERROR_STOP=1", "-c", `SELECT concat_ws('|',edge.target_id,edge.category,edge.outcome,array_length(edge.evidence_ids,1)) FROM zasp_inventory_agent_capability_edges('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','pid_21000001-0000-4000-8000-000000000001') edge WHERE (edge.target_id,edge.category,edge.outcome)=('pid_21000004-0000-4000-8000-000000000004','identity_assume','assume');`])).stdout.trim();
	assert.match(capabilityEdge, /^pid_21000004-0000-4000-8000-000000000004\|identity_assume\|assume\|[1-9][0-9]*$/, "runtime capability reachability edge was absent before enforcement");
	await runRuntimeGatewayProxyE2E(gatewayE2EBinary, postgresPort, actionPrivateKey, "apply");
	const blockedCapability = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-v", "ON_ERROR_STOP=1", "-c", `SELECT concat_ws('|',
	 (SELECT state FROM zasp_inventory_capability_evidence WHERE (organization_id,workspace_id,environment_id,evidence_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','pid_79000030-0000-4000-8000-000000000030')),
	 (SELECT evidence_id FROM zasp_inventory_capability_evidence WHERE (organization_id,workspace_id,environment_id,evidence_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','pid_79000030-0000-4000-8000-000000000030')),
	 (SELECT count(*) FROM zasp_inventory_agent_capability_edges('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','pid_21000001-0000-4000-8000-000000000001') edge WHERE (edge.target_id,edge.category,edge.outcome)=('pid_21000004-0000-4000-8000-000000000004','identity_assume','assume')));`])).stdout.trim();
	assert.equal(blockedCapability, "blocked|pid_79000030-0000-4000-8000-000000000030|1", "durable runtime policy evidence did not block the exact capability while retaining reachability");
	const applied = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,effect.state,count(target.*)) FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_temporary_policy_targets target USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE run.run_id='${temporaryRunID}' GROUP BY run.state,effect.state;`])).stdout.trim();
	assert.equal(applied, "contained|cleanup_pending|2", "temporary containment was not durably applied to every active gateway before publication");
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_security_agent_effects SET updated_at=transaction_timestamp() WHERE run_id='${temporaryRunID}' AND action_key='create_temporary_policy' AND state='cleanup_pending';`]);
	await runTemporaryPolicyActionWorker(workerE2EBinary, postgresPort, actionPrivateKey, "cleanup");
	await runRuntimeGatewayProxyE2E(gatewayE2EBinary, postgresPort, actionPrivateKey, "cleanup");
	const cleaned = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,effect.state,count(target.*),max(target.sequence)) FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_temporary_policy_targets target USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE run.run_id='${temporaryRunID}' GROUP BY run.state,effect.state;`])).stdout.trim();
	assert.equal(cleaned, "remediated|cleaned|4|3", "temporary containment cleanup did not durably restore every active gateway policy");

	let sessionApprovalID = "";
	let sessionRunID = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		const state = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',COALESCE(run.run_id,''),COALESCE(run.state,''),COALESCE(approval.approval_id,'')) FROM zasp_security_agent_runs run LEFT JOIN zasp_security_agent_approvals approval USING(organization_id,workspace_id,environment_id,run_id) WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id,run.trigger_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${sessionDefinition}','${isolatedSession}');`])).stdout.trim();
		const [candidateRun, runState, candidateApproval] = state.split("|");
		if (/^pid_[0-9a-f-]{36}$/.test(candidateRun) && runState === "waiting_approval" && /^pid_[0-9a-f-]{36}$/.test(candidateApproval)) {
			sessionRunID = candidateRun;
			sessionApprovalID = candidateApproval;
			break;
		}
		await delay(50);
	}
	assert.match(sessionApprovalID, /^pid_[0-9a-f-]{36}$/, "automatic session isolation did not reach supervised approval");
	api = startChild(apiBinary, [], { env: apiEnvironment });
	await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
	await navigateBrowser(cdp, `${publicOrigin}/protect/approvals`);
	await waitForBrowserText(cdp, /Isolate runtime session/);
	await clickBrowserAria(cdp, `Open approval ${sessionApprovalID}`);
	await waitForBrowserText(cdp, /Isolate runtime session/);
	await waitForBrowserText(cdp, /TTL 600s/);
	await clickBrowserText(cdp, "Approve");
	await waitForBrowserText(cdp, /approved/);
	worker = startSecurityAgentE2EWorker(workerE2EBinary, securityAgentWorkerEnvironment);
	await assertReadyTask4Worker(worker, "security-agent");
	let sessionEffectState = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		sessionEffectState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,effect.state,approval.state) FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_approvals approval USING(organization_id,workspace_id,environment_id,run_id) WHERE run.run_id='${sessionRunID}' AND effect.action_key='isolate_session';`])).stdout.trim();
		if (sessionEffectState === "running|pending|approved") break;
		await delay(50);
	}
	assert.equal(sessionEffectState, "running|pending|approved", "approved session isolation did not reach the action worker");
	await stopChild(worker);
	await stopChild(api);
	api = undefined;
	await runTemporaryPolicyActionWorker(workerE2EBinary, postgresPort, actionPrivateKey, "apply", { key: "isolate_session", afterSequence: 2, sessionID: isolatedSession, otherSessionID: unrelatedSession });
	const sessionApplied = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,effect.state,count(target.*),max(target.sequence),(SELECT count(*) FROM zasp_security_agent_temporary_policy_targets foreign_target WHERE foreign_target.action_key='isolate_session' AND foreign_target.organization_id='${foreignOrganization}')) FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_temporary_policy_targets target USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE run.run_id='${sessionRunID}' GROUP BY run.state,effect.state;`])).stdout.trim();
	assert.equal(sessionApplied, "contained|cleanup_pending|1|3|0", "session isolation was not exact, durable, and tenant scoped");
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_security_agent_effects SET updated_at=transaction_timestamp() WHERE run_id='${sessionRunID}' AND action_key='isolate_session' AND state='cleanup_pending';`]);
	await runTemporaryPolicyActionWorker(workerE2EBinary, postgresPort, actionPrivateKey, "cleanup", { key: "isolate_session", afterSequence: 3, sessionID: isolatedSession, otherSessionID: unrelatedSession });
	const sessionCleaned = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,effect.state,count(target.*),max(target.sequence)) FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_temporary_policy_targets target USING(organization_id,workspace_id,environment_id,run_id,step_id) WHERE run.run_id='${sessionRunID}' GROUP BY run.state,effect.state;`])).stdout.trim();
	assert.equal(sessionCleaned, "remediated|cleaned|2|4", "session isolation cleanup did not restore unrelated gateway activity");

	await runTemporaryPolicyActionWorker(workerE2EBinary, postgresPort, actionPrivateKey, "reconcile");
	const connectorFinalState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,effect.state,link.state,connection.state,credential.status,integration.state,workflow.body->>'status') FROM zasp_security_agent_runs run JOIN zasp_security_agent_effects effect USING(organization_id,workspace_id,environment_id,run_id) JOIN zasp_security_agent_connector_revocations link USING(organization_id,workspace_id,environment_id,run_id,step_id) JOIN zasp_integration_connections connection ON (connection.organization_id,connection.workspace_id,connection.environment_id,connection.id)=(link.organization_id,link.workspace_id,link.environment_id,link.connection_id) JOIN zasp_connector_credentials credential ON (credential.organization_id,credential.workspace_id,credential.environment_id,credential.id)=(link.organization_id,link.workspace_id,link.environment_id,link.credential_id) JOIN zasp_integrations integration ON (integration.organization_id,integration.workspace_id,integration.environment_id,integration.id)=(link.organization_id,link.workspace_id,link.environment_id,link.integration_id) JOIN zasp_workflow_records workflow ON (workflow.organization_id,workflow.workspace_id,workflow.environment_id,workflow.kind,workflow.id)=(link.organization_id,link.workspace_id,link.environment_id,'integration',link.integration_id) WHERE run.run_id='${connectorRunID}';`])).stdout.trim();
	assert.equal(connectorFinalState, "remediated|verified|verified|revoked|revoked|pending|pending_authorization", "connector revocation did not finish through provider and action worker authority");
	api = startChild(apiBinary, [], { env: apiEnvironment });
	await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
	await navigateBrowser(cdp, `${publicOrigin}/discovery/assets?inventory=pid_21000001-0000-4000-8000-000000000001`);
	await waitForBrowserText(cdp, /identity_assume · blocked · assume/);
	await reloadBrowser(cdp);
	await waitForBrowserText(cdp, /identity_assume · blocked · assume/);
	console.log("combined E2E: blocked capability evidence survived reload while its reachability edge remained authoritative");

	await navigateBrowser(cdp, `${publicOrigin}/protect/security-agents`);
	const visible = await waitForBrowserText(cdp, /remediated/);
	assert.match(visible, /Bounded response definition/);
	assert.doesNotMatch(visible, /Foreign autonomous response/);
	await navigateBrowser(cdp, `${publicOrigin}/protect/approvals`);
	const history = await waitForBrowserText(cdp, /Approval history/);
	assert.match(history, /approved/);
	assert.doesNotMatch(history, /Foreign autonomous response/);

	const degradedDefinition = "pid_78000040-0000-4000-8000-000000000040";
	const degradedFinding = "pid_30000140-0000-4000-8000-000000000140";
	const degradedEvidence = "pid_31000140-0000-4000-8000-000000000140";
	const policyBefore = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',sequence,encode(envelope_digest,'hex')) FROM zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayDevice}') ORDER BY sequence DESC LIMIT 1;`])).stdout.trim();
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `
INSERT INTO zasp_risk_findings(organization_id,workspace_id,environment_id,id,source,rule,title,severity,status)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${degradedFinding}','posture','planner_degraded','Planner unavailable proof','critical','open');
INSERT INTO zasp_risk_finding_evidence(organization_id,workspace_id,environment_id,finding_id,position,evidence_id)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${degradedFinding}',1,'${degradedEvidence}');
INSERT INTO zasp_security_agent_definitions(organization_id,workspace_id,environment_id,definition_id,activation,version,definition_version,body,plan_catalog_version)
VALUES('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${degradedDefinition}','supervised',1,1,
jsonb_build_object('id','${degradedDefinition}','name','Planner unavailable response','trigger_kind','finding','trigger_source','planner_degraded','environment_ids',jsonb_build_array('${primaryEnvironment}'),'autonomy','supervised','max_steps',1,'max_duration_seconds',300,'temporary_policy_seconds',600,'ai_token_budget',1000,'concurrency_limit',1,'allowed_actions',jsonb_build_array('update_finding_response'),'verification_kind','finding_state','definition_version',1,'enabled',true),'security-agent-actions-v1');`]);
	const degraded = await command(workerE2EBinary, ["-test.run=^TestProductionCombinedE2ESecurityAgentWorker$", "-test.v", "-test.count=1"], {
		timeout: 30_000,
		env: { ...process.env, ZASP_COMBINED_E2E_SECURITY_AGENT_DSN: securityAgentWorkerEnvironment.ZASP_POSTGRES_DSN, ZASP_COMBINED_E2E_SECURITY_AGENT_PLANNER: "unavailable", ZASP_COMBINED_E2E_SECURITY_AGENT_ONCE: "true" },
	});
	assert.match(degraded.stdout, /composed security agent persisted planner-unavailable without an action/);
	const degradedState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',run.state,run.last_error_code,
		(SELECT count(*) FROM zasp_security_agent_plans plan WHERE (plan.organization_id,plan.workspace_id,plan.environment_id,plan.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)),
		(SELECT count(*) FROM zasp_security_agent_steps step WHERE (step.organization_id,step.workspace_id,step.environment_id,step.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)),
		(SELECT count(*) FROM zasp_security_agent_approvals approval WHERE (approval.organization_id,approval.workspace_id,approval.environment_id,approval.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)),
		(SELECT count(*) FROM zasp_security_agent_effects effect WHERE (effect.organization_id,effect.workspace_id,effect.environment_id,effect.run_id)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id)),
		(SELECT count(*) FROM zasp_security_agent_planner_receipts receipt WHERE (receipt.organization_id,receipt.workspace_id,receipt.environment_id,receipt.run_id,receipt.outcome)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id,'planner_unavailable')),
		(SELECT count(*) FROM zasp_security_agent_audit audit WHERE (audit.organization_id,audit.workspace_id,audit.environment_id,audit.run_id,audit.event_kind)=(run.organization_id,run.workspace_id,run.environment_id,run.run_id,'planner_failed')))
		FROM zasp_security_agent_runs run WHERE (run.organization_id,run.workspace_id,run.environment_id,run.definition_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${degradedDefinition}');`])).stdout.trim();
	assert.equal(degradedState, "failed|planner_unavailable|0|0|0|0|1|1", "planner outage created executable authority");
	const policyAfter = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',sequence,encode(envelope_digest,'hex')) FROM zasp_runtime_gateway_policy_bundles WHERE (organization_id,workspace_id,environment_id,device_id)=('${primaryOrganization}','${primaryWorkspace}','${primaryEnvironment}','${gatewayDevice}') ORDER BY sequence DESC LIMIT 1;`])).stdout.trim();
	assert.equal(policyAfter, policyBefore, "planner outage changed the existing runtime policy authority");
	console.log("combined E2E: multi-tenant supervised approval, autonomous response, exact-session isolation with unrelated allowance and cleanup, signed temporary policy apply/cleanup, and irreversible connector revocation proven through real production workers");
	console.log("combined E2E: OpenRouter outage durably recorded planner unavailable, created zero action authority, and preserved the enforced runtime policy");
}

async function exerciseHomeDailyOperations(cdp, publicOrigin, dsn, approvalID, runID, sensorID) {
	const expectedScope = "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003";
	const headers = { "X-Zasp-Expected-Scope": expectedScope };
	const before = await browserFetchJSON(cdp, "/api/v1/home/summary", headers);
	assert.equal(before.status, 200, `Home summary unavailable: ${JSON.stringify(before.body)}`);
	assert.ok(before.body.high_risk_paths >= 1 && before.body.pending_approvals >= 1 && before.body.needs_human_runs === 1 && before.body.attention_required && !before.body.healthy, `Home omitted daily-ops authority: ${JSON.stringify(before.body)}`);

	await navigateBrowser(cdp, `${publicOrigin}/`);
	const home = await waitForBrowserText(cdp, /Needs attention/);
	for (const item of ["Critical exposures", "Pending approvals", "Needs human", "Stale launch coverage"]) assert.match(home, new RegExp(item));
	console.log("combined E2E: Home exposed every daily-ops item");

	await clickBrowserTextContains(cdp, "Critical exposures");
	await waitForBrowserAction(cdp, `document.querySelectorAll('[aria-label^="Open attack path "]').length >= 1`);
	assert.ok(await browserCountAriaPrefix(cdp, "Open attack path") >= 1, "Home critical exposure route had no authoritative path");

	await navigateBrowser(cdp, `${publicOrigin}/`);
	await waitForBrowserText(cdp, /Needs attention/);
	await clickBrowserTextContains(cdp, "Pending approvals");
	await waitForBrowserText(cdp, /Security Agent approvals/);
	await clickBrowserAria(cdp, `Open approval ${approvalID}`);
	assert.match(await waitForBrowserText(cdp, /Move finding to under review/), /pending/i);
	await clickBrowserAria(cdp, "Close");

	await navigateBrowser(cdp, `${publicOrigin}/`);
	await waitForBrowserText(cdp, /Needs attention/);
	await clickBrowserTextContains(cdp, "Needs human");
	await waitForBrowserText(cdp, /Security agents/);
	assert.doesNotMatch(await browserBodyText(cdp), /pid_9a000001-0000-4000-8000-000000000001|Foreign daily ops stale sensor/, "Home daily-ops route crossed tenant scope");
	await clickBrowserAria(cdp, `Open run ${runID}`);
	assert.match(await waitForBrowserText(cdp, /No plan has been persisted/), /needs_human/);
	await clickBrowserAria(cdp, "Close");

	await navigateBrowser(cdp, `${publicOrigin}/`);
	await waitForBrowserText(cdp, /Needs attention/);
	await clickBrowserTextContains(cdp, "Stale launch coverage");
	await waitForBrowserText(cdp, /Runtime sensors/);
	const sensors = await waitForBrowserText(cdp, /Daily ops stale sensor/);
	assert.match(sensors, /degraded/);
	assert.doesNotMatch(sensors, /Foreign daily ops stale sensor/);
	await clickBrowserAria(cdp, "Open Daily ops stale sensor");
	assert.match(await waitForBrowserText(cdp, /Resource version "1"/), /degraded/);
	await clickBrowserText(cdp, "Delete sensor");
	await waitForBrowserText(cdp, /Sensor deleted and its active tokens revoked\./);
	await waitForBrowserAction(cdp, `document.querySelector(${JSON.stringify('[aria-label="Open Daily ops stale sensor"]')}) === null`);
	const sensorState = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT state || '|' || version FROM zasp_sensors WHERE (organization_id,workspace_id,environment_id,id)=('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${sensorID}');`])).stdout.trim();
	assert.equal(sensorState, "deleted|2", "daily-ops sensor disappeared without exact deleted state");

	const after = await browserFetchJSON(cdp, "/api/v1/home/summary", headers);
	assert.equal(after.status, 200);
	for (const field of ["high_risk_paths", "pending_approvals", "needs_human_runs"]) assert.equal(after.body[field], before.body[field], `unrelated sensor action silently cleared ${field}`);
	console.log("combined E2E: Home daily-ops routing preserved explicit terminal and degraded authority");
}

async function exerciseProductionAttackLabLifecycle(cdp, workerE2EBinary, postgresPort, dsn, publicOrigin) {
	const organizationID = "pid_10000001-0000-4000-8000-000000000001";
	const workspaceID = "pid_10000022-0000-4000-8000-000000000022";
	const environmentID = "pid_10000023-0000-4000-8000-000000000023";
	const actorID = "pid_10000004-0000-4000-8000-000000000004";
	const credentialReference = "ref:red-team/target_e2e_0001";
	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `
UPDATE zasp_authorized_scopes SET permissions='["view","manage_workflows","manage_findings","manage_identity","run_tests"]'::jsonb
 WHERE principal_id='${actorID}' AND organization_id='${organizationID}' AND (workspace_id,environment_id) IN
 (('pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003'),('${workspaceID}','${environmentID}'));
UPDATE zasp_product_sessions SET permissions='["view","manage_workflows","manage_findings","manage_identity","run_tests"]'::jsonb
 WHERE principal_id='${actorID}' AND revoked_at IS NULL;
INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,state,first_seen_at,last_seen_at,product_kind,observed_at,fresh_until,winning_attributes)
VALUES('${organizationID}','${workspaceID}','${environmentID}','${attackLabTargetID}','agent_endpoint','Attack Lab staging agent','active',transaction_timestamp(),transaction_timestamp(),'agent',transaction_timestamp(),transaction_timestamp()+interval '1 hour',
 jsonb_build_object('red_team',jsonb_build_object('enabled',true,'endpoint','https://adapter.customer.example/v1/evaluate','credential_reference','${credentialReference}','target_kinds',jsonb_build_array('agent_endpoint'))))
ON CONFLICT(organization_id,workspace_id,environment_id,id) DO UPDATE SET state='active',observed_at=transaction_timestamp(),fresh_until=transaction_timestamp()+interval '1 hour',winning_attributes=excluded.winning_attributes;
INSERT INTO zasp_red_team_definitions(organization_id,workspace_id,environment_id,definition_id,version,name,target_id,target_kind,categories,safety,enabled,created_by)
VALUES('${organizationID}','${workspaceID}','${environmentID}','${attackLabDefinitionID}',1,'Attack Lab prompt safety','${attackLabTargetID}','agent_endpoint','["prompt_injection"]'::jsonb,'{"environment":"staging","credential_class":"read_only","expected_side_effects":["bounded canary evaluation"]}'::jsonb,true,'${actorID}')
ON CONFLICT DO NOTHING;
INSERT INTO zasp_red_team_runs(organization_id,workspace_id,environment_id,run_id,version,definition_id,definition_version,requested_by,state,attempt,cancel_requested,queued_at,started_at,completed_at,input_digest,verdict,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size)
VALUES('${organizationID}','${workspaceID}','${environmentID}','${attackLabSourceRunID}',3,'${attackLabDefinitionID}',1,'${actorID}','complete',1,false,transaction_timestamp()-interval '10 seconds',transaction_timestamp()-interval '9 seconds',transaction_timestamp()-interval '5 seconds',digest(convert_to('attack-lab-source-e2e','UTF8'),'sha256'),'fail','s3://zasp-production-e2e-evidence/attack-lab-source','attack-lab-source','version-source-e2e',digest(convert_to('attack-lab-source-evidence','UTF8'),'sha256'),512)
ON CONFLICT DO NOTHING;
INSERT INTO zasp_red_team_attempts(organization_id,workspace_id,environment_id,run_id,attempt,input_digest,verdict,objective,behavior,error_code,evidence,evidence_reference,evidence_key,evidence_version_id,evidence_checksum,evidence_size,completed_at)
VALUES('${organizationID}','${workspaceID}','${environmentID}','${attackLabSourceRunID}',1,digest(convert_to('attack-lab-source-e2e','UTF8'),'sha256'),'fail','Reject direct prompt injection','The staging target exposed the bounded canary',NULL,'["policy bypass observed"]'::jsonb,'s3://zasp-production-e2e-evidence/attack-lab-source','attack-lab-source','version-source-e2e',digest(convert_to('attack-lab-source-evidence','UTF8'),'sha256'),512,transaction_timestamp()-interval '5 seconds')
ON CONFLICT DO NOTHING;
SELECT zasp_attack_lab_register_credential_binding('${organizationID}','${workspaceID}','${environmentID}','${attackLabBindingID}','${attackLabTargetID}','${credentialReference}','read_only',1,digest(convert_to('attack-lab-credential-e2e','UTF8'),'sha256'),transaction_timestamp()+interval '1 hour');
`]);

	await reloadBrowser(cdp);
	await selectBrowserOption(cdp, "Authorized scope", "Staging");
	await waitForBrowserSelectedOption(cdp, "Authorized scope", "Staging");
	await navigateBrowser(cdp, `${publicOrigin}/test/attack-lab`);
	await waitForBrowserText(cdp, new RegExp(attackLabSourceRunID));
	assert.equal(await browserHasInteractiveText(cdp, /^Run Attack Lab$/i), true, "Attack Lab production route did not expose the authorized approval action");
	await clickBrowserText(cdp, "Review safety decision");
	const preflight = await waitForBrowserText(cdp, /Reject direct prompt injection/);
	assert.match(preflight, /adapter\.customer\.example/);
	assert.match(preflight, /staging/);
	assert.match(preflight, /read only/);
	assert.match(preflight, /500m CPU/);
	assert.doesNotMatch(preflight, /credential_reference|target_e2e_0001|lease_token/i);
	await clickBrowserAria(cdp, "Approve exact safety decision");
	await clickBrowserText(cdp, "Run Attack Lab");

	let runID = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		runID = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT run_id FROM zasp_attack_lab_runs WHERE (organization_id,workspace_id,environment_id,source_run_id)=('${organizationID}','${workspaceID}','${environmentID}','${attackLabSourceRunID}') ORDER BY queued_at DESC,run_id DESC LIMIT 1;`])).stdout.trim();
		if (/^pid_[0-9a-f-]{36}$/.test(runID)) break;
		await delay(25);
	}
	assert.match(runID, /^pid_[0-9a-f-]{36}$/, "Attack Lab browser approval did not create a durable run");
	const worker = await command(workerE2EBinary, ["-test.run=^TestProductionCombinedE2EAttackLabWorker$", "-test.v", "-test.count=1"], {
		cwd: platform,
		timeout: 60_000,
		env: {
			...process.env,
			ZASP_COMBINED_E2E_ATTACK_LAB_CONTROLLER_DSN: `postgres://zasp_e2e_attack_lab_controller@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_ATTACK_LAB_OUTBOX_DSN: `postgres://zasp_e2e_attack_lab_outbox@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_ATTACK_LAB_RUN_ID: runID,
		},
	});
	assert.match(worker.stdout, /composed Attack Lab outbox and controller completed deterministic isolated sandbox evidence/);
	const completed = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',state,verdict,cleanup_state,attempt,(SELECT count(*) FROM zasp_attack_lab_attempts WHERE run_id='${runID}'),(SELECT count(*) FROM zasp_attack_lab_outbox WHERE payload->>'run_id'='${runID}' AND state='published')) FROM zasp_attack_lab_runs WHERE run_id='${runID}';`])).stdout.trim();
	assert.equal(completed, "complete|verified|complete|1|1|1", "Attack Lab composed workers did not persist one terminal result, cleanup, attempt, and publication");

	await reloadBrowser(cdp);
	await waitForBrowserText(cdp, /verified/);
	await clickBrowserAria(cdp, `Open Attack Lab run ${runID}`);
	const evidence = await waitForBrowserText(cdp, /success criterion observed/);
	assert.match(evidence, /exact destination allowed/);
	assert.match(evidence, /isolated job completed/);
	assert.match(evidence, /Cleanup complete: yes/);
	assert.match(evidence, /Immutable evidence: s3:\/\/zasp-production-e2e-evidence\//);
	assert.match(evidence, /@ version-[0-9a-f]{16}/);
	assert.match(evidence, /sha256:[0-9a-f]{64}/);
	assert.match(evidence, /[1-9][0-9]* bytes/);
	await clickBrowserText(cdp, "Re-run safely");
	let rerunID = "";
	for (let attempt = 0; attempt < 100; attempt += 1) {
		rerunID = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT run_id FROM zasp_attack_lab_runs WHERE source_run_id='${attackLabSourceRunID}' AND run_id<>'${runID}' ORDER BY queued_at DESC,run_id DESC LIMIT 1;`])).stdout.trim();
		if (/^pid_[0-9a-f-]{36}$/.test(rerunID)) break;
		await delay(25);
	}
	assert.match(rerunID, /^pid_[0-9a-f-]{36}$/, "Attack Lab rerun was not durably queued");
	await clickBrowserAria(cdp, `Open Attack Lab run ${rerunID}`);
	await clickBrowserText(cdp, "Cancel run");
	const cancelled = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',state,cancel_requested,cleanup_state,attempt,error_code) FROM zasp_attack_lab_runs WHERE run_id='${rerunID}';`])).stdout.trim();
	assert.equal(cancelled, "cancelled|t|complete|0|cancelled", "Attack Lab queued cancellation did not terminalize without a sandbox");
	const cancelledWorker = await command(workerE2EBinary, ["-test.run=^TestProductionCombinedE2EAttackLabWorker$", "-test.v", "-test.count=1"], {
		cwd: platform,
		timeout: 60_000,
		env: {
			...process.env,
			ZASP_COMBINED_E2E_ATTACK_LAB_CONTROLLER_DSN: `postgres://zasp_e2e_attack_lab_controller@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_ATTACK_LAB_OUTBOX_DSN: `postgres://zasp_e2e_attack_lab_outbox@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_ATTACK_LAB_RUN_ID: rerunID,
			ZASP_COMBINED_E2E_ATTACK_LAB_EXPECT_CANCELLED: "true",
		},
	});
	assert.match(cancelledWorker.stdout, /acknowledged cancelled run without sandbox side effects/);
	const cancelledPublication = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',state,(SELECT count(*) FROM zasp_attack_lab_attempts WHERE run_id='${rerunID}'),(SELECT count(*) FROM zasp_attack_lab_outbox WHERE payload->>'run_id'='${rerunID}' AND state='published')) FROM zasp_attack_lab_runs WHERE run_id='${rerunID}';`])).stdout.trim();
	assert.equal(cancelledPublication, "cancelled|0|1", "Attack Lab cancelled delivery did not ACK terminally without a sandbox attempt");
	await reloadBrowser(cdp);
	const reloaded = await waitForBrowserText(cdp, new RegExp(rerunID));
	assert.match(reloaded, /verified/);
	assert.match(reloaded, /cancelled/);
	assert.doesNotMatch(reloaded, /ref:red-team|lease_token|controller_id|credential_binding/i);
	await selectBrowserOption(cdp, "Authorized scope", "Production");
	await waitForBrowserSelectedOption(cdp, "Authorized scope", "Production");
	console.log("combined E2E: production Attack Lab preflight, explicit approval, composed outbox/controller, isolated evidence, cleanup, rerun, cancellation, and reload proven");
}

async function runProductionRecoveryLifecycle(cdp, agentsecctl, workerE2EBinary, postgresPort, dsn, publicOrigin, certificate, credentialFile, expectedScope) {
	const backupID = "pid_7e000001-0000-4000-8000-000000000001";
	const backupIdempotencyKey = "recovery-backup-production-e2e-0001";
	const artifactFile = path.join(temporaryRoot, "recovery-artifacts.json");
	const manifestFile = path.join(temporaryRoot, "recovery-manifest.json");
	const recoveryOrigin = new URL(publicOrigin);
	recoveryOrigin.hostname = recoveryHostname;
	const common = ["--endpoint", recoveryOrigin.origin, "--credential-file", credentialFile, "--ca-bundle-file", certificate, "--timeout", "10s"];
	const backupStart = ["backup", "start", ...common, "--backup-id", backupID, "--retention-days", "30", "--idempotency-key", backupIdempotencyKey, "--if-match", '"0"'];
	const backupStartResult = await command(agentsecctl, backupStart, { reject: false });
	assert.notEqual(backupStartResult.status, 0, "committed recovery backup response was not lost");
	assert.equal(backupStartResult.stdout.trim(), "", "lost recovery backup response exposed a result");
	const replayResult = await command(agentsecctl, backupStart, { reject: false });
	if (replayResult.status !== 0) throw new Error(`recovery CLI backup replay failed: ${JSON.stringify(recoveryAPIResponses.slice(-4))}`);
	const created = JSON.parse(replayResult.stdout);
	const stableReplayResult = await command(agentsecctl, backupStart, { reject: false });
	if (stableReplayResult.status !== 0) throw new Error(`recovery CLI stable backup replay failed: ${JSON.stringify(recoveryAPIResponses.slice(-4))}`);
	const replayed = JSON.parse(stableReplayResult.stdout);
	assert.deepEqual(replayed, created, "same recovery idempotency key replayed a different backup result");
	assert.equal(created.id, backupID);
	assert.equal(created.state, "queued");
	assert.equal(new Set(recoveryBackupRequestKeys).size, 1, "lost recovery response retry changed its idempotency key");
	const replayCounts = (await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_recovery_backups WHERE backup_id='${backupID}'),
    (SELECT count(*) FROM zasp_recovery_outbox WHERE topic='recovery-backup-jobs' AND payload->>'backup_id'='${backupID}'),
    (SELECT count(*) FROM zasp_recovery_audit WHERE event_kind='recovery_backup_requested' AND resource_id='${backupID}'),
    (SELECT count(*) FROM zasp_recovery_request_receipts WHERE operation='startRecoveryBackup' AND idempotency_key='${backupIdempotencyKey}');`])).stdout.trim();
	assert.equal(replayCounts, "1|1|1|1", "lost recovery response created duplicate durable authority");
	console.log("combined E2E: committed recovery response loss replayed one backup, outbox, audit, and receipt");

	const workerEnvironment = {
		...process.env,
		ZASP_COMBINED_E2E_RECOVERY_PHASE: "backup",
		ZASP_COMBINED_E2E_RECOVERY_WORKER_DSN: `postgres://zasp_e2e_recovery@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
		ZASP_COMBINED_E2E_RECOVERY_OUTBOX_DSN: `postgres://zasp_e2e_recovery_outbox@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
		ZASP_COMBINED_E2E_RECOVERY_ARTIFACT_FILE: artifactFile,
	};
	const backupWorker = await command(workerE2EBinary, ["-test.run", "^TestProductionCombinedE2ERecoveryWorker$", "-test.v", "-test.count=1"], { env: workerEnvironment, timeout: 60_000 });
	assert.match(backupWorker.stdout, /signed recovery manifest published last/);
	const backup = JSON.parse((await command(agentsecctl, ["backup", "get", ...common, "--backup-id", backupID])).stdout);
	assert.equal(backup.state, "succeeded");
	assert.equal(backup.manifest.schema, "recovery_signed_manifest_v1");
	await writeFile(manifestFile, JSON.stringify(backup.manifest), { mode: 0o600 });
	await chmod(manifestFile, 0o600);
	console.log("combined E2E: signed recovery manifest published last");

	await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_product_sessions SET authenticated_at=transaction_timestamp(),permissions='["view","manage_workflows","manage_findings","manage_identity"]'::jsonb WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
	await navigateBrowser(cdp, `${publicOrigin}/administration/recovery`);
	await waitForBrowserAction(cdp, `location.origin === ${JSON.stringify(publicOrigin)} && location.pathname === "/administration/recovery" && document.readyState !== "loading"`);
	const retainedRecoveryState = JSON.stringify({ version: 1, backup: { id: backupID, retention_days: 30, idempotency_key: backupIdempotencyKey }, restore: null });
	const storedRecoveryState = await cdp.send("Runtime.evaluate", { expression: `(() => { const key = ${JSON.stringify(`zasp:recovery:v1:${expectedScope}`)}; const value = ${JSON.stringify(retainedRecoveryState)}; sessionStorage.setItem(key, value); return sessionStorage.getItem(key) === value; })()`, returnByValue: true });
	assert.equal(storedRecoveryState.exceptionDetails, undefined, "recovery session state storage raised a browser exception");
	assert.equal(storedRecoveryState.result?.value, true, "recovery session state was not retained in the loaded product document");
	await reloadBrowser(cdp);
	await waitForBrowserText(cdp, /Backup succeeded/);
	await reloadBrowser(cdp);
	await waitForBrowserText(cdp, /Backup succeeded/);
	await cdp.send("Runtime.evaluate", { expression: "window.confirm = () => true", returnByValue: true });
	await clickBrowserText(cdp, "Start restore rehearsal");
	await waitForBrowserAction(cdp, `(() => { try { return JSON.parse(sessionStorage.getItem(${JSON.stringify(`zasp:recovery:v1:${expectedScope}`)})).restore?.id?.startsWith('pid_') === true; } catch { return false; } })()`);
	const retained = await cdp.send("Runtime.evaluate", { expression: `JSON.parse(sessionStorage.getItem(${JSON.stringify(`zasp:recovery:v1:${expectedScope}`)}))`, returnByValue: true });
	const restoreID = retained.result?.value?.restore?.id;
	assert.match(restoreID, /^pid_[0-9a-f-]{36}$/);
	await waitForBrowserText(cdp, /Restore queued/);

	const restoreWorker = await command(workerE2EBinary, ["-test.run", "^TestProductionCombinedE2ERecoveryWorker$", "-test.v", "-test.count=1"], { env: { ...workerEnvironment, ZASP_COMBINED_E2E_RECOVERY_PHASE: "restore" }, timeout: 60_000 });
	assert.match(restoreWorker.stdout, /local TLS Neon fixture, exact projection counts, and temporary resource cleanup completed/);
	const restore = JSON.parse((await command(agentsecctl, ["restore", "get", ...common, "--restore-id", restoreID])).stdout);
	assert.equal(restore.state, "succeeded");
	assert.deepEqual(restore.observed_counts, restore.validation_evidence.expected_counts);
	assert.equal(restore.cleanup_evidence.state, "deleted");
	await waitForBrowserText(cdp, /Restore succeeded/);
	await waitForBrowserText(cdp, /Temporary resources deleted/);
	await reloadBrowser(cdp);
	const recovered = await waitForBrowserText(cdp, /Restore succeeded/);
	assert.match(recovered, /Temporary resources deleted/);

	const foreignBackupID = "pid_9e000001-0000-4000-8000-000000000001";
	const foreign = await requestHTTPSJSON(`${recoveryOrigin.origin}/api/v1/recovery/backups`, { method: "POST", headers: { authorization: "Bearer production-e2e-foreign-recovery-token-with-at-least-32-bytes", "content-type": "application/json", "idempotency-key": "foreign-recovery-backup-e2e-0001", "if-match": '"0"' } }, JSON.stringify({ backup_id: foreignBackupID, retention_days: 30 }));
	assert.equal(foreign.status, 202, `foreign recovery fixture failed: ${JSON.stringify(foreign)}`);
	const rejected = await requestHTTPSJSON(`${recoveryOrigin.origin}/api/v1/recovery/backups/${foreignBackupID}`, { method: "GET", headers: { authorization: "Bearer production-e2e-product-token-with-at-least-32-bytes" } });
	assert.equal(rejected.status, 404, "cross-tenant recovery read rejected with a distinguishable response");
	console.log("combined E2E: cross-tenant recovery read rejected");

	const forensics = JSON.stringify(await browserStorageHistoryAndCaches(cdp));
	assert.doesNotMatch(forensics, /s3:\/\/|arn:aws:kms|recovery-artifacts\.json|recovery-api-token|postgres:\/\//i, "recovery browser state retained private recovery authority");
	console.log("combined E2E: Recovery rehearsal completed; Temporary resources deleted");
	console.log("combined E2E: live Neon/AWS/S3/KMS/Kubernetes recovery remains NOT RUN");
}

async function runConnectorRevocationProviderWorker(workerE2EBinary, postgresPort, integrationID) {
	assert.equal(integrationID, task5GitHubIntegrationID, "unexpected Security Agent connector revocation target");
	const reference = "ref:github/installation/424242";
	const result = await command(workerE2EBinary, ["-test.run=^TestProductionCombinedE2EConnectorRevocationWorker$", "-test.v", "-test.count=1"], {
		cwd: platform,
		timeout: 60_000,
		env: {
			...process.env,
			ZASP_COMBINED_E2E_CONNECTOR_DSN: `postgres://zasp_e2e_api@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_CONNECTOR_INTEGRATION_ID: integrationID,
			ZASP_COMBINED_E2E_CONNECTOR_REFERENCE: reference,
		},
	});
	assert.match(result.stdout, new RegExp(`real connector reconciler revoked exact reference ${reference.replaceAll("/", "\\/")}`));
}

async function runTemporaryPolicyActionWorker(workerE2EBinary, postgresPort, actionPrivateKey, phase, action = { key: "create_temporary_policy", afterSequence: phase === "cleanup" ? 1 : 0 }) {
	const result = await command(workerE2EBinary, ["-test.run=^TestProductionCombinedE2ETemporaryPolicyActionWorker$", "-test.v", "-test.count=1"], {
		cwd: platform,
		timeout: 60_000,
		env: {
			...process.env,
			ZASP_COMBINED_E2E_ACTION_DSN: `postgres://zasp_e2e_security_agent_action@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_POLICY_DEPLOYMENT_DSN: `postgres://zasp_e2e_policy_deployment@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_GATEWAY_DSN: `postgres://zasp_e2e_gateway_control@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_ACTION_PRIVATE_KEY: actionPrivateKey,
			ZASP_COMBINED_E2E_ACTION_PHASE: phase,
			ZASP_COMBINED_E2E_ACTION_KEY: action.key,
			ZASP_COMBINED_E2E_AFTER_SEQUENCE: String(action.afterSequence),
			...(action.sessionID ? { ZASP_COMBINED_E2E_ACTION_SESSION_ID: action.sessionID } : {}),
			...(action.otherSessionID ? { ZASP_COMBINED_E2E_ACTION_OTHER_SESSION_ID: action.otherSessionID } : {}),
		},
	});
	if (phase === "reconcile") assert.match(result.stdout, /connector revocation reconciled through the production action worker/);
	else if (action.key === "isolate_session") assert.match(result.stdout, new RegExp(`central policy deployment signed session isolation gateway policy ${phase} and verified exact target plus unrelated allowance through gateway authority`));
	else assert.match(result.stdout, new RegExp(`central policy deployment signed temporary gateway policy ${phase} and verified through gateway authority`));
}

async function runRuntimeGatewayProxyE2E(gatewayE2EBinary, postgresPort, policyPrivateKey, phase) {
	const result = await command(gatewayE2EBinary, ["-test.run=^TestProductionCombinedE2ERuntimeGatewayProxy$", "-test.v", "-test.count=1"], {
		cwd: path.join(root, "services", "runtime-gateway"),
		timeout: 60_000,
		env: {
			...process.env,
			ZASP_COMBINED_E2E_GATEWAY_DSN: `postgres://zasp_e2e_gateway_control@127.0.0.1:${postgresPort}/postgres?sslmode=disable`,
			ZASP_COMBINED_E2E_GATEWAY_POLICY_PRIVATE_KEY: policyPrivateKey,
			ZASP_COMBINED_E2E_GATEWAY_PHASE: phase,
		},
	});
	assert.match(result.stdout, new RegExp(`composed runtime gateway ${phase} decision survived control outage with durable PostgreSQL event and exact TLS upstream semantics`));
}

function startTask4Worker(workerBinary, environment) {
  const worker = startChild(workerBinary, [], { env: environment });
  task4Workers.push(worker);
  return worker;
}

function startSecurityAgentE2EWorker(workerE2EBinary, environment) {
	const worker = startChild(workerE2EBinary, ["-test.run=^TestProductionCombinedE2ESecurityAgentWorker$", "-test.v", "-test.count=1"], {
		env: { ...environment, ZASP_COMBINED_E2E_SECURITY_AGENT_DSN: environment.ZASP_POSTGRES_DSN },
	});
	task4Workers.push(worker);
	return worker;
}

async function assertReadyTask4Worker(worker, mode) {
  let health;
  let ready;
  try {
    health = await waitForHTTP("http://127.0.0.1:8081/healthz", 200);
    ready = await waitForHTTP("http://127.0.0.1:8081/readyz", 200);
  } catch (error) {
    throw new Error(`${mode} worker startup failed: ${error instanceof Error ? error.message : error}; exit=${worker.exitCode}; signal=${worker.signalCode}; output=${worker.output()}`);
  }
  assert.equal(health.body, '{"status":"live"}\n', `${mode} health response`);
  assert.equal(ready.body, '{"status":"ready"}\n', `${mode} readiness response`);
  assert.match(worker.output(), /agentsec-worker build dev/);
}

async function assertFailClosedTask4Worker(worker, mode) {
  let health;
  let ready;
  try {
    health = await waitForHTTP("http://127.0.0.1:8081/healthz", 200);
    ready = await waitForHTTP("http://127.0.0.1:8081/readyz", 503);
  } catch (error) {
    throw new Error(`${mode} worker startup failed: ${error instanceof Error ? error.message : error}; exit=${worker.exitCode}; signal=${worker.signalCode}; output=${worker.output()}`);
  }
  assert.equal(health.body, '{"status":"live"}\n', `${mode} health response`);
  assert.equal(ready.body, '{"status":"not_ready"}\n', `${mode} readiness response`);
  assert.match(worker.output(), /agentsec-worker build dev/);
}

async function waitForChildExit(child, timeout) {
  if (child.exitCode !== null || child.signalCode !== null) return { status: child.exitCode, signal: child.signalCode };
  const result = await Promise.race([
    once(child, "exit").then(([status, signal]) => ({ status, signal })),
    delay(timeout).then(() => null),
  ]);
  assert.notEqual(result, null, `worker did not exit within ${timeout}ms: ${child.output()}`);
  return result;
}

async function assertPortAvailable(port) {
  const server = net.createServer();
  server.listen({ port, host: "0.0.0.0", exclusive: true });
  await Promise.race([
    once(server, "listening"),
    once(server, "error").then(([error]) => { throw new Error(`Task4 worker port ${port} unavailable: ${error.message}`); }),
  ]);
  await closeServer(server);
}

function assertTask4PublicResponse(response, status, label) {
  assert.equal(response.status, status, `${label} status`);
  assert.equal(response.headers["cache-control"], "no-store", `${label} cache policy`);
  assert.equal(response.headers["referrer-policy"], "no-referrer", `${label} referrer policy`);
  assert.doesNotMatch(JSON.stringify(response.body), /(?:access|refresh|session|web_identity)_token|client_secret|private_key|credential_reference|connection_reference|artifact_(?:key|uri)|cursor_(?:provider|version|value)|"next_cursor":"|worker_(?:id|identity)|lease_(?:owner|token)/i, `${label} exposed private discovery authority`);
}

async function seedCrossScopeConnectorAttempt(dsn, state) {
  const sql = `
INSERT INTO zasp_integrations(organization_id,workspace_id,environment_id,id,kind,connector_version,display_name,configuration,state)
VALUES ('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','pid_71000001-0000-4000-8000-000000000001','github','v1','Cross-scope GitHub witness','{}'::jsonb,'authorizing');
INSERT INTO zasp_connector_oauth_attempts(organization_id,workspace_id,environment_id,id,integration_id,provider,principal_id,session_digest,state_hash,pkce_verifier_reference,request_digest,integration_version,configuration_digest,requested_scopes,expires_at)
SELECT 'pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','pid_71000002-0000-4000-8000-000000000002','pid_71000001-0000-4000-8000-000000000001','github','pid_10000004-0000-4000-8000-000000000004',token_digest,digest('${state}','sha256'),'ref:harness/cross-scope-verifier',digest('cross-scope-request','sha256'),1,digest(convert_to('{}'::jsonb::text,'UTF8'),'sha256'),'["actions:read","contents:read","metadata:read"]'::jsonb,transaction_timestamp()+interval '5 minutes'
FROM zasp_product_sessions WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND revoked_at IS NULL AND expires_at>transaction_timestamp();
`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
}

async function connectorDurableCounts(dsn) {
  const result = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_connector_oauth_attempts),
    (SELECT count(*) FROM zasp_connector_effects),
    (SELECT count(*) FROM zasp_connector_credentials),
    (SELECT count(*) FROM zasp_connector_audit);`]);
  return result.stdout.trim();
}

async function connectorRevocationWitness(dsn, integrationID) {
  assert.ok([terminalRevocationIntegrationID, reloadRevocationIntegrationID].includes(integrationID), "unexpected harness revocation target");
  const result = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-v", "ON_ERROR_STOP=1", "-c", `SELECT concat_ws('|',
    COALESCE((SELECT body->>'status' FROM zasp_workflow_records WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND kind='integration' AND id='${integrationID}' AND deleted_at IS NULL),'missing'),
    COALESCE((SELECT state FROM zasp_integrations WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND id='${integrationID}'),'missing'),
    COALESCE((SELECT operation||':'||status FROM zasp_connector_effects WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND integration_id='${integrationID}' AND operation='revoke'),'missing'),
    COALESCE((SELECT response->'body'->>'status' FROM zasp_workflow_idempotency WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND operation='deleteIntegration' AND response->'body'->>'id'='${integrationID}'),'missing'),
    COALESCE((SELECT result->>'status' FROM zasp_workflow_receipts WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND operation='deleteIntegration' AND resource_id='${integrationID}'),'missing'),
    COALESCE((SELECT state FROM zasp_integration_connections WHERE organization_id='pid_10000001-0000-4000-8000-000000000001' AND workspace_id='pid_10000002-0000-4000-8000-000000000002' AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND integration_id='${integrationID}'),'missing')
  );`]);
  return result.stdout.trim();
}

async function completeHarnessConnectorRevocation(dsn, integrationID) {
  assert.ok([terminalRevocationIntegrationID, reloadRevocationIntegrationID].includes(integrationID), "unexpected harness completion target");
  const owner = "production-e2e-external-provider-completion";
  const token = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
  // This is an external-provider completion simulation after the real public API has
  // staged an unknown revoke effect. It never calls or claims success from a provider.
  const sql = `
DO $fixture$
DECLARE effect_value text;
BEGIN
  SELECT id INTO STRICT effect_value FROM zasp_connector_effects
  WHERE organization_id='pid_10000001-0000-4000-8000-000000000001'
    AND workspace_id='pid_10000002-0000-4000-8000-000000000002'
    AND environment_id='pid_10000003-0000-4000-8000-000000000003'
    AND integration_id='${integrationID}' AND operation='revoke' AND status='unknown';
  UPDATE zasp_connector_effects SET lease_owner='${owner}',lease_token='${token}',lease_expires_at=transaction_timestamp()+interval '30 seconds',updated_at=transaction_timestamp()
  WHERE organization_id='pid_10000001-0000-4000-8000-000000000001'
    AND workspace_id='pid_10000002-0000-4000-8000-000000000002'
    AND environment_id='pid_10000003-0000-4000-8000-000000000003' AND id=effect_value;
  PERFORM zasp_connector_complete_revocation('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003',effect_value,'${owner}','${token}');
END $fixture$;
SELECT concat_ws('|',
  (SELECT status FROM zasp_connector_effects WHERE integration_id='${integrationID}' AND operation='revoke'),
  (SELECT state FROM zasp_integrations WHERE id='${integrationID}'),
  (SELECT body->>'status' FROM zasp_workflow_records WHERE kind='integration' AND id='${integrationID}'),
  (SELECT state FROM zasp_integration_connections WHERE integration_id='${integrationID}')
);`;
  const result = await command(path.join(postgresBin, "psql"), [dsn, "-qAt", "-v", "ON_ERROR_STOP=1"], { input: sql });
  assert.equal(result.stdout.trim(), "reconciled|deleted|deleted|revoked", "external-provider completion simulation did not atomically terminalize durable revocation");
}

async function seedInvestigationSession(dsn) {
  const sql = `
INSERT INTO zasp_product_sessions(token_digest,csrf_token,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES
(digest('investigation-session-e2e','sha256'),'investigation-csrf-with-at-least-32-bytes','session-investigation-e2e','pid_10000005-0000-4000-8000-000000000005','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view"]'::jsonb,transaction_timestamp()+interval '1 hour');
INSERT INTO zasp_session_events(organization_id,session_id,id,class,label,evidence_id,source,confidence,at) VALUES
('pid_10000001-0000-4000-8000-000000000001','session-investigation-e2e','event-investigation-e2e','tool','Shell requested by E2E','evidence-session-e2e','product-runtime','exact',transaction_timestamp());`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
}

async function seedLaterReceipt(dsn) {
  await seedRecoveryReceipt(dsn, {
    policyID: "policy-second-tab", name: "Second-tab committed policy", idempotencyKey: "second-tab-policy-0001",
    receiptID: "pid_60000001-0000-4000-8000-000000000001", auditID: "pid_60000002-0000-4000-8000-000000000002", correlationID: "pid_60000003-0000-4000-8000-000000000003",
    createdAt: "transaction_timestamp()", expiresAt: "transaction_timestamp() + interval '7 days'",
  });
}

async function seedExpiringReceipt(dsn) {
  await seedRecoveryReceipt(dsn, {
    policyID: "policy-expiry-race", name: "Expiry-race committed policy", idempotencyKey: "expiry-race-policy-0001",
    receiptID: "pid_60000011-0000-4000-8000-000000000011", auditID: "pid_60000012-0000-4000-8000-000000000012", correlationID: "pid_60000013-0000-4000-8000-000000000013",
    createdAt: "transaction_timestamp() - interval '6 days'", expiresAt: "transaction_timestamp() + interval '1 hour'",
  });
}

async function seedRecoveryReceipt(dsn, value) {
  const body = JSON.stringify({ id: value.policyID, name: value.name, scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "read" }], action: "monitor", rollout: "draft", failure_mode: "open" });
  const intent = JSON.stringify({ body: JSON.parse(body), expected_version: 0, resource_id: "" });
  const sql = `
INSERT INTO zasp_workflow_records (organization_id, workspace_id, environment_id, kind, id, body)
VALUES ('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','policy','${value.policyID}','${body}'::jsonb);
INSERT INTO zasp_workflow_idempotency (organization_id, workspace_id, environment_id, principal_id, operation, idempotency_key, request_digest, response)
VALUES ('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_10000004-0000-4000-8000-000000000004','createPolicy','${value.idempotencyKey}',digest('${value.idempotencyKey}','sha256'),jsonb_build_object('body','${body}'::jsonb,'version',1,'secret_generation',0,'audit_id','${value.auditID}','correlation_id','${value.correlationID}','receipt_id','${value.receiptID}'));
INSERT INTO zasp_workflow_audit (organization_id, workspace_id, environment_id, audit_id, correlation_id, principal_id, operation, resource_kind, resource_id, resource_version)
VALUES ('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${value.auditID}','${value.correlationID}','pid_10000004-0000-4000-8000-000000000004','createPolicy','policy','${value.policyID}',1);
INSERT INTO zasp_workflow_receipts (organization_id, workspace_id, environment_id, principal_id, receipt_id, operation, idempotency_key, intent, result, resource_kind, resource_id, resource_version, audit_id, correlation_id, created_at, expires_at)
VALUES ('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_10000004-0000-4000-8000-000000000004','${value.receiptID}','createPolicy','${value.idempotencyKey}','${intent}'::jsonb,'${body}'::jsonb,'policy','${value.policyID}',1,'${value.auditID}','${value.correlationID}',${value.createdAt},${value.expiresAt});`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
}

async function startIdentityServer(port, publicOrigin) {
  const server = http.createServer(async (request, response) => {
    const target = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
    if (request.method === "GET" && target.pathname === "/v1/b2b/public/oauth/google/start") {
      identityOAuthStarts += 1;
      pendingIdentityLogin = nextIdentityLogin;
      assert.equal(target.searchParams.get("public_token"), "public-token-test-local");
      assert.equal(target.searchParams.get("organization_id"), "organization-test-local");
      const callback = new URL(target.searchParams.get("login_redirect_url"));
      assert.equal(callback.origin, publicOrigin);
      assert.equal(callback.pathname, "/auth/callback");
      assert.equal(target.searchParams.get("signup_redirect_url"), callback.toString());
      assert.ok((callback.searchParams.get("state") ?? "").length >= 32);
      callback.searchParams.set("token", pendingIdentityLogin === "group" ? "group-only-oauth-token" : "local-oauth-token");
      response.writeHead(302, { location: callback.toString() });
      response.end();
      return;
    }
    if (request.method === "POST" && target.pathname === "/v1/b2b/oauth/authenticate") {
      assert.equal(request.headers.authorization, `Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`);
      const groupLogin = pendingIdentityLogin === "group";
      assert.deepEqual(JSON.parse(await readBody(request)), { oauth_token: groupLogin ? "group-only-oauth-token" : "local-oauth-token", session_duration_minutes: 60 });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        status_code: 200,
        request_id: groupLogin ? "request-id-group-oauth" : "request-id-test-oauth",
        member_id: groupLogin ? "member-group-e2e" : "member-test-local",
        organization_id: "organization-test-local",
        session_jwt: groupLogin ? "group.header.payload" : "header.payload.signature",
      }));
      return;
    }
    if (request.method === "POST" && target.pathname === "/v1/b2b/sessions/authenticate") {
      assert.equal(request.headers.authorization, `Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`);
      const input = JSON.parse(await readBody(request));
      const groupLogin = input.session_jwt === "group.header.payload";
      assert.ok(groupLogin || input.session_jwt === "header.payload.signature", "unexpected Stytch session JWT");
      const now = new Date();
      const memberReference = groupLogin ? "member-group-e2e" : "member-test-local";
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({
        status_code: 200,
        request_id: groupLogin ? "request-id-group-session" : "request-id-test-session",
        session_jwt: input.session_jwt,
        member_session: {
          member_session_id: groupLogin ? "member-session-group-e2e" : "member-session-test-local",
          member_id: memberReference,
          organization_id: "organization-test-local",
          started_at: now.toISOString(),
          last_accessed_at: now.toISOString(),
          expires_at: new Date(now.getTime() + 3_600_000).toISOString(),
        },
        member: {
          member_id: memberReference,
          organization_id: "organization-test-local",
          scim_registration: { scim_attributes: { groups: groupLogin ? [{ value: identityGroupReference, display: "Production readers" }] : [] } },
        },
      }));
      return;
    }
    if (target.pathname.startsWith("/v1/b2b/")) {
      assert.equal(request.headers.authorization, `Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`);
      const requestBody = request.method === "GET" ? undefined : JSON.parse(await readBody(request));
      stytchProviderRequests.push({ method: request.method, path: target.pathname, body: requestBody });
      response.setHeader("content-type", "application/json");
      if (request.method === "GET" && target.pathname === "/v1/b2b/sso/organization-test-local") {
        response.end(JSON.stringify({ status_code: 200, request_id: "request-list-sso-e2e", saml_connections: stytchSSOConnections, oidc_connections: [] }));
        return;
      }
      if (request.method === "POST" && target.pathname === "/v1/b2b/sso/saml/organization-test-local") {
        assert.deepEqual(requestBody, { display_name: "E2E SSO", identity_provider: "generic" });
        const connection = { organization_id: "organization-test-local", connection_id: "saml-connection-e2e-created", status: "pending", display_name: "E2E SSO", identity_provider: "generic" };
        stytchSSOConnections.push(connection);
        response.end(JSON.stringify({ status_code: 200, request_id: "request-create-sso-e2e", connection }));
        return;
      }
      if (request.method === "GET" && target.pathname === "/v1/b2b/scim/organization-test-local/connection") {
        response.end(JSON.stringify({ status_code: 200, request_id: "request-list-scim-e2e", connection: stytchSCIMConnection ?? null }));
        return;
      }
      if (request.method === "POST" && target.pathname === "/v1/b2b/scim/organization-test-local/connection") {
        assert.deepEqual(requestBody, { display_name: "E2E SCIM", identity_provider: "generic" });
        stytchSCIMConnection = {
          organization_id: "organization-test-local",
          connection_id: "scim-connection-e2e-created",
          status: "active",
          display_name: "E2E SCIM",
          identity_provider: "generic",
          base_url: "https://scim.stytch.com/v2/production-e2e",
          bearer_token: "scim_bearer_token_e2e_only_copy_once",
        };
        response.end(JSON.stringify({ status_code: 200, request_id: "request-create-scim-e2e", connection: stytchSCIMConnection }));
        return;
      }
      response.writeHead(404);
      response.end(JSON.stringify({ status_code: 404 }));
      return;
    }
    response.writeHead(404);
    response.end();
  });
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  return server;
}

async function startPolicyHistoryServer(port) {
	const schemaSource = await readFile(path.join(platform, "runtimeindex", "opensearchdriver", "schema.go"), "utf8");
	const schemaMatch = schemaSource.match(/indexSchemaJSON = `([^`]+)`/);
	assert.ok(schemaMatch, "runtime index schema fixture missing");
	const schemaJSON = schemaMatch[1];
	const mapping = JSON.parse(schemaJSON);
	const mappingDigest = createHash("sha256").update(schemaJSON).digest("hex");
	const documentID = `evt_${"a".repeat(64)}`;
	const server = http.createServer(async (request, response) => {
		const target = new URL(request.url ?? "/", `http://127.0.0.1:${port}`);
		policyHistoryRequests.push({ method: request.method, path: target.pathname });
		if (!String(request.headers.authorization ?? "").startsWith("AWS4-HMAC-SHA256 ")) {
			response.writeHead(403, { "content-type": "application/json" });
			response.end('{"message":"unsigned"}');
			return;
		}
		if (request.method === "GET" && target.pathname === "/zasp-runtime-events-v1/_mapping") {
			response.writeHead(200, { "content-type": "application/json" });
			response.end(JSON.stringify({ "zasp-runtime-events-v1": mapping }));
			return;
		}
		if (request.method === "GET" && target.pathname === "/zasp-runtime-events-v1/_doc/_zasp_schema_v1") {
			response.writeHead(200, { "content-type": "application/json" });
			response.end(JSON.stringify({ _index: "zasp-runtime-events-v1", _id: "_zasp_schema_v1", _version: 1, _seq_no: 0, _primary_term: 1, found: true, _source: { record_type: "schema_marker", schema_version: 1, mapping_digest: `sha256:${mappingDigest}` } }));
			return;
		}
		if (request.method === "POST" && target.pathname === "/zasp-runtime-events-v1/_search") {
			const body = await readBody(request);
			for (const required of ["pid_10000001-0000-4000-8000-000000000001", "pid_10000002-0000-4000-8000-000000000002", "pid_10000003-0000-4000-8000-000000000003", '"event_class":"tool"', '"size":100']) assert.ok(body.includes(required), `policy history query missing ${required}`);
			response.writeHead(200, { "content-type": "application/json" });
			response.end(JSON.stringify({ timed_out: false, hits: { hits: [{ _id: documentID, sort: ["2026-08-28T12:00:00.000Z", documentID], _source: { organization_id: "pid_10000001-0000-4000-8000-000000000001", workspace_id: "pid_10000002-0000-4000-8000-000000000002", environment_id: "pid_10000003-0000-4000-8000-000000000003", record_type: "runtime_event", event_id: "pid_78000004-0000-4000-8000-000000000004", event_class: "tool", action: "write", agent_id: "pid_78000001-0000-4000-8000-000000000001", session_id: "pid_78000005-0000-4000-8000-000000000005", tool_id: "shell", source_event_id: "policy-history-source-1", event_time: "2026-08-28T12:00:00.000Z" } }] } }));
			return;
		}
		response.writeHead(404, { "content-type": "application/json" });
		response.end('{"message":"not found"}');
	});
	server.listen(port, "127.0.0.1");
	await once(server, "listening");
	return server;
}

async function startProxy(port, apiPort, webPort, keyPath, certificatePath, dsn) {
  const server = https.createServer({ key: await readFile(keyPath), cert: await readFile(certificatePath) }, async (request, response) => {
    // The production ingress applies this policy to every route, including middleware rejections.
    response.setHeader("Referrer-Policy", "no-referrer");
    const target = new URL(request.url ?? "/", "https://combined.invalid");
    if (request.method === "GET" && target.pathname === "/connector-oauth-e2e-provider") {
      response.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      response.end("<!doctype html><html><body><h1>Provider authorization harness</h1></body></html>");
      return;
    }
    if (target.pathname.startsWith("/api/")) productAPIRequests.push({ method: request.method, path: target.pathname, host: String(request.headers.host ?? "") });
    const browserTab = String(request.headers["x-zasp-e2e-tab"] ?? "");
    const receiptAcknowledgement = request.method === "POST" && /^\/api\/v1\/workflow-mutation-receipts\/pid_[0-9a-f-]+\/acknowledge$/.test(target.pathname);
    const tokenCreate = request.method === "POST" && target.pathname === "/api/v1/admin/api-tokens";
    const tokenRotate = request.method === "POST" && /^\/api\/v1\/admin\/api-tokens\/pid_[0-9a-f-]+\/rotate$/.test(target.pathname);
    const tokenReveal = request.method === "POST" && /^\/api\/v1\/admin\/api-token-reveal-grants\/pid_[0-9a-f-]+\/reveal$/.test(target.pathname);
    const tokenAcknowledge = request.method === "DELETE" && /^\/api\/v1\/admin\/api-token-reveal-grants\/pid_[0-9a-f-]+$/.test(target.pathname);
		const integrationDeleteID = request.method === "DELETE" && /^\/api\/v1\/integrations\/pid_[0-9a-f-]+$/.test(target.pathname) ? target.pathname.split("/").at(-1) : undefined;
    const findingTicketRequest = request.method === "POST" && /^\/api\/v1\/findings\/pid_[0-9a-f-]+\/ticket$/.test(target.pathname);
    const integrationWebhookTest = request.method === "POST" && /^\/api\/v1\/integrations\/pid_[0-9a-f-]+\/test-delivery$/.test(target.pathname)
      ? { body: "", idempotencyKey: String(request.headers["idempotency-key"] ?? ""), ifMatch: String(request.headers["if-match"] ?? ""), csrf: String(request.headers["x-csrf-token"] ?? ""), status: 0, auditID: "" } : null;
    if (integrationWebhookTest) request.on("data", (chunk) => { if (integrationWebhookTest.body.length < 1024) integrationWebhookTest.body += chunk; });
		const recoveryBackupRequest = request.method === "POST" && target.pathname === "/api/v1/recovery/backups";
		const securityAgentApprovalRequest = request.method === "POST" && /^\/api\/v1\/security-agent-approvals\/pid_[0-9a-f-]+\/decision$/.test(target.pathname);
    const connectorAuthorizationRequest = request.method === "POST" && target.pathname === `/api/v1/integrations/${terminalRevocationIntegrationID}/authorize` && String(request.headers.cookie ?? "").includes("__Host-zasp_session=");
    if (tokenCreate) tokenMutationKeys.create.push(String(request.headers["idempotency-key"] ?? ""));
    if (tokenRotate) tokenMutationKeys.rotate.push(String(request.headers["idempotency-key"] ?? ""));
		if (recoveryBackupRequest) recoveryBackupRequestKeys.push(String(request.headers["idempotency-key"] ?? ""));
    if (request.method === "GET" && target.pathname === "/api/v1/policies") workflowPageRequests.policies.push(target.search);
    if (request.method === "GET" && target.pathname === "/api/v1/integrations") workflowPageRequests.integrations.push(target.search);
    if (request.method === "GET" && target.pathname === "/api/v1/findings") riskPageRequests.findings.push(target.search);
    if (request.method === "GET" && target.pathname === "/api/v1/attack-paths") riskPageRequests.attackPaths.push(target.search);
    const findingRecoveryRefetch = request.method === "GET" && target.pathname === "/api/v1/findings/pid_30000001-0000-4000-8000-000000000001";
    const riskDetailKind = request.method === "GET" && target.pathname === "/api/v1/attack-paths/pid_40000001-0000-4000-8000-000000000001" ? "path"
      : request.method === "GET" && target.pathname === "/api/v1/attack-paths/pid_40000001-0000-4000-8000-000000000001/break-options" ? "options" : undefined;
    if (findingTicketRequest) {
      const body = await readBody(request);
      findingTicketRequests.push({
        body,
        contentType: String(request.headers["content-type"] ?? ""),
        csrf: String(request.headers["x-csrf-token"] ?? ""),
        expectedScope: String(request.headers["x-zasp-expected-scope"] ?? ""),
        idempotencyKey: String(request.headers["idempotency-key"] ?? ""),
        ifMatch: String(request.headers["if-match"] ?? ""),
        origin: String(request.headers.origin ?? ""),
        operation: findingTicketOperation,
      });
      if (loseNextFindingTicketResponse) {
        loseNextFindingTicketResponse = false;
        response.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
        response.end(JSON.stringify({ code: "dependency_unavailable", message: "Injected finding ticket response loss", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }));
      } else {
        response.writeHead(201, { "content-type": "application/json", "cache-control": "no-store" });
        response.end(JSON.stringify({ ticket_id: "SEC-E2E-0001" }));
      }
      return;
    }
    if (connectorAuthorizationRequest) {
      connectorAuthorizationRequests.push({
        body: await readBody(request),
        contentType: String(request.headers["content-type"] ?? ""),
        csrf: String(request.headers["x-csrf-token"] ?? ""),
        expectedScope: String(request.headers["x-zasp-expected-scope"] ?? ""),
        idempotencyKey: String(request.headers["idempotency-key"] ?? ""),
        origin: String(request.headers.origin ?? ""),
      });
      if (loseNextConnectorAuthorizationResponse) {
        loseNextConnectorAuthorizationResponse = false;
        response.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
        response.end(JSON.stringify({ code: "dependency_unavailable", message: "Injected OAuth response loss", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }));
      } else {
        response.writeHead(200, { "content-type": "application/json", "cache-control": "no-store", "referrer-policy": "no-referrer" });
        response.end(JSON.stringify({ authorization_attempt_id: "pid_70000002-0000-4000-8000-000000000002", authorization_url: `https://${productHostname}:${port}/connector-oauth-e2e-provider`, expires_at: new Date(Date.now() + 10 * 60_000).toISOString() }));
      }
      return;
    }
    if (findingRecoveryRefetch && failNextRiskRecoveryRefetch) {
      failNextRiskRecoveryRefetch = false;
      riskRecoverySequence.push("GET:503");
      response.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
      response.end(JSON.stringify({ code: "dependency_unavailable", message: "Injected authoritative refetch failure", retryable: true, correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee" }));
      return;
    }
    if (receiptAcknowledgement && expireNextReceiptBeforeAcknowledgement) {
      expireNextReceiptBeforeAcknowledgement = false;
      try {
        const receiptID = target.pathname.split("/").at(-2);
        await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_workflow_receipts SET expires_at = transaction_timestamp() - interval '1 minute' WHERE receipt_id = '${receiptID}';`]);
      } catch (error) {
        proxyFailure = error;
        response.writeHead(502); response.end("receipt expiry injection failed"); return;
      }
    }
		const upstreamPort = request.url?.startsWith("/api/v1/") ? apiPort : webPort;
		const inboundHost = String(request.headers.host ?? "");
		const upstreamHost = inboundHost === `${recoveryHostname}:${port}` ? `${productHostname}:${port}` : inboundHost;
		const upstreamHeaders = {
			...request.headers,
			host: upstreamHost,
			"x-forwarded-for": "127.0.0.1",
			"x-forwarded-host": upstreamHost,
      "x-forwarded-port": String(port),
      "x-forwarded-proto": "https",
    };
    delete upstreamHeaders["x-zasp-e2e-tab"];
		const upstream = http.request({ hostname: "127.0.0.1", port: upstreamPort, method: request.method, path: request.url, headers: upstreamHeaders }, (upstreamResponse) => {
      if (integrationWebhookTest) {
        integrationWebhookTest.status = upstreamResponse.statusCode ?? 0;
        integrationWebhookTest.auditID = String(upstreamResponse.headers["x-audit-id"] ?? "");
        integrationWebhookTestRequests.push(integrationWebhookTest);
        const loseResponse = integrationWebhookTestRequests.length === 1 && upstreamResponse.statusCode === 200;
        if (loseResponse) {
          upstreamResponse.resume();
          upstreamResponse.once("end", () => {
            response.writeHead(503, { "content-type": "application/json", "cache-control": "no-store" });
            response.end(JSON.stringify({ code: "dependency_unavailable", message: "Injected webhook response loss after durable completion", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }));
          });
          return;
        }
      }
		if (target.pathname.startsWith("/api/v1/recovery/")) recoveryAPIResponses.push({ method: request.method, path: target.pathname, status: upstreamResponse.statusCode ?? 0, contentType: String(upstreamResponse.headers["content-type"] ?? ""), cacheControl: String(upstreamResponse.headers["cache-control"] ?? ""), etag: String(upstreamResponse.headers.etag ?? ""), audit: String(upstreamResponse.headers["x-audit-id"] ?? ""), receipt: String(upstreamResponse.headers["x-mutation-receipt-id"] ?? "") });
		const securityAgentApprovalResponse = securityAgentApprovalRequest ? { path: target.pathname, status: upstreamResponse.statusCode ?? 0, idempotencyKey: String(request.headers["idempotency-key"] ?? ""), ifMatch: String(request.headers["if-match"] ?? ""), fresh: String(request.headers["x-zasp-fresh-auth"] ?? ""), audit: String(upstreamResponse.headers["x-audit-id"] ?? ""), receipt: String(upstreamResponse.headers["x-mutation-receipt-id"] ?? ""), errorBody: "" } : undefined;
		if (securityAgentApprovalResponse) securityAgentApprovalResponses.push(securityAgentApprovalResponse);
		if (recoveryBackupRequest && loseNextRecoveryBackupResponse && upstreamResponse.statusCode === 202) {
			loseNextRecoveryBackupResponse = false;
			upstreamResponse.resume();
			upstreamResponse.once("end", () => response.destroy());
			return;
		}
      if (integrationDeleteID) {
        integrationDeleteRequests.push({
          id: integrationDeleteID,
          idempotencyKey: String(request.headers["idempotency-key"] ?? ""),
          ifMatch: String(request.headers["if-match"] ?? ""),
          status: upstreamResponse.statusCode ?? 0,
          etag: String(upstreamResponse.headers.etag ?? ""),
          auditID: String(upstreamResponse.headers["x-audit-id"] ?? ""),
          receiptID: String(upstreamResponse.headers["x-mutation-receipt-id"] ?? ""),
          retryAfter: String(upstreamResponse.headers["retry-after"] ?? ""),
          cacheControl: String(upstreamResponse.headers["cache-control"] ?? ""),
          contentType: String(upstreamResponse.headers["content-type"] ?? ""),
          contentLength: String(upstreamResponse.headers["content-length"] ?? ""),
        });
        if (integrationDeleteID === terminalRevocationIntegrationID && malformNextIntegrationDeleteResponse && upstreamResponse.statusCode === 202) {
          malformNextIntegrationDeleteResponse = false;
          upstreamResponse.resume();
          upstreamResponse.once("end", () => {
            response.writeHead(202, { ...upstreamResponse.headers, "content-type": "application/json", "cache-control": "no-store" });
            response.end("{}");
          });
          return;
        }
      }
      if (findingRecoveryRefetch) riskRecoverySequence.push(`GET:${upstreamResponse.statusCode}`);
      if (receiptAcknowledgement) riskRecoverySequence.push(`POST:${upstreamResponse.statusCode}`);
      if (riskDetailKind && delayRiskDetailResponses) {
        captureRiskDetailResponse(riskDetailKind, response, upstreamResponse);
        return;
      }
      if (/^\/api\/v1\/(?:admin|organization|workspaces|environments|sessions|audit-events|compliance|settings|system)\b/.test(target.pathname)) {
        const record = { method: request.method, path: target.pathname, status: upstreamResponse.statusCode, cacheControl: String(upstreamResponse.headers["cache-control"] ?? "") };
        administrationRequests.push(record);
        if ((upstreamResponse.statusCode ?? 500) >= 400) {
          let errorBody = "";
          upstreamResponse.on("data", (chunk) => { if (errorBody.length < 2_048) errorBody += chunk; });
          upstreamResponse.once("end", () => { record.errorBody = errorBody.slice(0, 2_048); });
        }
      }
      if (target.pathname.startsWith("/api/v1/session/")) response.once("finish", () => { scopeOverlapProof.events.push(`${browserTab || "untagged"}:${request.socket.remotePort}:${request.method}:${target.pathname}:finished`); });
      if ((upstreamResponse.headers["set-cookie"] ?? []).some((value) => value.startsWith("__Host-zasp_session="))) observedSessionCookie = true;
      if (target.pathname.startsWith("/api/v1/session/") || upstreamResponse.statusCode === 409) scopeOverlapProof.events.push(`${browserTab || "untagged"}:${request.socket.remotePort}:${request.method}:${target.pathname}:${upstreamResponse.statusCode}`);
		if (securityAgentApprovalResponse && (upstreamResponse.statusCode ?? 500) >= 400) {
			const chunks = [];
			let bytes = 0;
			upstreamResponse.on("data", (chunk) => {
				if (bytes >= 2_048) return;
				const bounded = chunk.subarray(0, 2_048 - bytes);
				chunks.push(bounded);
				bytes += bounded.length;
			});
			upstreamResponse.once("end", () => {
				securityAgentApprovalResponse.errorBody = Buffer.concat(chunks).toString("utf8");
				response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
				response.end(securityAgentApprovalResponse.errorBody);
			});
			return;
		}
      if (browserTab === "first" && upstreamResponse.statusCode === 409) scopeOverlapProof.firstTabScopeStaleResponses += 1;
      if (browserTab === "second" && target.pathname === "/api/v1/session/bootstrap" && scopeOverlapProof.delayedFirstTabBootstrap && !scopeOverlapProof.delayedFirstTabBootstrap.released) {
        scopeOverlapProof.secondTabBootstrapWhileFirstDelayed = true;
      }
      if (browserTab === "first" && target.pathname === "/api/v1/session/bootstrap" && scopeOverlapProof.delayNextFirstTabBootstrap) {
        scopeOverlapProof.delayNextFirstTabBootstrap = false;
        captureDelayedFirstTabBootstrap(response, upstreamResponse);
        return;
      }
      const lostTokenKind = tokenCreate ? "create" : tokenRotate ? "rotate" : tokenReveal ? "reveal" : tokenAcknowledge ? "acknowledge" : undefined;
      const successfulTokenStatus = lostTokenKind === "create" || lostTokenKind === "rotate" ? upstreamResponse.statusCode === 201
        : lostTokenKind === "reveal" ? upstreamResponse.statusCode === 200
        : lostTokenKind === "acknowledge" ? upstreamResponse.statusCode === 204 : false;
      if (lostTokenKind && lostTokenResponses[lostTokenKind] && successfulTokenStatus) {
        lostTokenResponses[lostTokenKind] = false;
        upstreamResponse.resume();
        upstreamResponse.once("end", () => {
          response.writeHead(502, { "content-type": "application/json", "cache-control": "no-store" });
          response.end(JSON.stringify({ code: "dependency_unavailable", message: "Request could not be completed", correlation_id: "pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", retryable: true }));
        });
        return;
      }
      if (request.method === "PATCH" && /^\/api\/v1\/findings\/pid_[0-9a-f-]+$/.test(target.pathname) && !request.headers.authorization && loseNextFindingResponse && upstreamResponse.statusCode === 200) {
        loseNextFindingResponse = false;
        lostFindingResponseKeys.push(String(request.headers["idempotency-key"] ?? ""));
        upstreamResponse.resume();
        upstreamResponse.once("end", () => {
          response.writeHead(200, { ...upstreamResponse.headers, "content-type": "application/json", "cache-control": "no-store" });
          response.end("{}");
        });
        return;
      }
      if (request.method === "POST" && request.url === "/api/v1/policies" && !request.headers.authorization && lostPolicyResponseKeys.length < 2) {
        lostPolicyResponseKeys.push(String(request.headers["idempotency-key"] ?? ""));
        upstreamResponse.resume();
        upstreamResponse.once("end", () => {
          response.writeHead(upstreamResponse.statusCode ?? 201, { "content-type": "application/json", "cache-control": "no-store" });
          response.end("{}");
        });
        return;
      }
      if (request.method === "POST" && request.url === "/api/v1/policies" && !request.headers.authorization) lostPolicyResponseKeys.push(String(request.headers["idempotency-key"] ?? ""));
      if (receiptAcknowledgement && injectLaterReceiptOnNextAcknowledgement && upstreamResponse.statusCode === 204) {
        injectLaterReceiptOnNextAcknowledgement = false;
        upstreamResponse.resume();
        upstreamResponse.once("end", async () => {
          try {
            await seedLaterReceipt(dsn);
            response.writeHead(204, upstreamResponse.headers);
            response.end();
          } catch (error) {
            proxyFailure = error;
            response.writeHead(502); response.end("later receipt injection failed");
          }
        });
        return;
      }
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    });
    upstream.on("error", () => { response.writeHead(502); response.end("upstream unavailable"); });
      request.pipe(upstream);
  });
  server.listen(port, "127.0.0.1");
  await once(server, "listening");
  return server;
}

function captureDelayedFirstTabBootstrap(response, upstreamResponse) {
  assert.equal(scopeOverlapProof.delayedFirstTabBootstrap, undefined);
  const delayedFirstTabBootstrap = {
    body: undefined,
    headers: upstreamResponse.headers,
    ready: false,
    released: false,
    response,
    status: upstreamResponse.statusCode ?? 502,
  };
  scopeOverlapProof.delayedFirstTabBootstrap = delayedFirstTabBootstrap;
  const chunks = [];
  upstreamResponse.on("data", (chunk) => { chunks.push(chunk); });
  upstreamResponse.once("end", () => {
    delayedFirstTabBootstrap.body = Buffer.concat(chunks);
    delayedFirstTabBootstrap.ready = true;
  });
}

function releaseDelayedFirstTabBootstrap() {
  const delayedFirstTabBootstrap = scopeOverlapProof.delayedFirstTabBootstrap;
  assert.ok(delayedFirstTabBootstrap?.ready, "delayed first-tab bootstrap was not ready");
  assert.equal(delayedFirstTabBootstrap.released, false, "delayed first-tab bootstrap was released twice");
  delayedFirstTabBootstrap.released = true;
  delayedFirstTabBootstrap.response.writeHead(delayedFirstTabBootstrap.status, delayedFirstTabBootstrap.headers);
  delayedFirstTabBootstrap.response.end(delayedFirstTabBootstrap.body);
}

function captureRiskDetailResponse(kind, response, upstreamResponse) {
  const captured = { body: undefined, closed: false, headers: upstreamResponse.headers, kind, ready: false, released: false, response, status: upstreamResponse.statusCode ?? 502 };
  delayedRiskDetailResponses.push(captured);
  const chunks = [];
  response.once("close", () => { if (!response.writableEnded) captured.closed = true; });
  upstreamResponse.on("data", (chunk) => { chunks.push(chunk); });
  upstreamResponse.once("end", () => {
    captured.body = Buffer.concat(chunks);
    captured.ready = true;
  });
}

function releaseRiskDetailResponse(kind, override = {}) {
  const captured = delayedRiskDetailResponses.find((entry) => entry.kind === kind && !entry.released);
  assert.ok(captured?.ready, `delayed ${kind} response was not ready`);
  captured.released = true;
  if (captured.closed || captured.response.destroyed) return;
  const headers = override.headers ?? (override.status ? { "content-type": "application/json", "cache-control": "no-store" } : captured.headers);
  captured.response.writeHead(override.status ?? captured.status, headers);
  captured.response.end(override.body ?? captured.body);
}

async function startBrowser(profile, port, target) {
  const child = startChild(chrome, ["--headless=new", "--no-first-run", "--disable-background-networking", "--disable-component-update", "--ignore-certificate-errors", `--host-resolver-rules=MAP ${productHostname} 127.0.0.1`, `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, target]);
  let page;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    try {
      const pages = await fetch(`http://127.0.0.1:${port}/json/list`).then((response) => response.json());
      page = pages.find((value) => value.type === "page" && value.webSocketDebuggerUrl);
      if (page) break;
    } catch {
      page = undefined;
    }
    await delay(50);
  }
  if (!page) throw new Error(`browser debugging endpoint unavailable: ${child.output()}`);
  const version = await fetch(`http://127.0.0.1:${port}/json/version`).then((response) => response.json());
  assert.ok(version.webSocketDebuggerUrl);
  const browserCDP = await connectCDP(version.webSocketDebuggerUrl);
  const cdp = await attachToBrowserTarget(browserCDP, page.id);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Log.enable");
  cdp.on("Runtime.exceptionThrown", (parameters) => browserConsoleErrors.push({ kind: "exception", text: parameters.exceptionDetails?.text ?? "unknown exception" }));
  cdp.on("Runtime.consoleAPICalled", (parameters) => {
    const text = parameters.args?.map((argument) => argument.value ?? argument.description ?? "").join(" ") ?? "";
    browserConsoleMessages.push({ kind: parameters.type, text });
    if (parameters.type === "error" || parameters.type === "assert") browserConsoleErrors.push({ kind: parameters.type, text });
  });
  cdp.on("Log.entryAdded", (parameters) => {
    if (parameters.entry?.level === "error" && parameters.entry?.source === "javascript") browserConsoleErrors.push({ kind: "log", text: parameters.entry.text });
  });
  return { child, cdp };
}

async function startBrowserTab(port, target, sessionCookie) {
  const version = await fetch(`http://127.0.0.1:${port}/json/version`).then((response) => response.json());
  assert.ok(version.webSocketDebuggerUrl);
  const browserCDP = await connectCDP(version.webSocketDebuggerUrl);
  const context = await browserCDP.send("Target.createBrowserContext");
  const created = await browserCDP.send("Target.createTarget", { url: "about:blank", browserContextId: context.browserContextId });
  let page;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const pages = await fetch(`http://127.0.0.1:${port}/json/list`).then((response) => response.json());
    page = pages.find((value) => value.id === created.targetId && value.webSocketDebuggerUrl);
    if (page) break;
    await delay(25);
  }
  assert.ok(page, "isolated browser tab debugging endpoint unavailable");
  assert.equal(page.type, "page");
  assert.ok(page.webSocketDebuggerUrl);
  const cdp = await attachToBrowserTarget(browserCDP, created.targetId, context.browserContextId);
  await cdp.send("Page.enable");
  await cdp.send("Runtime.enable");
  await cdp.send("Network.enable");
  const stored = await cdp.send("Network.setCookie", {
    name: sessionCookie.name,
    value: sessionCookie.value,
    url: target,
    httpOnly: true,
    secure: true,
    sameSite: sessionCookie.sameSite,
  });
  assert.equal(stored.success, true, "shared session cookie was not installed in the isolated tab");
  await navigateBrowser(cdp, target);
  let disposed = false;
  cdp.dispose = async () => {
    if (disposed) return;
    disposed = true;
    try { await browserCDP.send("Target.disposeBrowserContext", { browserContextId: context.browserContextId }); } finally { browserCDP.close(); }
  };
  return cdp;
}

async function getBrowserSessionCookie(cdp, origin) {
  await cdp.send("Network.enable");
  const cookies = await cdp.send("Network.getCookies", { urls: [origin] });
  const sessionCookie = cookies.cookies.find((cookie) => cookie.name === "__Host-zasp_session");
  assert.ok(sessionCookie, "signed-in Chrome tab did not retain the product session cookie");
  return sessionCookie;
}

async function setBrowserTabHeader(cdp, value) {
  await cdp.send("Network.enable");
  await cdp.send("Network.setExtraHTTPHeaders", { headers: { "X-Zasp-E2E-Tab": value } });
}

async function browserBodyText(cdp) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: "document.body ? document.body.innerText : ''", returnByValue: true });
  return evaluated.result?.value ?? "";
}

async function browserCurrentURL(cdp) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: "location.href", returnByValue: true });
  return String(evaluated.result?.value ?? "");
}

async function assertTask4BrowserPublicState(cdp, publicOrigin, syncID) {
  await navigateBrowser(cdp, `${publicOrigin}/connectors`);
  await waitForBrowserText(cdp, /Harness AWS discovery/);
  await clickBrowserAria(cdp, "Open Harness AWS discovery");
  await waitForBrowserText(cdp, /Automatic discovery/);
  await waitForBrowserText(cdp, /Risk projection: pending/);
  await waitForBrowserText(cdp, /No automatic sync schedule/);
  let discovery = await waitForBrowserText(cdp, /succeeded/);
  assert.match(discovery, /Risk projection: pending/);
  assert.match(discovery, /Graph projection: pending/);
  assert.match(discovery, /Search projection: pending/);
  assert.match(discovery, /No automatic sync schedule/);
  assert.match(discovery, /succeeded/);
  await clickBrowserAria(cdp, "Open succeeded sync");
  discovery = await waitForBrowserText(cdp, /Sync detail: succeeded/);
  assert.match(discovery, /1 discovered/);
  assert.match(syncID, /^pid_[0-9a-f-]{36}$/);

  await reloadBrowser(cdp);
  await waitForBrowserText(cdp, /Harness AWS discovery/);
  await clickBrowserAria(cdp, "Open Harness AWS discovery");
  await waitForBrowserText(cdp, /Automatic discovery/);
  await waitForBrowserText(cdp, /Risk projection: pending/);
  await waitForBrowserText(cdp, /No automatic sync schedule/);
  const reloaded = await waitForBrowserText(cdp, /succeeded/);
  assert.match(reloaded, /Risk projection: pending/);
  assert.match(reloaded, /No automatic sync schedule/);
  assert.match(reloaded, /succeeded/);
  console.log("combined E2E: Task4 reload preserved authoritative discovery state");

  const forensics = await browserConnectorForensics(cdp);
  const { resources, ...persistentForensics } = forensics;
  const forbiddenPersistentDiscovery = /production-e2e-manual-sync-0001|production-e2e-schedule-(?:put|delete)-0001|ref:aws\/external-id\/production-e2e|artifact_(?:key|uri)|cursor|worker_(?:id|identity)|lease_(?:owner|token)/i;
  for (const [field, value] of Object.entries({ body: reloaded, ...persistentForensics })) {
    const encoded = JSON.stringify(value);
    const match = forbiddenPersistentDiscovery.exec(encoded);
    const offset = match?.index ?? 0;
    assert.equal(match?.[0] ?? null, null, `Task4 discovery authority leaked into persistent browser ${field}: ${encoded.slice(Math.max(0, offset - 120), offset + 240)}`);
  }
  assert.equal(resources.every((resource) => new URL(resource).origin === publicOrigin), true, "Task4 discovery request history escaped the TLS same-origin boundary");
  assert.doesNotMatch(JSON.stringify(resources), /production-e2e-manual-sync-0001|production-e2e-schedule-(?:put|delete)-0001|ref:aws\/external-id\/production-e2e|artifact_(?:key|uri)|worker_(?:id|identity)|lease_(?:owner|token)/i);
  console.log("combined E2E: Task4 discovery forensics found no token, credential reference, artifact key, cursor, or worker identity in persistent browser state");
  console.log("combined E2E: Task4 opaque pagination cursors remained same-origin transport-only data");
}

async function assertTypedInventoryBrowserState(cdp, publicOrigin) {
  await navigateBrowser(cdp, `${publicOrigin}/discovery/assets`);
  await waitForBrowserText(cdp, /Support agent/);
  await clickBrowserAria(cdp, "Open Support agent");
  let detail = await waitForBrowserText(cdp, /Canonical record/);
  assert.match(detail, /Source authority/);
  assert.match(detail, /2 source observations/);
  assert.match(await browserCurrentURL(cdp), /inventory=pid_21000001-0000-4000-8000-000000000001/);
  await reloadBrowser(cdp);
  detail = await waitForBrowserText(cdp, /Canonical record/);
  assert.match(detail, /Support agent/);
  assert.match(await browserCurrentURL(cdp), /inventory=pid_21000001-0000-4000-8000-000000000001/);
  await navigateBrowser(cdp, `${publicOrigin}/inventory/tools`);
  await waitForBrowserText(cdp, /Automation repository/);
  await navigateBrowser(cdp, `${publicOrigin}/identities`);
  await waitForBrowserText(cdp, /Security operators/);
  await navigateBrowser(cdp, `${publicOrigin}/inventory/runtimes`);
  await waitForBrowserText(cdp, /Production runtime/);
  console.log("combined E2E: typed inventory browser deep-link reload proven across agents, tools, identities, and runtimes");
}

async function assertTask6SensorBrowserState(cdp, publicOrigin, dsn) {
  const sensorCredentialPattern = /\bzasp_sensor_v1\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/;
  const sensorAPIPath = "/api/v1/sensors";
  const sensorRequestStart = productAPIRequests.length;
  const scopePredicate = `sensor_row.organization_id='pid_10000001-0000-4000-8000-000000000001' AND sensor_row.workspace_id='pid_10000002-0000-4000-8000-000000000002' AND sensor_row.environment_id='pid_10000003-0000-4000-8000-000000000003'`;
  await navigateBrowser(cdp, `${publicOrigin}/integrations/sensors`);
  await waitForBrowserText(cdp, /Runtime sensors/);
  await waitForBrowserText(cdp, /No runtime sensors/);
  await clickBrowserText(cdp, "Enroll sensor");
  await waitForBrowserText(cdp, /Enroll runtime sensor/);
  await fillBrowserLabel(cdp, "Sensor name", "Production E2E sensor");
  await selectBrowserOption(cdp, "Sensor kind", "Tetragon");
  await selectBrowserOption(cdp, "Collection mode", "Metadata only");
  await clickBrowserText(cdp, "Create enrollment");
  await waitForBrowserText(cdp, /Sensor enrollment created\. Copy the token before closing\./);
  await waitForBrowserText(cdp, /Copy this token now/);
  const helmBoundary = await waitForBrowserText(cdp, /Helm deployment boundary/);
  assert.equal(helmBoundary.includes("sensorAgent.enabled=true"), true);
  assert.equal(helmBoundary.includes("sensorAgent.tokenSecretName=<pre-created-secret-name>"), true);
  assert.doesNotMatch(helmBoundary, /--set sensorAgent\.token=/);
  let firstCredential = await waitForBrowserTextMatch(cdp, sensorCredentialPattern);
  assert.equal(firstCredential.length, 81, "sensor enrollment token did not use the exact v1 wire shape");

  const createdWitness = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',sensor_row.id,sensor_row.state,sensor_row.version,sensor_row.mode,count(token_row.id),min(token_row.token_generation),min(octet_length(token_row.locator_digest)),min(octet_length(token_row.salt)),min(octet_length(token_row.token_hash)),(SELECT count(*) FROM zasp_runtime_sensor_mutations mutation WHERE mutation.sensor_id=sensor_row.id AND mutation.result::text LIKE '%zasp_sensor_v1.%')) FROM zasp_sensors sensor_row JOIN zasp_sensor_tokens token_row ON (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id) WHERE ${scopePredicate} AND sensor_row.name='Production E2E sensor' GROUP BY sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id,sensor_row.state,sensor_row.version,sensor_row.mode;`]);
  const [sensorID, ...createdAuthority] = createdWitness.stdout.trim().split("|");
  assert.match(sensorID, /^pid_[0-9a-f-]{36}$/);
  assert.deepEqual(createdAuthority, ["pending", "1", "metadata_only", "1", "1", "32", "32", "32", "0"], "sensor enrollment did not persist only exact hashed token authority");
  const enrollmentPersistence = await browserStorageHistoryAndCaches(cdp);
  assert.doesNotMatch(JSON.stringify(enrollmentPersistence), sensorCredentialPattern, "one-time enrollment token entered persistent browser state");

  const [, firstLocatorValue, firstSecretValue] = firstCredential.split(".");
  const firstLocator = Buffer.from(firstLocatorValue, "base64url");
  const firstSecret = Buffer.from(firstSecretValue, "base64url");
  assert.equal(firstLocator.length, 16);
  assert.equal(firstSecret.length, 32);
  await command(path.join(postgresBin, "psql"), [dsn, "-At", "-v", "ON_ERROR_STOP=1"], { input: `SELECT zasp_runtime_sensor_heartbeat(decode('${firstLocator.toString("hex")}','hex'),decode('${firstSecret.toString("hex")}','hex'),'event-ingest',1,'healthy','["file","network","process"]'::jsonb,'6.8.0',true,125,0);` });
  firstLocator.fill(0);
  firstSecret.fill(0);
  await clickBrowserText(cdp, "Done");
  await waitForBrowserTextMissing(cdp, firstCredential);
  await clickBrowserAria(cdp, "Open Production E2E sensor");
  let sensorDetail = await waitForBrowserText(cdp, /125 events\/s/);
  assert.match(sensorDetail, /healthy/);
  assert.match(sensorDetail, /6\.8\.0/);
  assert.match(sensorDetail, /file · network · process/);
  console.log("combined E2E: Task6 authenticated heartbeat and healthy sensor coverage proven");

  await fillBrowserLabel(cdp, "Sensor name", "Production E2E sensor renamed");
  await selectBrowserOption(cdp, "Collection mode", "Full");
  await clickBrowserText(cdp, "Save sensor");
  await waitForBrowserText(cdp, /Sensor settings saved\./);
  await clickBrowserText(cdp, "Rotate enrollment token");
  await waitForBrowserText(cdp, /Enrollment token rotated\. Copy it before closing\./);
  await waitForBrowserText(cdp, /Copy this token now/);
  let secondCredential = await waitForBrowserTextMatch(cdp, sensorCredentialPattern);
  assert.notEqual(secondCredential, firstCredential, "sensor rotation repeated the prior enrollment credential");
  const rotatedWitness = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',sensor_row.name,sensor_row.mode,sensor_row.state,sensor_row.version,count(token_row.id),count(*) FILTER(WHERE token_row.revoked_at IS NULL),count(*) FILTER(WHERE token_row.revoked_at IS NOT NULL),max(token_row.token_generation),max(token_row.sensor_version_at_issue) FILTER(WHERE token_row.revoked_at IS NULL)) FROM zasp_sensors sensor_row JOIN zasp_sensor_tokens token_row ON (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id) WHERE ${scopePredicate} AND sensor_row.id='${sensorID}' GROUP BY sensor_row.name,sensor_row.mode,sensor_row.state,sensor_row.version;`]);
  assert.equal(rotatedWitness.stdout.trim(), "Production E2E sensor renamed|full|active|2|2|1|1|2|2", "sensor update/rotation authority was not exact");
  console.log("combined E2E: Task6 token rotation and version-pinned sensor update proven");

  await reloadBrowser(cdp);
  await waitForBrowserText(cdp, /Production E2E sensor renamed/);
  const reloadedForensics = await browserConnectorForensics(cdp);
  assert.doesNotMatch(JSON.stringify(reloadedForensics), sensorCredentialPattern, "sensor enrollment credential survived a full browser reload");
  assert.equal(JSON.stringify(reloadedForensics).includes(firstCredential) || JSON.stringify(reloadedForensics).includes(secondCredential), false, "known sensor credential survived a full browser reload");
  await clickBrowserAria(cdp, "Open Production E2E sensor renamed");
  sensorDetail = await waitForBrowserText(cdp, /125 events\/s/);
  assert.match(sensorDetail, /Resource version "2"/);
  await clickBrowserText(cdp, "Delete sensor");
  await waitForBrowserText(cdp, /Sensor deleted and its active tokens revoked\./);
  await waitForBrowserAction(cdp, `document.querySelector(${JSON.stringify('[aria-label="Open Production E2E sensor renamed"]')}) === null`);
  const deletedWitness = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',sensor_row.state,sensor_row.version,sensor_row.revoked_at IS NOT NULL,count(token_row.id),count(*) FILTER(WHERE token_row.revoked_at IS NOT NULL)) FROM zasp_sensors sensor_row JOIN zasp_sensor_tokens token_row ON (token_row.organization_id,token_row.workspace_id,token_row.environment_id,token_row.sensor_id)=(sensor_row.organization_id,sensor_row.workspace_id,sensor_row.environment_id,sensor_row.id) WHERE ${scopePredicate} AND sensor_row.id='${sensorID}' GROUP BY sensor_row.state,sensor_row.version,sensor_row.revoked_at;`]);
  assert.equal(deletedWitness.stdout.trim(), "deleted|3|t|2|2", "sensor deletion did not revoke the sensor and every token exactly once");
  const deletedForensics = await browserConnectorForensics(cdp);
  assert.doesNotMatch(JSON.stringify(deletedForensics), sensorCredentialPattern, "sensor credential survived deletion in persistent browser state");
  assert.equal(JSON.stringify(deletedForensics).includes(firstCredential) || JSON.stringify(deletedForensics).includes(secondCredential), false, "known sensor credential survived deletion in persistent browser state");
  const sensorRequests = new Set(productAPIRequests.slice(sensorRequestStart).map((request) => `${request.method} ${request.path}`));
  for (const expectedRequest of [
    `GET ${sensorAPIPath}`, `POST ${sensorAPIPath}`, `GET ${sensorAPIPath}/${sensorID}`,
    `GET ${sensorAPIPath}/${sensorID}/coverage`, `PATCH ${sensorAPIPath}/${sensorID}`,
    `POST ${sensorAPIPath}/${sensorID}/rotate-token`, `DELETE ${sensorAPIPath}/${sensorID}`,
  ]) assert.equal(sensorRequests.has(expectedRequest), true, `installed browser omitted sensor operation ${expectedRequest}`);
  firstCredential = "";
  secondCredential = "";
  console.log("combined E2E: Task6 reload and deletion left no enrollment credential in persistent browser state");
}

async function navigateBrowser(cdp, url) {
  browserStage = `navigate:${url}`;
  await cdp.replaceTarget(url);
  console.log(`combined E2E: browser document transition ${new URL(url).pathname}`);
}

async function reloadBrowser(cdp) {
  browserStage = "reload";
  await reloadBrowserPage(cdp);
}

async function browserStorageAndHistoryText(cdp) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `JSON.stringify({ local: Object.fromEntries(Object.entries(localStorage)), session: Object.fromEntries(Object.entries(sessionStorage)), href: location.href, resources: performance.getEntriesByType('resource').map((entry) => entry.name) })`,
    returnByValue: true,
  });
  return String(evaluated.result?.value ?? "");
}

async function browserStorageHistoryAndCaches(cdp) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(async () => ({
      local: Object.fromEntries(Object.entries(localStorage)),
      session: Object.fromEntries(Object.entries(sessionStorage)),
      historyState: history.state,
      href: location.href,
      cacheKeys: 'caches' in globalThis ? await caches.keys() : [],
      indexedDatabases: typeof indexedDB.databases === 'function' ? (await indexedDB.databases()).map((database) => database.name ?? '') : [],
    }))()`,
    awaitPromise: true,
    returnByValue: true,
  });
  return evaluated.result?.value;
}

async function browserConnectorForensics(cdp) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(async () => ({
      dom: document.documentElement?.outerHTML ?? '',
      local: Object.fromEntries(Object.entries(localStorage)),
      session: Object.fromEntries(Object.entries(sessionStorage)),
      historyState: history.state,
      href: location.href,
      resources: performance.getEntriesByType('resource').map((entry) => entry.name),
      cacheKeys: 'caches' in globalThis ? await caches.keys() : [],
      indexedDatabases: typeof indexedDB.databases === 'function' ? (await indexedDB.databases()).map((database) => database.name ?? '') : [],
    }))()`,
    awaitPromise: true,
    returnByValue: true,
  });
  const navigation = await cdp.send("Page.getNavigationHistory");
  return {
    ...evaluated.result?.value,
    navigationHistory: navigation.entries.map((entry) => ({ url: entry.url, userTypedURL: entry.userTypedURL ?? "" })),
  };
}

async function assertResponsiveRiskLayout(cdp, heading) {
  for (const viewport of [{ width: 1440, height: 900 }, { width: 1024, height: 768 }, { width: 390, height: 844 }]) {
    await cdp.send("Emulation.setDeviceMetricsOverride", { ...viewport, deviceScaleFactor: 1, mobile: viewport.width < 600 });
    await cdp.send("Runtime.evaluate", { expression: "new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))", awaitPromise: true, returnByValue: true });
    const evaluated = await cdp.send("Runtime.evaluate", {
      expression: `(() => ({
        heading: [...document.querySelectorAll('h1,h2')].some((element) => element.textContent?.trim() === ${JSON.stringify(heading)}),
        viewport: innerWidth,
        documentWidth: document.documentElement.scrollWidth,
        bodyWidth: document.body.scrollWidth,
        focusedVisible: !document.activeElement || document.activeElement === document.body || document.activeElement.getBoundingClientRect().width > 0,
      }))()`,
      returnByValue: true,
    });
    const state = evaluated.result?.value;
    assert.equal(state.heading, true, `${heading} heading disappeared at ${viewport.width}x${viewport.height}`);
    assert.ok(state.documentWidth <= state.viewport && state.bodyWidth <= state.viewport, `${heading} overflowed at ${viewport.width}x${viewport.height}: ${JSON.stringify(state)}`);
    assert.equal(state.focusedVisible, true, `${heading} focus target was not visible at ${viewport.width}x${viewport.height}`);
  }
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1440, height: 900, deviceScaleFactor: 1, mobile: false });
}

async function waitForBrowserText(cdp, pattern) {
  let last = "";
  for (let attempt = 0; attempt < 300; attempt += 1) {
    last = await browserBodyText(cdp);
    if (pattern.test(last)) return last;
    await delay(50);
  }
  throw new Error(`browser text did not match ${pattern}: ${last}`);
}

async function waitForBrowserTextMatch(cdp, pattern) {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    const match = (await browserBodyText(cdp)).match(pattern);
    if (match) return match[0];
    await delay(50);
  }
  throw new Error(`browser text did not contain ${pattern}`);
}

async function waitForBrowserTextMissing(cdp, text) {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    if (!(await browserBodyText(cdp)).includes(text)) return;
    await delay(50);
  }
  throw new Error(`browser text still contained ${text.slice(0, 16)}…`);
}

async function waitForScopeOverlap(predicate, message) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (predicate()) return;
    await delay(25);
  }
  throw new Error(message);
}

async function browserHasInteractiveText(cdp, pattern) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `(() => { const matcher = new RegExp(${JSON.stringify(pattern.source)}, ${JSON.stringify(pattern.flags)}); return [...document.querySelectorAll('button,a')].some((candidate) => matcher.test(candidate.textContent ?? '')); })()`, returnByValue: true });
  return evaluated.result?.value === true;
}

async function browserTextControlDisabled(cdp, text) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `(() => { const value = ${JSON.stringify(text)}; const element = [...document.querySelectorAll('button,input,select,textarea')].find((candidate) => candidate.textContent?.trim() === value || candidate.getAttribute('aria-label') === value); return element instanceof HTMLButtonElement || element instanceof HTMLInputElement || element instanceof HTMLSelectElement || element instanceof HTMLTextAreaElement ? element.disabled : null; })()`, returnByValue: true });
  return evaluated.result?.value;
}

async function browserHasAriaLabel(cdp, label) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `document.querySelector(${JSON.stringify(`[aria-label="${label}"]`)}) !== null`, returnByValue: true });
  return evaluated.result?.value === true;
}

async function browserLabeledControlDisabled(cdp, label) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `(() => { const text = ${JSON.stringify(label)}; const field = [...document.querySelectorAll('label')].find((candidate) => [...candidate.querySelectorAll('span')].some((span) => span.textContent?.trim() === text)); const control = field?.querySelector('button,input,select,textarea'); return control instanceof HTMLButtonElement || control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement ? control.disabled : null; })()`, returnByValue: true });
  return evaluated.result?.value;
}

async function browserRoleControlState(cdp, label, buttonText) {
  await cdp.send("Runtime.evaluate", { expression: "new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))", awaitPromise: true, returnByValue: true });
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `(() => { const labelText = ${JSON.stringify(label)}; const field = [...document.querySelectorAll('label')].find((candidate) => [...candidate.querySelectorAll('span')].some((span) => span.textContent?.trim() === labelText)); const select = field?.querySelector('select'); const row = select?.closest('li'); const button = row && [...row.querySelectorAll('button')].find((candidate) => candidate.textContent?.trim() === ${JSON.stringify(buttonText)}); return { selected: select?.value ?? null, disabled: button instanceof HTMLButtonElement ? button.disabled : null }; })()`, returnByValue: true });
  return evaluated.result?.value;
}

async function waitForBrowserControlDisabled(cdp, text, expected) {
  await waitForBrowserAction(cdp, `(() => { const value = ${JSON.stringify(text)}; const element = [...document.querySelectorAll('button,input,select,textarea')].find((candidate) => candidate.textContent?.trim() === value || candidate.getAttribute('aria-label') === value); return Boolean(element) && element.disabled === ${JSON.stringify(expected)}; })()`);
  return expected;
}

async function selectBrowserOption(cdp, label, text) {
  await waitForBrowserAction(cdp, `(() => { const labelText = ${JSON.stringify(label)}; const field = [...document.querySelectorAll('label')].find((candidate) => [...candidate.querySelectorAll('span')].some((span) => span.textContent?.trim() === labelText)); const select = document.querySelector(${JSON.stringify(`select[aria-label="${label}"]`)}) ?? field?.querySelector('select'); const option = select && [...select.options].find((candidate) => candidate.textContent?.trim() === ${JSON.stringify(text)}); if (!select || !option || select.disabled) return false; const setter = Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype, 'value').set; setter.call(select, option.value); select.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
}

async function selectBrowserOptionAndClickSibling(cdp, label, text, buttonText) {
  await selectBrowserOption(cdp, label, text);
  await waitForBrowserAction(cdp, `(() => { const labelText = ${JSON.stringify(label)}; const field = [...document.querySelectorAll('label')].find((candidate) => [...candidate.querySelectorAll('span')].some((span) => span.textContent?.trim() === labelText)); const select = document.querySelector(${JSON.stringify(`select[aria-label="${label}"]`)}) ?? field?.querySelector('select'); const row = select?.closest('li'); const button = row && [...row.querySelectorAll('button')].find((candidate) => candidate.textContent?.trim() === ${JSON.stringify(buttonText)}); if (!button || button.disabled) return false; button.click(); return true; })()`);
}

async function waitForBrowserSelectedOption(cdp, label, text) {
  await waitForBrowserAction(cdp, `(() => { const labelText = ${JSON.stringify(label)}; const field = [...document.querySelectorAll('label')].find((candidate) => [...candidate.querySelectorAll('span')].some((span) => span.textContent?.trim() === labelText)); const select = document.querySelector(${JSON.stringify(`select[aria-label="${label}"]`)}) ?? field?.querySelector('select'); return Boolean(select && select.options[select.selectedIndex]?.textContent?.trim() === ${JSON.stringify(text)} && !select.disabled); })()`);
}

async function browserSelectedOptionValue(cdp, label) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `document.querySelector(${JSON.stringify(`select[aria-label="${label}"]`)})?.value ?? ""`, returnByValue: true });
  const value = evaluated.result?.value;
  assert.equal(typeof value, "string");
  assert.notEqual(value, "");
  return value;
}

async function waitForBrowserScope(cdp, expectedScope) {
  const [organizationID, workspaceID, environmentID] = expectedScope.split("/");
  let last;
  for (let attempt = 0; attempt < 200; attempt += 1) {
    last = await browserFetchJSON(cdp, "/api/v1/session/bootstrap", { "X-Zasp-Expected-Scope": expectedScope });
    if (last.status === 200 && last.body?.organization_id === organizationID && last.body?.workspace_id === workspaceID && last.body?.environment_id === environmentID) return;
    await delay(25);
  }
	throw new Error(`browser scope did not reconcile to ${expectedScope}: ${JSON.stringify(last)}`);
}

async function browserCountAriaPrefix(cdp, prefix) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `document.querySelectorAll(${JSON.stringify(`[aria-label^="${prefix}"]`)}).length`, returnByValue: true });
  return evaluated.result?.value;
}

async function waitForBrowserMissing(cdp, selector) {
  await waitForBrowserAction(cdp, `document.querySelector(${JSON.stringify(selector)}) === null`);
}

async function browserDialogIsolation(cdp) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `(() => { const layers = [...document.body.children].filter((element) => element.hasAttribute('data-dialog-layer')); const active = layers.at(-1); return layers.length === 1 && active && !active.hasAttribute('inert') && [...document.body.children].filter((element) => element !== active).every((element) => element.hasAttribute('inert') && element.getAttribute('aria-hidden') === 'true'); })()`, returnByValue: true });
  return evaluated.result?.value === true;
}

async function waitForBrowserActive(cdp, label) {
  await waitForBrowserAction(cdp, `(() => { const active = document.activeElement; const label = active?.getAttribute('aria-label') ?? active?.textContent?.trim(); return label === ${JSON.stringify(label)}; })()`);
}

async function dispatchBrowserKey(cdp, key, options = {}) {
  const definitions = { Tab: { code: "Tab", keyCode: 9 }, Escape: { code: "Escape", keyCode: 27 } };
  const definition = definitions[key];
  assert.ok(definition, `unsupported browser key ${key}`);
  const modifiers = options.shift ? 8 : 0;
  await cdp.send("Input.dispatchKeyEvent", { type: "keyDown", key, code: definition.code, windowsVirtualKeyCode: definition.keyCode, nativeVirtualKeyCode: definition.keyCode, modifiers });
  await cdp.send("Input.dispatchKeyEvent", { type: "keyUp", key, code: definition.code, windowsVirtualKeyCode: definition.keyCode, nativeVirtualKeyCode: definition.keyCode, modifiers });
}

async function clickBrowserText(cdp, text) {
  await waitForBrowserAction(cdp, `(() => { const value = ${JSON.stringify(text)}; const element = [...document.querySelectorAll('button,a')].find((candidate) => candidate.textContent?.trim() === value); if (!element) return false; element.focus(); element.click(); return true; })()`);
}

async function clickBrowserTextContains(cdp, text) {
	await waitForBrowserAction(cdp, `(() => { const value = ${JSON.stringify(text)}; const element = [...document.querySelectorAll('button,a')].find((candidate) => candidate.textContent?.includes(value)); if (!element) return false; element.focus(); element.click(); return true; })()`);
}

async function clickBrowserAria(cdp, label) {
  await waitForBrowserAction(cdp, `(() => { const element = document.querySelector(${JSON.stringify(`[aria-label="${label}"]`)}); if (!element) return false; element.click(); return true; })()`);
}

async function fillBrowserLabel(cdp, label, value) {
  await waitForBrowserAction(cdp, `(() => { const text = ${JSON.stringify(label)}; const value = ${JSON.stringify(value)}; const label = [...document.querySelectorAll('label')].find((candidate) => [...candidate.querySelectorAll('span')].some((span) => span.textContent?.trim() === text)); const control = label?.querySelector('input,textarea,select'); if (!control) return false; const prototype = control instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : control instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype; Object.getOwnPropertyDescriptor(prototype, 'value').set.call(control, value); control.dispatchEvent(new Event('input', { bubbles: true })); control.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
  await cdp.send("Runtime.evaluate", { expression: "new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)))", awaitPromise: true, returnByValue: true });
}

async function waitForBrowserAction(cdp, expression) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const evaluated = await cdp.send("Runtime.evaluate", { expression, returnByValue: true });
    if (evaluated.result?.value === true) return;
    await delay(25);
  }
	const diagnostic = await cdp.send("Runtime.evaluate", {
		expression: `({ href: location.href, body: (document.body?.innerText ?? "").slice(0, 4096) })`,
		returnByValue: true,
	});
	throw new Error(`browser action target unavailable: ${expression}; state=${JSON.stringify(diagnostic.result?.value)}`);
}

async function requestHTTPSJSON(target, options, body) {
  return new Promise((resolve, reject) => {
    const request = https.request(target, { ...options, lookup: productLoopbackLookup, rejectUnauthorized: false }, (response) => {
      let payload = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => { payload += chunk; });
      response.on("end", () => {
        try {
          resolve({ status: response.statusCode, headers: response.headers, body: payload === "" ? null : JSON.parse(payload) });
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on("error", reject);
    request.end(body);
  });
}

async function exerciseStytchDeprovision(publicOrigin, dsn) {
  const messageID = "msg_task11_deprovision_0001";
  const timestamp = String(Math.floor(Date.now() / 1000));
  const event = {
    action: "DELETE",
    details: { organization_id: "organization-test-local" },
    event_id: "webhook-event-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c90",
    id: "member-webhook-e2e",
    object_type: "member",
    project_id: "project-test-local",
    source: "SCIM",
    timestamp: new Date(Number(timestamp) * 1000).toISOString().replace(".000Z", "Z"),
    vertical: "B2B",
    workspace_id: "workspace-test-local",
  };
  const body = JSON.stringify(event);
  const key = Buffer.from(stytchWebhookSecret.slice("whsec_".length), "base64");
  const signature = `v1,${createHmac("sha256", key).update(`${messageID}.${timestamp}.${body}`).digest("base64")}`;
  const options = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": String(Buffer.byteLength(body)),
      "svix-id": messageID,
      "svix-timestamp": timestamp,
      "svix-signature": signature,
    },
  };
  const processed = await requestHTTPSJSON(`${publicOrigin}/api/v1/webhooks/stytch`, options, body);
  const replayed = await requestHTTPSJSON(`${publicOrigin}/api/v1/webhooks/stytch`, options, body);
  assert.deepEqual({ status: processed.status, body: processed.body }, { status: 202, body: { processed: true } });
  assert.deepEqual({ status: replayed.status, body: replayed.body }, { status: 202, body: { processed: false } });
  const proof = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT concat_ws('|',
    (SELECT active::text FROM zasp_identity_memberships WHERE principal_id='pid_10000006-0000-4000-8000-000000000006'),
    (SELECT count(*) FROM zasp_product_sessions WHERE principal_id='pid_10000006-0000-4000-8000-000000000006' AND revoked_at IS NOT NULL),
    (SELECT count(*) FROM zasp_product_api_tokens WHERE principal_id='pid_10000006-0000-4000-8000-000000000006' AND revoked_at IS NOT NULL),
    (SELECT count(*) FROM zasp_authorized_scopes WHERE principal_id='pid_10000006-0000-4000-8000-000000000006'),
    (SELECT count(*) FROM zasp_identity_webhook_events WHERE event_id='webhook-event-test-018f85a0-2c17-7ba3-91d1-7f0382dd7c90'),
    (SELECT count(*) FROM zasp_admin_audit WHERE action='identity.member.deprovision' AND target_id='pid_10000006-0000-4000-8000-000000000006')
  );`]);
  assert.equal(proof.stdout.trim(), "false|1|1|0|1|1", "signed deprovision did not atomically disable the member and revoke tenant authority");
  console.log("combined E2E: signed Stytch webhook replay and tenant deprovision proven");
}

function assertRejectedConnectorResponse(response, status, code, label) {
  assert.equal(response.status, status, `${label} status`);
  assert.equal(response.headers["cache-control"], "no-store", `${label} cache policy`);
  assert.equal(response.headers["referrer-policy"], "no-referrer", `${label} referrer policy`);
  assert.equal(response.headers.location, undefined, `${label} redirected outside the product boundary`);
  assert.equal(response.body?.code, code, `${label} error code`);
  assert.deepEqual(Object.keys(response.body ?? {}).sort(), ["code", "correlation_id", "message", "retryable"], `${label} returned a non-strict error envelope`);
  assert.doesNotMatch(JSON.stringify(response.body), /access_token|refresh_token|code_verifier|client_secret|authorization_url|authorization_attempt_id|credential_reference|secret_reference/i, `${label} exposed connector material`);
}

async function browserConnectorAuthorizeRejection(cdp, target, expectedScope) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(async () => {
      const bootstrap = await fetch('/api/v1/session/bootstrap', { cache: 'no-store' }).then((response) => response.json());
      const response = await fetch(${JSON.stringify(target)}, {
        method: 'POST',
        cache: 'no-store',
        redirect: 'manual',
        headers: {
          'content-type': 'application/json',
          'Idempotency-Key': 'connector-e2e-cross-scope-authorize',
          'X-CSRF-Token': bootstrap.csrf_token,
          'X-Zasp-Expected-Scope': ${JSON.stringify(expectedScope)},
        },
        body: '{}',
      });
      const text = await response.text();
      return { status: response.status, headers: Object.fromEntries(response.headers.entries()), body: text === '' ? null : JSON.parse(text) };
    })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  return evaluated.result.value;
}

async function browserFetchJSON(cdp, target, headers) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(async () => { const response = await fetch(${JSON.stringify(target)}, { headers: ${JSON.stringify(headers)} }); return { status: response.status, body: await response.json() }; })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  return evaluated.result.value;
}

async function browserHarnessDirectIntegrationDeleteReplay(cdp, integrationID, idempotencyKey, ifMatch, expectedScope) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(async () => {
      const bootstrap = await fetch('/api/v1/session/bootstrap', { cache: 'no-store' }).then((response) => response.json());
      const response = await fetch(${JSON.stringify(`/api/v1/integrations/${integrationID}`)}, {
        method: 'DELETE', cache: 'no-store',
        headers: {
          'Idempotency-Key': ${JSON.stringify(idempotencyKey)},
          'If-Match': ${JSON.stringify(ifMatch)},
          'X-CSRF-Token': bootstrap.csrf_token,
          'X-Zasp-Expected-Scope': ${JSON.stringify(expectedScope)},
        },
      });
      return { status: response.status, headers: Object.fromEntries(response.headers.entries()), body: await response.text() };
    })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  return evaluated.result.value;
}

async function browserScopedMutationJSON(cdp, target, method, expectedScope) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(async () => { const bootstrap = await fetch('/api/v1/session/bootstrap', { cache: 'no-store' }).then((response) => response.json()); const response = await fetch(${JSON.stringify(target)}, { method: ${JSON.stringify(method)}, headers: { 'content-type': 'application/json', 'X-CSRF-Token': bootstrap.csrf_token, 'X-Zasp-Expected-Scope': ${JSON.stringify(expectedScope)} }, body: '{}' }); const text = await response.text(); return { status: response.status, body: text === '' ? null : JSON.parse(text) }; })()`,
    awaitPromise: true,
    returnByValue: true,
  });
  return evaluated.result.value;
}

async function attachToBrowserTarget(browserCDP, initialTargetId, browserContextId) {
  let targetId = initialTargetId;
  let attached = await browserCDP.send("Target.attachToTarget", { targetId, flatten: true });
  assert.ok(attached.sessionId, "Chrome target session was not created");
  return {
    send(method, params = {}) { return browserCDP.send(method, params, attached.sessionId); },
    on(method, listener) { return browserCDP.on((message) => { if (message.method === method && message.sessionId === attached.sessionId) listener(message.params ?? {}); }); },
    async replaceTarget(url) {
      const previousTargetId = targetId;
      const created = await browserCDP.send("Target.createTarget", { url, ...(browserContextId ? { browserContextId } : {}) });
      assert.ok(created.targetId, "Chrome replacement target was not created");
      const replacement = await browserCDP.send("Target.attachToTarget", { targetId: created.targetId, flatten: true });
      assert.ok(replacement.sessionId, "Chrome replacement target session was not created");
      targetId = created.targetId;
      attached = replacement;
      await browserCDP.send("Runtime.enable", {}, attached.sessionId);
      await browserCDP.send("Log.enable", {}, attached.sessionId);
      const closed = await browserCDP.send("Target.closeTarget", { targetId: previousTargetId });
      assert.equal(closed.success, true, "Chrome previous target was not closed");
    },
    close() { browserCDP.close(); },
  };
}

async function connectCDP(target) {
  let nextID = 0;
  let closed = false;
  const pending = new Map();
  const listeners = new Set();
  const socket = new WebSocket(target);
  await new Promise((resolve, reject) => {
    socket.addEventListener("open", resolve, { once: true });
    socket.addEventListener("error", () => reject(new Error("browser debugging connection rejected")), { once: true });
  });
  const rejectPending = (message) => {
    for (const { reject, timeout } of pending.values()) {
      clearTimeout(timeout);
      reject(new Error(message));
    }
    pending.clear();
  };
  socket.addEventListener("message", (event) => {
    const message = JSON.parse(event.data);
    if (!message.id) {
      for (const listener of listeners) listener(message);
      return;
    }
    if (!pending.has(message.id)) return;
    const { resolve, reject, timeout } = pending.get(message.id);
    pending.delete(message.id);
    clearTimeout(timeout);
    if (message.error) reject(new Error(message.error.message)); else resolve(message.result);
  });
  socket.addEventListener("close", () => { if (!closed) rejectPending("CDP connection closed"); });
  return {
    on(listener) { listeners.add(listener); return () => listeners.delete(listener); },
    send(method, params = {}, sessionId) {
      const id = ++nextID;
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          pending.delete(id);
          reject(new Error(`CDP request timed out at ${browserStage}: ${method} ${JSON.stringify(params)}`));
        }, 20_000);
        pending.set(id, { resolve, reject, timeout });
        socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
      });
    },
    close() { closed = true; rejectPending("CDP connection closed"); socket.close(); },
  };
}

function startChild(executable, args, options = {}) {
  const child = spawn(executable, args, { cwd: options.cwd ?? root, env: options.env ?? process.env, stdio: ["ignore", "pipe", "pipe"] });
  let output = "";
  child.stdout.on("data", (value) => { output += value; });
  child.stderr.on("data", (value) => { output += value; });
  child.output = () => output.slice(-16_384);
  children.push(child);
  return child;
}

async function stopChild(child) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([once(child, "exit"), delay(5_000)]);
  if (child.exitCode === null && child.signalCode === null) {
    child.kill("SIGKILL");
    await Promise.race([once(child, "exit"), delay(2_000)]);
  }
}

async function command(executable, args, options = {}) {
  const child = spawn(executable, args, { cwd: options.cwd ?? root, env: options.env ?? process.env, stdio: ["pipe", "pipe", "pipe"] });
	children.push(child);
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (value) => { stdout += value; });
  child.stderr.on("data", (value) => { stderr += value; });
  if (options.input) child.stdin.end(options.input); else child.stdin.end();
  const deadline = setTimeout(() => child.kill("SIGKILL"), options.timeout ?? 30_000);
	const [status, signal] = await once(child, "exit");
  clearTimeout(deadline);
	const result = { status, signal, stdout, stderr };
	if (status !== 0 && options.reject !== false) throw new Error(`${path.basename(executable)} failed (${status ?? signal}): ${stderr || stdout}`);
  return result;
}

async function reservePort() {
  const server = net.createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await closeServer(server);
  return port;
}

async function waitForHTTP(target, expected, insecure = false) {
  let last = { status: 0, body: "" };
  for (let attempt = 0; attempt < 200; attempt += 1) {
    last = await new Promise((resolve) => {
      const transport = target.startsWith("https:") ? https : http;
      const request = transport.get(target, { ...(target.startsWith("https:") ? { lookup: productLoopbackLookup } : {}), rejectUnauthorized: !insecure }, (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => { if (body.length < 2_048) body += chunk; });
        response.on("end", () => resolve({ status: response.statusCode ?? 0, body: body.slice(0, 2_048) }));
      });
      request.on("error", (error) => resolve({ status: 0, body: String(error.message ?? error) }));
    });
    if (last.status === expected) return last;
    await delay(50);
  }
  throw new Error(`endpoint did not become ready: ${target}; last=${JSON.stringify(last)}`);
}

async function readBody(request) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 16_384) throw new Error("identity request too large");
  }
  return body;
}

async function closeServer(server) {
  server.closeAllConnections?.();
  server.close();
  if (server.listening) await Promise.race([once(server, "close"), delay(2_000)]);
}

function delay(milliseconds) { return new Promise((resolve) => setTimeout(resolve, milliseconds)); }

function productLoopbackLookup(_hostname, options, callback) {
  if (options?.all) callback(null, [{ address: "127.0.0.1", family: 4 }]);
  else callback(null, "127.0.0.1", 4);
}

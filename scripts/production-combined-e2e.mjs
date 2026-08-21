import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { chmod, mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";
import { reloadBrowserPage } from "./browser-e2e-helpers.mjs";

const FIXED_NODE_VERSION = "v22.23.1";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const platform = path.join(root, "services", "platform");
const postgresBin = "/opt/homebrew/bin";
const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const productHostname = "zasp.production-e2e.test";
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

if (process.version !== FIXED_NODE_VERSION) throw new Error(`production combined E2E requires Node ${FIXED_NODE_VERSION}`);

const temporaryRoot = await mkdtemp(path.join(os.tmpdir(), "zasp-production-e2e-"));
const children = [];
let proxy;
let identity;
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
const connectorAuthorizationRequests = [];
const productAPIRequests = [];
const browserConsoleErrors = [];
const browserConsoleMessages = [];
const administrationRequests = [];
const lostTokenResponses = { create: false, rotate: false, reveal: false, acknowledge: false };
const tokenMutationKeys = { create: [], rotate: [] };
let identityOAuthStarts = 0;
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
const cleanupController = installBoundedSignalCleanup(cleanupOwnedResources);

try {
  const ports = await Promise.all(Array.from({ length: 7 }, reservePort));
  const [postgresPort, identityPort, apiPort, healthPort, webPort, proxyPort, chromePort] = ports;
  const githubAppPrivateKey = path.join(temporaryRoot, "github-app-private-key.pem");
  await generateHarnessGitHubAppPrivateKey(githubAppPrivateKey);
  const dsn = `postgres://zasp_e2e@127.0.0.1:${postgresPort}/postgres?sslmode=disable`;
  const apiDSN = `postgres://zasp_e2e_api@127.0.0.1:${postgresPort}/postgres?sslmode=disable`;
  postgres = await startPostgres(postgresPort);
  await provisionPostgresPrincipals(dsn);
  console.log("combined E2E: disposable PostgreSQL ready");

  const migrate = path.join(temporaryRoot, "agentsec-migrate");
  const apiBinary = path.join(temporaryRoot, "agentsec-api");
  const workerBinary = path.join(temporaryRoot, "agentsec-worker");
  const workerE2EBinary = path.join(temporaryRoot, "agentsec-worker-e2e");
  await command("go", ["build", "-o", migrate, "./agentsec-migrate"], { cwd: platform });
  await command("go", ["build", "-o", apiBinary, "./agentsec-api"], { cwd: platform });
  await command("go", ["build", "-o", workerBinary, "./agentsec-worker"], { cwd: platform });
  await command("go", ["test", "-c", "-o", workerE2EBinary, "./agentsec-worker"], { cwd: platform, timeout: 120_000 });
  await command(migrate, ["up"], { env: {
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
  } });
  const schemaRelease = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", "SELECT version || '|' || name FROM zasp_schema_versions WHERE version IN (14,15,16) ORDER BY version;"]);
  assert.equal(schemaRelease.stdout.trim(), "14|typed_inventory_cutover\n15|runtime_data_plane\n16|runtime_gateway_reconciliation", "combined E2E did not migrate through the typed inventory, runtime data-plane, and gateway reconciliation releases");
  console.log("combined E2E: schema 14 typed_inventory_cutover verified");
  console.log("combined E2E: schema 15 runtime_data_plane verified");
  console.log("combined E2E: schema 16 runtime_gateway_reconciliation verified");
  await seedPostgres(dsn);
  console.log("combined E2E: migrations and durable seed ready");

  const publicOrigin = `https://${productHostname}:${proxyPort}`;
  identity = await startIdentityServer(identityPort, publicOrigin);
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
    ZASP_STYTCH_BASE_URL: `http://127.0.0.1:${identityPort}`,
    ZASP_STYTCH_AUTHORIZE_URL: `http://127.0.0.1:${identityPort}/v1/b2b/public/oauth/google/start`,
    ZASP_STYTCH_PROJECT_ID: "project-test-local",
    ZASP_STYTCH_SECRET: "secret-test-local",
    ZASP_STYTCH_PUBLIC_TOKEN: "public-token-test-local",
    ZASP_STYTCH_ORGANIZATION_ID: "organization-test-local",
    ZASP_WORKFLOW_SIGNING_KEY: "0123456789abcdef0123456789abcdef",
    ZASP_TOKEN_REVEAL_KEY: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
    ZASP_CONNECTOR_AWS_REGION: "us-east-1",
    ZASP_CONNECTOR_ROLE_ARN: "arn:aws:iam::000000000000:role/zasp-production-e2e-api-connectors",
    ZASP_CONNECTOR_WEB_IDENTITY_TOKEN_FILE: "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
    ZASP_CONNECTOR_KMS_KEY_ARN: "arn:aws:kms:us-east-1:000000000000:key/11111111-1111-1111-1111-111111111111",
    ZASP_CONNECTOR_SECRET_PREFIX: "zasp-production-e2e/connectors/oauth",
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

  await command("npm", ["run", "build"], { cwd: root, timeout: 120_000 });
  web = startChild(path.join(root, "node_modules", ".bin", "vinext"), ["start", "--port", String(webPort), "--hostname", "127.0.0.1"], { cwd: root });
  await waitForHTTP(`http://127.0.0.1:${webPort}/sign-in`, 200);
  console.log("combined E2E: built web server ready");

  const key = path.join(temporaryRoot, "tls.key");
  const certificate = path.join(temporaryRoot, "tls.crt");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", `/CN=${productHostname}`, "-addext", `subjectAltName=DNS:${productHostname}`, "-keyout", key, "-out", certificate]);
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
  assert.equal(patCreated.status, 201, `PAT create failed: ${JSON.stringify(patCreated)}`);
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
  await assertTask4BrowserPublicState(browser.cdp, publicOrigin, task4Public.syncID);
  await assertTypedInventoryBrowserState(browser.cdp, publicOrigin);
  await assertTask6SensorBrowserState(browser.cdp, publicOrigin, dsn);
  await exerciseTypedInventoryRetention(publicOrigin, dsn, postgresPort, workerE2EBinary, patHeaders.authorization);
  await navigateBrowser(browser.cdp, `${publicOrigin}/discovery/assets`);
  await waitForBrowserText(browser.cdp, /No records in this scope/);

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

  const hiddenRequestStart = productAPIRequests.length;
  for (const hiddenPath of ["/red-team/results", "/test/attack-lab", "/reports", "/guardrails/dashboard", "/prompt-hardening"]) {
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
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Simulate policy|Decision history)$/i), false);
  await clickBrowserAria(browser.cdp, "Open Production runtime policy");
  await waitForBrowserText(browser.cdp, /Policy detail · policy-production/);
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
  await clickBrowserAria(browser.cdp, "Open Harness terminal revocation");
  await waitForBrowserText(browser.cdp, /Provider credentials are never returned to this browser/);
  await clickBrowserText(browser.cdp, "Authorize GitHub");
  await waitForBrowserText(browser.cdp, /Provider authorization harness/);
  assert.equal(await browserCurrentURL(browser.cdp), `${publicOrigin}/connector-oauth-e2e-provider`);
  assert.equal(connectorAuthorizationRequests.length, 2, "browser OAuth response-loss replay count drifted");
  assert.equal(new Set(connectorAuthorizationRequests.map((request) => request.idempotencyKey)).size, 1, "browser OAuth retry changed idempotency key");
  for (const request of connectorAuthorizationRequests) {
    assert.equal(request.body, "{}");
    assert.equal(request.contentType, "application/json");
    assert.match(request.csrf, /^.{32,256}$/);
    assert.equal(request.expectedScope, "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003");
    assert.equal(request.origin, publicOrigin);
  }
  assert.equal(productAPIRequests.slice(connectorUIRequestStart).some((request) => request.path === `/api/v1/integrations/${terminalRevocationIntegrationID}/authorize`), true, "product UI did not invoke connector authorization");
  assert.doesNotMatch(await browserBodyText(browser.cdp), /authorization_(?:url|attempt_id)|code_verifier|opaque-e2e-state/i);
  console.log("combined E2E: browser OAuth authorization navigation and exact retained request proven");
  await navigateBrowser(browser.cdp, `${publicOrigin}/connectors`);
  await waitForBrowserText(browser.cdp, /Harness terminal revocation/);

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
  assert.equal(await browserHasAriaLabel(browser.cdp, "Open Harness reload revocation"), true, "reload hid a still-revoking integration");
  assert.equal(await browserAriaControlDisabled(browser.cdp, "Open Harness reload revocation"), true, "reload did not retain the scope mutation lock");
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
  await clickBrowserAria(browser.cdp, "Close");

  await navigateBrowser(browser.cdp, `${publicOrigin}/protect/security-agents`);
  await waitForBrowserText(browser.cdp, /Durable, scoped response definitions/);
  await clickBrowserText(browser.cdp, "Create Security Agent");
  await clickBrowserText(browser.cdp, "Save Security Agent definition");
  await waitForBrowserText(browser.cdp, /Bounded response definition/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Run Security Agent|Simulate Security Agent|Approve|Start bounded run|Runs|Approvals)$/i), false);

  await navigateBrowser(browser.cdp, `${publicOrigin}/protect/approvals`);
  const approvalsHidden = await waitForBrowserText(browser.cdp, /Security overview/);
  assert.doesNotMatch(approvalsHidden, /Approve|Pending approvals/);
  console.log("combined E2E: full-document receipt recovery, local integration, Security Agent definition, and hidden unsafe response controls proven");

  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/identity-access`);
  const identityAccess = await waitForBrowserText(browser.cdp, /member-target-local[\s\S]*E2E Organization/);
  assert.match(identityAccess, /E2E Organization/);
  assert.match(identityAccess, /Enterprise identity\s+Unavailable/);
  assert.match(identityAccess, /Group mappings\s+Unavailable/);
  assert.doesNotMatch(identityAccess, /Configure SSO|Enable SCIM|Rotate webhook/);
  assert.doesNotMatch(identityAccess, /Unpermitted environment/, "scope selector exposed an environment without an authorized-scope row");
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
  assert.equal(identityOAuthStarts, 2, "fresh reauthentication did not use the provider-faithful start/callback path exactly once");
  assert.match(await browserCurrentURL(browser.cdp), /\/administration\/identity-access$/);
  await selectBrowserOption(browser.cdp, "Role for member-target-local", "read only viewer");
  const reauthenticatedRoleControl = await browserRoleControlState(browser.cdp, "Role for member-target-local", "Update role");
  assert.deepEqual(reauthenticatedRoleControl, { selected: "read_only_viewer", disabled: false }, `fresh reauthentication left sensitive role control unavailable: ${JSON.stringify(reauthenticatedRoleControl)}`);
  await selectBrowserOptionAndClickSibling(browser.cdp, "Role for member-target-local", "read only viewer", "Update role");
  await waitForBrowserText(browser.cdp, /Member role updated; active sessions revoked/);
  const roleResult = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT role || '|' || (SELECT count(*) FROM zasp_product_sessions WHERE session_id='session-role-change-e2e' AND revoked_at IS NOT NULL) FROM zasp_identity_memberships WHERE principal_id='pid_10000005-0000-4000-8000-000000000005';`]);
  assert.equal(roleResult.stdout.trim(), "read_only_viewer|1", "member role and session revocation were not atomic");
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
  await selectBrowserOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized scope", "Production");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized workspace", "Production Workspace");
  await waitForBrowserSelectedOption(browser.cdp, "Authorized environment", "Production");

  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/api-access`);
  await waitForBrowserText(browser.cdp, /Create scoped automation credentials/);
  const seededTokenCount = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT count(*) FROM zasp_product_api_tokens WHERE organization_id='pid_10000001-0000-4000-8000-000000000001';`]);
  assert.equal(seededTokenCount.stdout.trim(), "1");
  const browserTokenInventory = await browserFetchJSON(browser.cdp, "/api/v1/admin/api-tokens", {
    "X-Zasp-Expected-Scope": "pid_10000001-0000-4000-8000-000000000001/pid_10000002-0000-4000-8000-000000000002/pid_10000003-0000-4000-8000-000000000003",
  });
  assert.equal(browserTokenInventory.status, 200, JSON.stringify(browserTokenInventory.body));
  assert.equal(browserTokenInventory.body.items.length, 1);
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
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1", "-c", `UPDATE zasp_product_sessions SET authenticated_at=transaction_timestamp()-interval '10 minutes' WHERE principal_id='pid_10000004-0000-4000-8000-000000000004' AND revoked_at IS NULL;`]);
  await clickBrowserText(browser.cdp, "I saved it — destroy recovery copy");
  await waitForBrowserText(browser.cdp, /revealed token was cleared/);
  assert.doesNotMatch(await browserBodyText(browser.cdp), /zasp_pat_[A-Za-z0-9_-]{43}/, "fresh-auth expiry left a raw token in the document");
  assert.equal(await browserHasInteractiveText(browser.cdp, /^Copy token$/), false, "fresh-auth expiry left token copy enabled");
  await clickBrowserText(browser.cdp, "Reauthenticate");
  await waitForBrowserText(browser.cdp, /Continue through the configured identity provider/);
  await clickBrowserText(browser.cdp, "Continue to sign in");
  await waitForBrowserText(browser.cdp, /Created token/);
  assert.equal(identityOAuthStarts, 3, "token-dialog reauthentication did not use the provider-faithful flow");
  await clickBrowserText(browser.cdp, "Reveal token");
  await waitForBrowserText(browser.cdp, /Save API token/);
  await clickBrowserText(browser.cdp, "I saved it — destroy recovery copy");
  await waitForBrowserMissing(browser.cdp, '[aria-label="Save API token"]');
  await waitForBrowserActive(browser.cdp, "Create API token");

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

  await seedInvestigationSession(dsn);
  await navigateBrowser(browser.cdp, `${publicOrigin}/investigate/sessions`);
  const investigation = await waitForBrowserText(browser.cdp, /Shell requested by E2E/);
  assert.match(investigation, /evidence-session-e2e/);
  await clickBrowserAria(browser.cdp, "Revoke session session-investigation-e2e");
  const sessionRevokeOutcome = await waitForBrowserText(browser.cdp, /Session revoked|Session could not be revoked/);
  assert.match(sessionRevokeOutcome, /Session revoked/, `administration requests: ${JSON.stringify(administrationRequests)}`);
  const revokedSession = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT (revoked_at IS NOT NULL)::text || '|' || version FROM zasp_product_sessions WHERE session_id='session-investigation-e2e';`]);
  assert.equal(revokedSession.stdout.trim(), "true|2");

  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/audit-log`);
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

  await stopChild(api);
  api = startChild(apiBinary, [], { env: apiEnvironment });
  await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
  await navigateBrowser(browser.cdp, `${publicOrigin}/violations`);
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
  await navigateBrowser(browser.cdp, `${publicOrigin}/protect/security-agents`);
  await waitForBrowserText(browser.cdp, /Bounded response definition/);
  await clickBrowserAria(browser.cdp, "Open Bounded response definition");
  assert.match(await waitForBrowserText(browser.cdp, /Resource version/), /supervised/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Run Security Agent|Simulate Security Agent|Approve|Start bounded run|Runs|Approvals)$/i), false);
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
  const connectorForensics = await browserConnectorForensics(browser.cdp);
  assert.deepEqual(connectorForensics.local, {});
  assert.deepEqual(connectorForensics.session, {});
  assert.deepEqual(connectorForensics.cacheKeys, []);
  assert.deepEqual(connectorForensics.indexedDatabases, []);
  const connectorBrowserSurface = JSON.stringify({ connectorForensics, browserConsoleMessages });
  assert.doesNotMatch(connectorBrowserSurface, /zasp_pat_|access_token|refresh_token|code_verifier|client_secret|authorization_url|authorization_attempt_id|connector-(?:code|state|cross-scope)|secret-test-local|ref:(?:github\/(?:client-secret|app-private-key)|okta\/client-secret)|MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY/i);
  assert.equal(connectorForensics.navigationHistory.some((entry) => /[?&](?:code|state)=/i.test(`${entry.url} ${entry.userTypedURL}`)), false, "connector code/state remained in browser navigation history");
  console.log("combined E2E: connector tokens, state, verifier, and secrets absent from DOM, URL/history, storage, caches, IndexedDB, and console");
  assert.deepEqual(browserConsoleErrors, [], `browser console/exception errors: ${JSON.stringify(browserConsoleErrors)}`);
  console.log("combined E2E: browser console and exception stream remained clean");
  assert.equal(proxyFailure, undefined, `proxy fixture failed: ${proxyFailure}`);
  console.log("combined E2E: live provider revocation NOT RUN; harness exercised only explicit external-provider completion simulation");
  console.log("combined E2E: live AWS/GitHub/Okta connector success remains typed external evidence");
  console.log("combined E2E: live AWS/Kubernetes/GitHub/Okta collection and managed SQS/S3/OpenSearch/Neo4j remain NOT RUN");

  console.log("production combined E2E passed: callback/cookie/bootstrap, risk pagination/recovery, administration, PAT/receipt recovery, responsive keyboard focus, durable restart/reload, tenant denial");
} finally {
	await cleanupController.run();
	cleanupController.dispose();
}

async function cleanupOwnedResources() {
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
  console.log("combined E2E: cleanup web");
  if (web) await stopChild(web);
  console.log("combined E2E: cleanup postgres");
  if (postgres) await stopPostgres(postgres);
  console.log("combined E2E: cleanup remaining processes");
  for (const child of children.reverse()) await stopChild(child);
  console.log("combined E2E: cleanup files");
  await rm(temporaryRoot, { recursive: true, force: true });
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
`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
}

async function seedPostgres(dsn) {
  const sql = `
INSERT INTO zasp_authorized_scopes (principal_id, organization_id, workspace_id, environment_id, label, permissions, is_default) VALUES
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','Production','["view","manage_workflows","manage_findings"]'::jsonb,true),
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','Staging','["view","manage_workflows","manage_findings"]'::jsonb,false),
('pid_90000004-0000-4000-8000-000000000004','pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','Foreign','["view"]'::jsonb,true);
INSERT INTO zasp_identity_memberships (principal_id, organization_id, organization_reference, member_reference, role) VALUES
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','organization-test-local','member-test-local','security_admin'),
('pid_10000005-0000-4000-8000-000000000005','pid_10000001-0000-4000-8000-000000000001','organization-test-local','member-target-local','security_engineer');
INSERT INTO zasp_organizations(id,name,domain) VALUES
('pid_10000001-0000-4000-8000-000000000001','E2E Organization','e2e.invalid');
INSERT INTO zasp_workspaces(id,organization_id,name) VALUES
('pid_10000002-0000-4000-8000-000000000002','pid_10000001-0000-4000-8000-000000000001','Production Workspace'),
('pid_10000022-0000-4000-8000-000000000022','pid_10000001-0000-4000-8000-000000000001','Staging Workspace');
INSERT INTO zasp_environments(id,organization_id,workspace_id,name,environment_class) VALUES
('pid_10000003-0000-4000-8000-000000000003','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','Production','production'),
('pid_10000023-0000-4000-8000-000000000023','pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','Staging','staging'),
('pid_10000033-0000-4000-8000-000000000033','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','Unpermitted environment','test');
INSERT INTO zasp_data_controls(organization_id,workspace_id,environment_id,environment_class,collection_mode,retention_days,deletion_enabled,migration_seeded) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','production','metadata_only',30,true,false),
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','staging','metadata_only',30,true,false);
INSERT INTO zasp_compliance_controls(organization_id,id,framework,name,fresh_until) VALUES
('pid_10000001-0000-4000-8000-000000000001','access-control','SOC 2','Logical access controls',transaction_timestamp()+interval '24 hours');
INSERT INTO zasp_compliance_evidence(organization_id,control_id,id,asset_id,source,at) VALUES
('pid_10000001-0000-4000-8000-000000000001','access-control','evidence-membership','pid_10000004-0000-4000-8000-000000000004','product-membership',transaction_timestamp());
INSERT INTO zasp_product_sessions(token_digest,csrf_token,session_id,principal_id,organization_id,workspace_id,environment_id,permissions,expires_at) VALUES
(digest('target-role-session','sha256'),'target-role-csrf-with-at-least-32-bytes','session-role-change-e2e','pid_10000005-0000-4000-8000-000000000005','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view"]'::jsonb,transaction_timestamp()+interval '1 hour');
INSERT INTO zasp_product_api_tokens (token_digest, principal_id, organization_id, workspace_id, environment_id, permissions, expires_at) VALUES
(digest('production-e2e-product-token-with-at-least-32-bytes', 'sha256'),'pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view","manage_workflows","manage_findings"]'::jsonb,transaction_timestamp() + interval '1 hour');
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
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5GitHubIntegrationID}','pid_75000011-0000-4000-8000-000000000011','github','ref:github/installation/e2e-424242','verified',transaction_timestamp()),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','${task5OktaIntegrationID}','pid_76000011-0000-4000-8000-000000000011','okta','ref:okta/refresh/e2e-tenant','verified',transaction_timestamp());
INSERT INTO zasp_discovery_connection_subjects(organization_id,workspace_id,environment_id,integration_id,connection_id,provider,subject_kind,subject_id,connection_version,configuration_digest,source)
SELECT organization_id,workspace_id,environment_id,id,
 CASE id WHEN '${task5KubernetesAIntegrationID}' THEN 'pid_74000011-0000-4000-8000-000000000011' WHEN '${task5KubernetesBIntegrationID}' THEN 'pid_74000012-0000-4000-8000-000000000012' WHEN '${task5KubernetesPartialIntegrationID}' THEN 'pid_74000013-0000-4000-8000-000000000013' ELSE 'pid_74000014-0000-4000-8000-000000000014' END,
 'kubernetes','kubernetes_cluster',CASE id WHEN '${task5KubernetesAIntegrationID}' THEN 'prod.example/cluster-a' WHEN '${task5KubernetesBIntegrationID}' THEN 'prod.example/cluster-a' WHEN '${task5KubernetesPartialIntegrationID}' THEN 'prod.example/cluster-partial' ELSE 'prod.example/cluster-failed' END,1,digest(convert_to(configuration::text,'UTF8'),'sha256'),'reference'
FROM zasp_integrations WHERE id IN('${task5KubernetesAIntegrationID}','${task5KubernetesBIntegrationID}','${task5KubernetesPartialIntegrationID}','${task5KubernetesFailedIntegrationID}');
INSERT INTO zasp_connector_credentials(organization_id,workspace_id,environment_id,id,integration_id,provider,credential_class,credential_reference,version,metadata) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_75000021-0000-4000-8000-000000000021','${task5GitHubIntegrationID}','github','github_installation_reference','ref:github/installation/e2e-424242',1,'{"installation_id":"424242"}'::jsonb),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','pid_76000021-0000-4000-8000-000000000021','${task5OktaIntegrationID}','okta','okta_refresh_reference','ref:okta/refresh/e2e-tenant',1,'{"tenant":"e2e.okta.com"}'::jsonb);
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

function startTask4Worker(workerBinary, environment) {
  const worker = startChild(workerBinary, [], { env: environment });
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
      assert.equal(target.searchParams.get("public_token"), "public-token-test-local");
      assert.equal(target.searchParams.get("organization_id"), "organization-test-local");
      const callback = new URL(target.searchParams.get("login_redirect_url"));
      assert.equal(callback.origin, publicOrigin);
      assert.equal(callback.pathname, "/auth/callback");
      assert.equal(target.searchParams.get("signup_redirect_url"), callback.toString());
      assert.ok((callback.searchParams.get("state") ?? "").length >= 32);
      callback.searchParams.set("token", "local-oauth-token");
      response.writeHead(302, { location: callback.toString() });
      response.end();
      return;
    }
    if (request.method === "POST" && target.pathname === "/v1/b2b/oauth/authenticate") {
      assert.equal(request.headers.authorization, `Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`);
      assert.deepEqual(JSON.parse(await readBody(request)), { oauth_token: "local-oauth-token", session_duration_minutes: 60 });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ status_code: 200, request_id: "request-id-test-oauth", member_id: "member-test-local", organization_id: "organization-test-local", session_jwt: "header.payload.signature" }));
      return;
    }
    if (request.method === "POST" && target.pathname === "/v1/b2b/sessions/authenticate") {
      assert.equal(request.headers.authorization, `Basic ${Buffer.from("project-test-local:secret-test-local").toString("base64")}`);
      assert.deepEqual(JSON.parse(await readBody(request)), { session_jwt: "header.payload.signature" });
      const now = new Date();
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ status_code: 200, request_id: "request-id-test-session", session_jwt: "header.payload.signature", member_session: { member_session_id: "member-session-test-local", member_id: "member-test-local", organization_id: "organization-test-local", started_at: now.toISOString(), last_accessed_at: now.toISOString(), expires_at: new Date(now.getTime() + 3_600_000).toISOString() } }));
      return;
    }
    response.writeHead(404);
    response.end();
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
    const connectorAuthorizationRequest = request.method === "POST" && target.pathname === `/api/v1/integrations/${terminalRevocationIntegrationID}/authorize` && String(request.headers.cookie ?? "").includes("__Host-zasp_session=");
    if (tokenCreate) tokenMutationKeys.create.push(String(request.headers["idempotency-key"] ?? ""));
    if (tokenRotate) tokenMutationKeys.rotate.push(String(request.headers["idempotency-key"] ?? ""));
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
    const upstreamHeaders = {
      ...request.headers,
      host: request.headers.host,
      "x-forwarded-for": "127.0.0.1",
      "x-forwarded-host": request.headers.host,
      "x-forwarded-port": String(port),
      "x-forwarded-proto": "https",
    };
    delete upstreamHeaders["x-zasp-e2e-tab"];
    const upstream = http.request({ hostname: "127.0.0.1", port: upstreamPort, method: request.method, path: request.url, headers: upstreamHeaders }, (upstreamResponse) => {
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

async function browserAriaControlDisabled(cdp, label) {
  const evaluated = await cdp.send("Runtime.evaluate", { expression: `(() => { const element = document.querySelector(${JSON.stringify(`[aria-label="${label}"]`)}); return element instanceof HTMLButtonElement ? element.disabled : null; })()`, returnByValue: true });
  return evaluated.result?.value;
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
  throw new Error(`browser action target unavailable: ${expression}`);
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
  const [status] = await once(child, "exit");
  clearTimeout(deadline);
  const result = { status, stdout, stderr };
  if (status !== 0 && options.reject !== false) throw new Error(`${path.basename(executable)} failed (${status}): ${stderr || stdout}`);
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

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { installBoundedSignalCleanup } from "./bounded-signal-cleanup.mjs";

const FIXED_NODE_VERSION = "v22.23.1";
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const platform = path.join(root, "services", "platform");
const postgresBin = "/opt/homebrew/bin";
const chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

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
let observedSessionCookie = false;
const lostPolicyResponseKeys = [];
const workflowPageRequests = { policies: [], integrations: [] };
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
let proxyFailure;
const cleanupController = installBoundedSignalCleanup(cleanupOwnedResources);

try {
  const ports = await Promise.all(Array.from({ length: 7 }, reservePort));
  const [postgresPort, identityPort, apiPort, healthPort, webPort, proxyPort, chromePort] = ports;
  const dsn = `postgres://zasp_e2e@127.0.0.1:${postgresPort}/postgres?sslmode=disable`;
  postgres = await startPostgres(postgresPort);
  console.log("combined E2E: disposable PostgreSQL ready");

  const migrate = path.join(temporaryRoot, "agentsec-migrate");
  const apiBinary = path.join(temporaryRoot, "agentsec-api");
  await command("go", ["build", "-o", migrate, "./agentsec-migrate"], { cwd: platform });
  await command("go", ["build", "-o", apiBinary, "./agentsec-api"], { cwd: platform });
  await command(migrate, ["up"], { env: { ...process.env, ZASP_POSTGRES_DSN: dsn, ZASP_MIGRATION_TIMEOUT: "20s" } });
  await seedPostgres(dsn);
  console.log("combined E2E: migrations and durable seed ready");

  const publicOrigin = `https://127.0.0.1:${proxyPort}`;
  identity = await startIdentityServer(identityPort, publicOrigin);
  const apiEnvironment = {
    ...process.env,
    ZASP_ENVIRONMENT: "test",
    ZASP_DEPLOYMENT_MODE: "saas",
    ZASP_ORGANIZATION_ID: "",
    ZASP_PRODUCT_LISTEN_ADDRESS: `127.0.0.1:${apiPort}`,
    ZASP_INTERNAL_LISTEN_ADDRESS: `127.0.0.1:${healthPort}`,
    ZASP_PUBLIC_ORIGIN: publicOrigin,
    ZASP_COOKIE_SECURE: "true",
    ZASP_PROVIDER_TIMEOUT: "5s",
    ZASP_SHUTDOWN_TIMEOUT: "5s",
    ZASP_READINESS_INTERVAL: "100ms",
    ZASP_READINESS_MAX_INTERVAL: "1s",
    ZASP_POSTGRES_DSN: dsn,
    ZASP_STYTCH_BASE_URL: `http://127.0.0.1:${identityPort}`,
    ZASP_STYTCH_AUTHORIZE_URL: `http://127.0.0.1:${identityPort}/v1/b2b/public/oauth/google/start`,
    ZASP_STYTCH_PROJECT_ID: "project-test-local",
    ZASP_STYTCH_SECRET: "secret-test-local",
    ZASP_STYTCH_PUBLIC_TOKEN: "public-token-test-local",
    ZASP_STYTCH_ORGANIZATION_ID: "organization-test-local",
    ZASP_WORKFLOW_SIGNING_KEY: "0123456789abcdef0123456789abcdef",
    ZASP_TOKEN_REVEAL_KEY: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
  };
  api = startChild(apiBinary, [], { env: apiEnvironment });
	try {
		await waitForHTTP(`http://127.0.0.1:${healthPort}/readyz`, 200);
	} catch (error) {
		throw new Error(`${error instanceof Error ? error.message : "API readiness failed"}: ${api.output()}`);
	}
  console.log("combined E2E: Go product and internal listeners ready");

  await command("npm", ["run", "build"], { cwd: root, timeout: 120_000 });
  web = startChild(path.join(root, "node_modules", ".bin", "vinext"), ["start", "--port", String(webPort), "--hostname", "127.0.0.1"], { cwd: root });
  await waitForHTTP(`http://127.0.0.1:${webPort}/sign-in`, 200);
  console.log("combined E2E: built web server ready");

  const key = path.join(temporaryRoot, "tls.key");
  const certificate = path.join(temporaryRoot, "tls.crt");
  await command("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", certificate]);
  proxy = await startProxy(proxyPort, apiPort, webPort, key, certificate, dsn);
  await waitForHTTP(`${publicOrigin}/sign-in`, 200, true);

  const patHeaders = { authorization: "Bearer production-e2e-product-token-with-at-least-32-bytes", "content-type": "application/json", "idempotency-key": "production-e2e-pat-0001" };
  const patBody = JSON.stringify({ id: "policy-pat-e2e", name: "PAT E2E boundary", scope: "environment", trigger: "tool", conditions: [{ field: "action", operator: "equals", value: "read" }], action: "monitor", rollout: "draft", failure_mode: "open" });
  const patCreated = await requestHTTPSJSON(`${publicOrigin}/api/v1/policies`, { method: "POST", headers: patHeaders }, patBody);
  const patReplayed = await requestHTTPSJSON(`${publicOrigin}/api/v1/policies`, { method: "POST", headers: patHeaders }, patBody);
  assert.equal(patCreated.status, 201);
  assert.equal(patReplayed.status, 201);
  assert.equal(patCreated.headers["x-mutation-receipt-id"], undefined);
  assert.equal(patReplayed.headers["x-mutation-receipt-id"], undefined);
  assert.deepEqual(patReplayed.body, patCreated.body);
  const patCounts = await command(path.join(postgresBin, "psql"), [dsn, "-At", "-c", `SELECT
    (SELECT count(*) FROM zasp_workflow_idempotency WHERE operation='createPolicy' AND idempotency_key='production-e2e-pat-0001'),
    (SELECT count(*) FROM zasp_workflow_audit WHERE operation='createPolicy' AND resource_id='policy-pat-e2e'),
    (SELECT count(*) FROM zasp_workflow_receipts WHERE operation='createPolicy' AND idempotency_key='production-e2e-pat-0001');`]);
  assert.equal(patCounts.stdout.trim(), "1|1|0", "PAT create/replay inserted a browser mutation receipt");
  console.log("combined E2E: PAT success, replay, and zero browser receipts proven");

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

  const sharedSessionCookie = await getBrowserSessionCookie(browser.cdp, publicOrigin);
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

  await navigateBrowser(browser.cdp, `${publicOrigin}/connectors`);
  await waitForBrowserText(browser.cdp, /Durable local connector configuration/);
  await waitForBrowserText(browser.cdp, /Paged integration 1001/);
  assert.equal(await browserCountAriaPrefix(browser.cdp, "Open "), 1001, "integration UI did not traverse exactly 1001 stable IDs");
  assert.equal(workflowPageRequests.integrations.length, 11, "integration UI pagination requested an extra or missing page");
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
  await clickBrowserText(browser.cdp, "Close");

  await navigateBrowser(browser.cdp, `${publicOrigin}/protect/security-agents`);
  await waitForBrowserText(browser.cdp, /Durable, scoped response definitions/);
  await clickBrowserText(browser.cdp, "Create Security Agent");
  await clickBrowserText(browser.cdp, "Save Security Agent definition");
  await waitForBrowserText(browser.cdp, /Bounded response definition/);
  assert.equal(await browserHasInteractiveText(browser.cdp, /^(?:Run Security Agent|Simulate Security Agent|Approve|Start bounded run|Runs|Approvals)$/i), false);

  await navigateBrowser(browser.cdp, `${publicOrigin}/integrations/sensors`);
  const sensorHidden = await waitForBrowserText(browser.cdp, /Security overview/);
  assert.doesNotMatch(sensorHidden, /Enroll sensor|Sensors/);
  await navigateBrowser(browser.cdp, `${publicOrigin}/protect/approvals`);
  const approvalsHidden = await waitForBrowserText(browser.cdp, /Security overview/);
  assert.doesNotMatch(approvalsHidden, /Approve|Pending approvals/);
  console.log("combined E2E: full-document receipt recovery, local integration, Security Agent definition, and hidden unsafe controls proven");

  await navigateBrowser(browser.cdp, `${publicOrigin}/administration/identity-access`);
  const identityAccess = await waitForBrowserText(browser.cdp, /member-target-local/);
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
  assert.equal(proxyFailure, undefined, `proxy fixture failed: ${proxyFailure}`);

  console.log("production combined E2E passed: callback/cookie/bootstrap, pagination, administration, PAT/receipt recovery, keyboard focus, durable restart/reload, tenant denial");
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

async function seedPostgres(dsn) {
  const sql = `
INSERT INTO zasp_authorized_scopes (principal_id, organization_id, workspace_id, environment_id, label, permissions, is_default) VALUES
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','Production','["view","manage_workflows"]'::jsonb,true),
('pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','Staging','["view","manage_workflows"]'::jsonb,false),
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
(digest('production-e2e-product-token-with-at-least-32-bytes', 'sha256'),'pid_10000004-0000-4000-8000-000000000004','pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','["view","manage_workflows"]'::jsonb,transaction_timestamp() + interval '1 hour');
INSERT INTO zasp_core_payloads (organization_id, workspace_id, environment_id, operation, payload) VALUES
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','session_bootstrap:pid_10000004-0000-4000-8000-000000000004','{"principal":{"id":"pid_10000004-0000-4000-8000-000000000004","organization_id":"pid_10000001-0000-4000-8000-000000000001","organization_reference":"organization-local","member_reference":"member-local","role":"security_admin","active":true},"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000002-0000-4000-8000-000000000002","environment_id":"pid_10000003-0000-4000-8000-000000000003","permissions":["view"],"capabilities":["inventory.read","scope.switch"],"csrf_token":"cccccccccccccccccccccccccccccccc","correlation_id":"pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}'::jsonb),
('pid_10000001-0000-4000-8000-000000000001','pid_10000022-0000-4000-8000-000000000022','pid_10000023-0000-4000-8000-000000000023','session_bootstrap:pid_10000004-0000-4000-8000-000000000004','{"principal":{"id":"pid_10000004-0000-4000-8000-000000000004","organization_id":"pid_10000001-0000-4000-8000-000000000001","organization_reference":"organization-local","member_reference":"member-local","role":"security_admin","active":true},"organization_id":"pid_10000001-0000-4000-8000-000000000001","workspace_id":"pid_10000022-0000-4000-8000-000000000022","environment_id":"pid_10000023-0000-4000-8000-000000000023","permissions":["view"],"capabilities":["inventory.read","scope.switch"],"csrf_token":"dddddddddddddddddddddddddddddddd","correlation_id":"pid_eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}'::jsonb),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','home','{"agent_count":1,"high_risk_paths":0,"verified_changes":0,"blocked_changes":0,"pending_approvals":0,"oldest_approval_age_seconds":0,"needs_human_runs":0,"failed_runs":0,"inconclusive_runs":0,"recent_contained":0,"recent_remediated":0,"healthy":true,"attention_required":false}'::jsonb),
('pid_10000001-0000-4000-8000-000000000001','pid_10000002-0000-4000-8000-000000000002','pid_10000003-0000-4000-8000-000000000003','agents','{"items":[{"id":"pid_20000001-0000-4000-8000-000000000001","name":"Support agent","kind":"agent","owner":"security","team":"platform","tags":["production"],"evidence_id":"pid_20000006-0000-4000-8000-000000000006","first_seen":"2026-08-18T09:00:00Z","last_seen":"2026-08-18T10:00:00Z"}]}'::jsonb),
('pid_90000001-0000-4000-8000-000000000001','pid_90000002-0000-4000-8000-000000000002','pid_90000003-0000-4000-8000-000000000003','agent:pid_90000001-0000-4000-8000-000000000001','{"id":"pid_90000001-0000-4000-8000-000000000001","name":"Foreign tenant agent","kind":"agent","owner":"foreign","team":"foreign","tags":[],"evidence_id":"pid_90000006-0000-4000-8000-000000000006","first_seen":"2026-08-18T09:00:00Z","last_seen":"2026-08-18T10:00:00Z"}'::jsonb);
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
`;
  await command(path.join(postgresBin, "psql"), [dsn, "-v", "ON_ERROR_STOP=1"], { input: sql });
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
    const target = new URL(request.url ?? "/", "https://combined.invalid");
    const browserTab = String(request.headers["x-zasp-e2e-tab"] ?? "");
    const receiptAcknowledgement = request.method === "POST" && /^\/api\/v1\/workflow-mutation-receipts\/pid_[0-9a-f-]+\/acknowledge$/.test(target.pathname);
    const tokenCreate = request.method === "POST" && target.pathname === "/api/v1/admin/api-tokens";
    const tokenRotate = request.method === "POST" && /^\/api\/v1\/admin\/api-tokens\/pid_[0-9a-f-]+\/rotate$/.test(target.pathname);
    const tokenReveal = request.method === "POST" && /^\/api\/v1\/admin\/api-token-reveal-grants\/pid_[0-9a-f-]+\/reveal$/.test(target.pathname);
    const tokenAcknowledge = request.method === "DELETE" && /^\/api\/v1\/admin\/api-token-reveal-grants\/pid_[0-9a-f-]+$/.test(target.pathname);
    if (tokenCreate) tokenMutationKeys.create.push(String(request.headers["idempotency-key"] ?? ""));
    if (tokenRotate) tokenMutationKeys.rotate.push(String(request.headers["idempotency-key"] ?? ""));
    if (request.method === "GET" && target.pathname === "/api/v1/policies") workflowPageRequests.policies.push(target.search);
    if (request.method === "GET" && target.pathname === "/api/v1/integrations") workflowPageRequests.integrations.push(target.search);
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
    const upstreamHeaders = { ...request.headers, host: `127.0.0.1:${port}` };
    delete upstreamHeaders["x-zasp-e2e-tab"];
    const upstream = http.request({ hostname: "127.0.0.1", port: upstreamPort, method: request.method, path: request.url, headers: upstreamHeaders }, (upstreamResponse) => {
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

async function startBrowser(profile, port, target) {
  const child = startChild(chrome, ["--headless=new", "--no-first-run", "--disable-background-networking", "--disable-component-update", "--ignore-certificate-errors", `--user-data-dir=${profile}`, `--remote-debugging-port=${port}`, target]);
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

async function navigateBrowser(cdp, url) {
  browserStage = `navigate:${url}`;
  await cdp.replaceTarget(url);
  console.log(`combined E2E: browser document transition ${new URL(url).pathname}`);
}

async function reloadBrowser(cdp) {
  browserStage = "reload";
  await cdp.replaceTarget(await browserCurrentURL(cdp));
}

async function browserStorageAndHistoryText(cdp) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `JSON.stringify({ local: Object.fromEntries(Object.entries(localStorage)), session: Object.fromEntries(Object.entries(sessionStorage)), href: location.href, resources: performance.getEntriesByType('resource').map((entry) => entry.name) })`,
    returnByValue: true,
  });
  return String(evaluated.result?.value ?? "");
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
    const request = https.request(target, { ...options, rejectUnauthorized: false }, (response) => {
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

async function browserFetchJSON(cdp, target, headers) {
  const evaluated = await cdp.send("Runtime.evaluate", {
    expression: `(async () => { const response = await fetch(${JSON.stringify(target)}, { headers: ${JSON.stringify(headers)} }); return { status: response.status, body: await response.json() }; })()`,
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
    async replaceTarget(url) {
      const previousTargetId = targetId;
      const created = await browserCDP.send("Target.createTarget", { url, ...(browserContextId ? { browserContextId } : {}) });
      assert.ok(created.targetId, "Chrome replacement target was not created");
      const replacement = await browserCDP.send("Target.attachToTarget", { targetId: created.targetId, flatten: true });
      assert.ok(replacement.sessionId, "Chrome replacement target session was not created");
      targetId = created.targetId;
      attached = replacement;
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
    if (!message.id || !pending.has(message.id)) return;
    const { resolve, reject, timeout } = pending.get(message.id);
    pending.delete(message.id);
    clearTimeout(timeout);
    if (message.error) reject(new Error(message.error.message)); else resolve(message.result);
  });
  socket.addEventListener("close", () => { if (!closed) rejectPending("CDP connection closed"); });
  return {
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
  for (let attempt = 0; attempt < 200; attempt += 1) {
    const status = await new Promise((resolve) => {
      const transport = target.startsWith("https:") ? https : http;
      const request = transport.get(target, { rejectUnauthorized: !insecure }, (response) => { response.resume(); resolve(response.statusCode); });
      request.on("error", () => resolve(0));
    });
    if (status === expected) return;
    await delay(50);
  }
  throw new Error(`endpoint did not become ready: ${target}`);
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

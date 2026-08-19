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
  ]) assert.match(source, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.doesNotMatch(source, /Shown only once/);
  assert.doesNotMatch(source, /"Page\.(?:navigate|reload)"/);
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

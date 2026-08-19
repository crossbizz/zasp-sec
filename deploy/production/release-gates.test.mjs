import assert from "node:assert/strict";
import { createServer } from "node:http";
import { once } from "node:events";
import test from "node:test";

import { loadReleasePolicy, runReadOnlySynthetic, verifyReleaseSources } from "./release-gates.mjs";

test("release policy binds performance, resilience, supply-chain, and owned proof gates", async () => {
  const policy = await loadReleasePolicy();
  assert.deepEqual(policy.performance, { webP95Milliseconds: 2000, apiReadP95Milliseconds: 500, apiMutationP95Milliseconds: 1000, errorRatePercent: 1 });
  assert.deepEqual(policy.resilience, ["replica_restart", "provider_timeout", "queue_redrive", "stale_read_revalidation"]);
  assert.deepEqual(policy.supplyChain, ["npm_spdx_sbom", "go_spdx_sbom", "license_allowlist", "offline_dependency_audit", "digest_pinned_container_definition", "full_tracked_gitleaks", "required_ci_gate"]);
  assert.equal(policy.proof.ownedPrefix, "zasp-production-e2e-");
  assert.equal(policy.proof.ambientMutation, false);
});

test("read-only synthetic proves web and authenticated API correlation without leaking token", async () => {
  let observedToken = "";
  const server = createServer((request, response) => {
    if (request.url === "/sign-in") {
      response.writeHead(200, securityHeaders({ "content-type": "text/html" }));
      response.end("Zasp sign in");
      return;
    }
    if (request.url === "/api/v1/home/summary") {
      observedToken = String(request.headers.authorization ?? "");
      response.writeHead(200, securityHeaders({ "content-type": "application/json", "x-correlation-id": "pid_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", traceparent: "00-11111111111111111111111111111111-2222222222222222-01" }));
      response.end("{}");
      return;
    }
    response.writeHead(404); response.end();
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  try {
    const origin = `http://${server.address().address}:${server.address().port}`;
    const evidence = await runReadOnlySynthetic({ origin, token: "synthetic-secret-token-with-32-bytes", allowHTTPLoopback: true });
    assert.deepEqual(Object.keys(evidence), ["apiMilliseconds", "correlationID", "traceID", "webMilliseconds"]);
    assert.equal(observedToken, "Bearer synthetic-secret-token-with-32-bytes");
    assert.doesNotMatch(JSON.stringify(evidence), /synthetic-secret/);
  } finally {
    server.close(); await once(server, "close");
  }
});

test("release sources contain truthful runbooks, canary, SBOM/license/image/secret gates", async () => {
  const result = await verifyReleaseSources();
  assert.equal(result.canary, true);
  assert.equal(result.documentation, true);
  assert.equal(result.imageDefinitions, 3);
  assert.equal(result.licensePolicy, true);
  assert.equal(result.trackedSecretScan, true);
  assert.ok(result.npmSpdxPackages > 20);
  assert.ok(result.goSpdxPackages > 20);
  assert.equal(result.requiredCI, true);
});

function securityHeaders(extra) {
  return {
    ...extra,
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
  };
}
